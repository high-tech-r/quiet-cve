#!/usr/bin/env python3
"""OSV.dev に依存関係を問い合わせ、トリアージ用の JSON を返す。

標準ライブラリのみで動作する（PyYAML があれば使うが、無くても動く）。

使い方:
    # 親プロジェクトを自動検出してスキャン
    python3 scripts/osv_query.py --out scan.json

    # 依存ファイルの検出結果だけ見る
    python3 scripts/osv_query.py --detect-only

    # 依存リストを明示的に渡す
    python3 scripts/osv_query.py --packages npm:lodash@4.17.20 PyPI:requests@2.19.1

出力される JSON の構造は README.md の「osv_query.py の出力」を参照。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

USER_AGENT = "quiet-cve/0.1 (+https://github.com/; OSV client)"
HTTP_TIMEOUT = 30
KEV_CACHE_TTL = 24 * 60 * 60  # 24h

ECO_NPM = "npm"
ECO_PYPI = "PyPI"
ECO_COMPOSER = "Packagist"


# ===========================================================================
# 設定読み込み
# ===========================================================================

DEFAULT_EXCLUDES = [
    "node_modules", "vendor", ".venv", "venv", ".git", "dist", "build",
    "target", "__pycache__", ".tox", ".next", "coverage", "quiet-cve",
]


def load_config(path: Path) -> dict:
    """config.yml を読む。PyYAML があれば使い、無ければ最小パーサにフォールバック。"""
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        return _mini_yaml(text)


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _split_flow(s: str) -> list[str]:
    parts, buf, depth, quote = [], [], 0, None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _parse_scalar(s: str):
    s = s.strip()
    if not s:
        return None
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        return [_parse_scalar(x) for x in _split_flow(s[1:-1])]
    if s.startswith("{") and s.endswith("}"):
        d = {}
        for part in _split_flow(s[1:-1]):
            if ":" in part:
                k, v = part.split(":", 1)
                d[k.strip().strip("\"'")] = _parse_scalar(v)
        return d
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


# キーと値の区切りはコロン + 空白（または行末）。
# こうしないと `- http://example.com` がマップとして誤解釈される。
_KEY_RE = re.compile(r"^([A-Za-z0-9_.\-]+|\"[^\"]+\"|'[^']+')\s*:(?:\s+(.*))?$")


def _mini_yaml(text: str) -> dict:
    """config.yml で使っている範囲の YAML だけを読む簡易パーサ。

    対応: ネストしたマップ、ブロックリスト、`- key: value` 形式、フロー([a, b])、
          コメント、真偽値/数値/null。アンカーや複数行文字列は非対応。
    """
    toks: list[tuple[int, str, str]] = []  # (indent, kind, text)
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if body == "-" or body.startswith("- "):
            toks.append((indent, "item", ""))
            rest = body[1:].lstrip()
            if rest:
                # "- " の後ろの実際の桁位置を求める（`-   key: v` にも耐える）
                dash = line.index("-", indent)
                content_indent = dash + 1 + (len(body[1:]) - len(rest))
                toks.append((content_indent, "line", rest))
        else:
            toks.append((indent, "line", body))
    if not toks:
        return {}
    value, _ = _parse_node(toks, 0, toks[0][0])
    return value if isinstance(value, dict) else {}


def _parse_node(toks, i, indent):
    if i >= len(toks):
        return None, i
    if toks[i][1] == "item":
        items = []
        while i < len(toks) and toks[i][0] == indent and toks[i][1] == "item":
            i += 1
            if i < len(toks) and toks[i][0] > indent:
                v, i = _parse_node(toks, i, toks[i][0])
            else:
                v = None
            items.append(v)
        return items, i
    # `- node_modules` のような、キーを持たない素のスカラー
    if not _KEY_RE.match(toks[i][2]):
        return _parse_scalar(toks[i][2]), i + 1

    mapping = {}
    while i < len(toks) and toks[i][0] == indent and toks[i][1] == "line":
        m = _KEY_RE.match(toks[i][2])
        if not m:
            i += 1
            continue
        key = m.group(1).strip("\"'")
        rest = (m.group(2) or "").strip()
        i += 1
        if rest:
            mapping[key] = _parse_scalar(rest)
        elif i < len(toks) and toks[i][0] > indent:
            mapping[key], i = _parse_node(toks, i, toks[i][0])
        elif i < len(toks) and toks[i][0] == indent and toks[i][1] == "item":
            mapping[key], i = _parse_node(toks, i, indent)
        else:
            mapping[key] = None
    return mapping, i


def cfg_get(config: dict, path: str, default=None):
    cur = config
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur or cur[part] is None:
            return default
        cur = cur[part]
    return cur


# ===========================================================================
# CVSS
# ===========================================================================

_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _roundup(x: float) -> float:
    """CVSS 3.1 仕様の Roundup。"""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str):
    """CVSS v3.x ベクタからベーススコアを計算する。解析できなければ None。"""
    try:
        parts = dict(
            p.split(":", 1) for p in vector.strip().split("/") if ":" in p
        )
        scope = parts["S"]
        pr_table = _CVSS3_W["PR_C"] if scope == "C" else _CVSS3_W["PR_U"]
        c = _CVSS3_W["CIA"][parts["C"]]
        i_ = _CVSS3_W["CIA"][parts["I"]]
        a = _CVSS3_W["CIA"][parts["A"]]
        iss = 1 - ((1 - c) * (1 - i_) * (1 - a))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        expl = (
            8.22
            * _CVSS3_W["AV"][parts["AV"]]
            * _CVSS3_W["AC"][parts["AC"]]
            * pr_table[parts["PR"]]
            * _CVSS3_W["UI"][parts["UI"]]
        )
        if impact <= 0:
            return 0.0
        raw = impact + expl if scope == "U" else 1.08 * (impact + expl)
        return _roundup(min(raw, 10.0))
    except (KeyError, ValueError, IndexError):
        return None


def severity_label(score) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def extract_severity(vuln: dict) -> dict:
    """OSV の vuln から CVSS 情報を取り出す。

    v3 ベクタがあれば正確に計算する。v4 のみの場合はスコアを計算せず
    (仕様上ルックアップテーブルが必要なため)、ベクタと DB 側のラベルを返す。
    """
    vectors = []
    for entry in vuln.get("severity") or []:
        vectors.append((entry.get("type", ""), entry.get("score", "")))
    for aff in vuln.get("affected") or []:
        for entry in aff.get("severity") or []:
            vectors.append((entry.get("type", ""), entry.get("score", "")))

    v3 = next((v for t, v in vectors if t.startswith("CVSS_V3")), None)
    v4 = next((v for t, v in vectors if t.startswith("CVSS_V4")), None)

    if v3:
        score = cvss3_base_score(v3)
        if score is not None:
            return {
                "score": score,
                "label": severity_label(score),
                "vector": v3,
                "version": "3.x",
                "source": "computed_from_vector",
            }

    # v3 が無い/壊れている場合はアドバイザリ DB のラベルを使う（GHSA 等は持っている）
    db_label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_label, str) and db_label.upper() in (
        "CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW",
    ):
        label = db_label.upper()
        label = "MEDIUM" if label == "MODERATE" else label
        return {
            "score": None,
            "label": label,
            "vector": v4 or v3,
            "version": "4.0" if v4 else None,
            "source": "advisory_label",
        }

    return {
        "score": None,
        "label": "UNKNOWN",
        "vector": v4 or v3,
        "version": "4.0" if v4 else None,
        "source": "unavailable",
    }


# ===========================================================================
# 依存ファイルの検出とパース
# ===========================================================================

MANIFEST_NAMES = {
    # ロックファイルを優先する（正確なバージョンが取れるため）
    "package-lock.json": (ECO_NPM, 10),
    "yarn.lock": (ECO_NPM, 9),
    "package.json": (ECO_NPM, 1),
    "poetry.lock": (ECO_PYPI, 10),
    "Pipfile.lock": (ECO_PYPI, 10),
    "uv.lock": (ECO_PYPI, 10),
    "requirements.txt": (ECO_PYPI, 5),
    "requirements-dev.txt": (ECO_PYPI, 4),
    "composer.lock": (ECO_COMPOSER, 10),
    "composer.json": (ECO_COMPOSER, 1),
}

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?")


def discover_manifests(root: Path, excludes: list[str], max_depth: int,
                       self_dir: Path | None = None) -> list[dict]:
    """依存ファイルを探す。同一ディレクトリ・同一エコシステムではロックファイルを優先。

    self_dir には本ツール自身のディレクトリを渡す。名前ではなくパスで除外するため、
    ディレクトリをリネームしても自分自身を走査してしまうことがない。
    """
    found: list[dict] = []
    excl = set(excludes)
    root = root.resolve()
    self_resolved = self_dir.resolve() if self_dir else None
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).resolve().relative_to(root)
        depth = len(rel_dir.parts)
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [
            d for d in dirnames
            if d not in excl and not d.startswith(".")
            and (Path(dirpath) / d).resolve() != self_resolved
        ]
        for name in filenames:
            if name in MANIFEST_NAMES:
                eco, prio = MANIFEST_NAMES[name]
                found.append({
                    "path": str((Path(dirpath) / name).resolve()),
                    "rel_path": str(rel_dir / name) if str(rel_dir) != "." else name,
                    "file": name,
                    "ecosystem": eco,
                    "priority": prio,
                    "dir": str(Path(dirpath).resolve()),
                })

    # ディレクトリ×エコシステムごとに最優先のものだけ残す
    best: dict[tuple, dict] = {}
    for m in found:
        key = (m["dir"], m["ecosystem"])
        # requirements*.txt は複数併存しうるのでファイル名込みで残す
        if m["file"].startswith("requirements"):
            key = (m["dir"], m["ecosystem"], m["file"])
        if key not in best or m["priority"] > best[key]["priority"]:
            best[key] = m
    result = sorted(best.values(), key=lambda m: m["rel_path"])

    # 同ディレクトリにロックファイルがあるなら requirements.txt は補助扱い（重複除去）
    lock_dirs = {m["dir"] for m in result if m["priority"] >= 10 and m["ecosystem"] == ECO_PYPI}
    result = [
        m for m in result
        if not (m["ecosystem"] == ECO_PYPI and m["priority"] < 10 and m["dir"] in lock_dirs)
    ]
    return result


def _clean_version(v: str) -> str | None:
    if not v:
        return None
    v = v.strip().lstrip("=v ").strip()
    m = _VERSION_RE.search(v)
    return m.group(0) if m else None


def _add(pkgs: dict, eco: str, name: str, version, manifest: str, dev: bool,
         direct: bool, exact: bool):
    if not name or not version:
        return
    key = (eco, name, version)
    if key in pkgs:
        entry = pkgs[key]
        # 複数のマニフェストに現れた場合は安全側に倒す。
        # dev 扱いは全員が dev のときだけ、直接依存はどれか 1 つでも直接なら直接。
        entry["manifests"] = sorted(set(entry["manifests"] + [manifest]))
        entry["dev"] = entry["dev"] and dev
        entry["direct"] = entry["direct"] or direct
        # ロックファイルが正確に固定していれば、レンジ推定より優先する
        entry["version_exact"] = entry["version_exact"] or exact
        return
    pkgs[key] = {
        "ecosystem": eco, "name": name, "version": version,
        "manifests": [manifest], "dev": dev, "direct": direct,
        "version_exact": exact,
    }


def parse_manifest(manifest: dict, pkgs: dict, errors: list, include_dev: bool):
    path = Path(manifest["path"])
    rel = manifest["rel_path"]
    name = manifest["file"]
    try:
        if name == "package-lock.json":
            _parse_package_lock(path, rel, pkgs, include_dev)
        elif name == "package.json":
            _parse_package_json(path, rel, pkgs, include_dev)
        elif name == "yarn.lock":
            _parse_yarn_lock(path, rel, pkgs)
        elif name in ("poetry.lock", "uv.lock"):
            _parse_toml_lock(path, rel, pkgs)
        elif name == "Pipfile.lock":
            _parse_pipfile_lock(path, rel, pkgs, include_dev)
        elif name.startswith("requirements"):
            _parse_requirements(path, rel, pkgs)
        elif name == "composer.lock":
            _parse_composer_lock(path, rel, pkgs, include_dev)
        elif name == "composer.json":
            _parse_composer_json(path, rel, pkgs, include_dev)
    except Exception as exc:  # 1 ファイルの失敗で全体を止めない
        errors.append({"manifest": rel, "error": f"{type(exc).__name__}: {exc}"})


def _direct_names_from_root(root_entry: dict) -> set:
    names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies",
                  "peerDependencies"):
        names |= set((root_entry.get(field) or {}).keys())
    return names


def _parse_package_lock(path, rel, pkgs, include_dev):
    data = json.loads(path.read_text(encoding="utf-8"))
    if "packages" in data:  # lockfileVersion 2/3
        # "" エントリ（プロジェクト自身）から直接依存の名前を取る。
        # node_modules はホイスティングされるため、階層の深さでは直接依存を判定できない。
        direct_names = _direct_names_from_root(data["packages"].get("", {}))
        if not direct_names:  # 稀に "" が無い/空。その場合は隣の package.json を見る
            sibling = path.parent / "package.json"
            if sibling.exists():
                try:
                    direct_names = _direct_names_from_root(
                        json.loads(sibling.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    pass
        for loc, info in data["packages"].items():
            if not loc or not isinstance(info, dict):
                continue  # "" はプロジェクト自身
            pkg_name = info.get("name") or loc.split("node_modules/")[-1]
            dev = bool(info.get("dev") or info.get("devOptional"))
            if dev and not include_dev:
                continue
            if direct_names:
                direct = pkg_name in direct_names
            else:  # 情報が無いときのみ階層の深さで代用する
                direct = loc.count("node_modules/") == 1
            _add(pkgs, ECO_NPM, pkg_name, _clean_version(info.get("version", "")),
                 rel, dev, direct, True)
    elif "dependencies" in data:  # lockfileVersion 1
        def walk(deps, direct):
            for pkg_name, info in (deps or {}).items():
                if not isinstance(info, dict):
                    continue
                dev = bool(info.get("dev"))
                if not (dev and not include_dev):
                    _add(pkgs, ECO_NPM, pkg_name, _clean_version(info.get("version", "")),
                         rel, dev, direct, True)
                walk(info.get("dependencies"), False)
        walk(data["dependencies"], True)


def _parse_package_json(path, rel, pkgs, include_dev):
    data = json.loads(path.read_text(encoding="utf-8"))
    fields = ["dependencies"] + (["devDependencies"] if include_dev else [])
    for field in fields:
        for pkg_name, spec in (data.get(field) or {}).items():
            if not isinstance(spec, str) or spec.startswith(("file:", "link:", "workspace:", "git", "http")):
                continue
            _add(pkgs, ECO_NPM, pkg_name, _clean_version(spec), rel,
                 field == "devDependencies", True, False)


def _parse_yarn_lock(path, rel, pkgs):
    text = path.read_text(encoding="utf-8")
    direct_names: set = set()
    sibling = path.parent / "package.json"
    if sibling.exists():
        try:
            direct_names = _direct_names_from_root(
                json.loads(sibling.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    current = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            head = line.strip().rstrip(":").split(",")[0].strip().strip("\"'")
            at = head.rfind("@")
            current = head[:at] if at > 0 else head
        elif current and line.strip().startswith("version"):
            ver = _clean_version(line.split(":", 1)[-1].split(None, 1)[-1].strip().strip("\"'"))
            _add(pkgs, ECO_NPM, current, ver, rel, False, current in direct_names, True)
            current = None


def _poetry_direct_names(path: Path) -> set:
    """隣の pyproject.toml から直接依存の名前を復元する。"""
    sibling = path.parent / "pyproject.toml"
    if not sibling.exists():
        return set()
    try:
        import tomllib
        data = tomllib.loads(sibling.read_text(encoding="utf-8"))
    except (ImportError, ValueError, OSError):
        return set()
    names = set(((data.get("project") or {}).get("dependencies") or []))
    names = {re.split(r"[<>=!\[; ]", n)[0].strip().lower() for n in names if isinstance(n, str)}
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for field in ("dependencies", "dev-dependencies"):
        names |= {k.lower() for k in (poetry.get(field) or {})}
    for grp in (poetry.get("group") or {}).values():
        names |= {k.lower() for k in ((grp or {}).get("dependencies") or {})}
    names.discard("python")
    return names


def _parse_toml_lock(path, rel, pkgs):
    direct_names = _poetry_direct_names(path)
    is_direct = lambda n: (n or "").lower() in direct_names if direct_names else False
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for entry in data.get("package", []):
            name = entry.get("name")
            _add(pkgs, ECO_PYPI, name, _clean_version(entry.get("version", "")),
                 rel, entry.get("category") == "dev", is_direct(name), True)
        return
    except ImportError:
        pass
    name = None  # tomllib が無い環境向けのフォールバック
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("name ="):
            name = s.split("=", 1)[1].strip().strip("\"'")
        elif s.startswith("version =") and name:
            ver = _clean_version(s.split("=", 1)[1].strip().strip("\"'"))
            _add(pkgs, ECO_PYPI, name, ver, rel, False, is_direct(name), True)
            name = None


def _parse_pipfile_lock(path, rel, pkgs, include_dev):
    data = json.loads(path.read_text(encoding="utf-8"))
    sections = ["default"] + (["develop"] if include_dev else [])
    for section in sections:
        for pkg_name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            _add(pkgs, ECO_PYPI, pkg_name, _clean_version(info.get("version", "")),
                 rel, section == "develop", True, True)


def _parse_requirements(path, rel, pkgs):
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith(("git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()  # environment marker
        m = re.match(r"^([A-Za-z0-9._\-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        pkg_name, spec = m.group(1), (m.group(3) or "").strip()
        exact = spec.startswith("==")
        _add(pkgs, ECO_PYPI, pkg_name, _clean_version(spec), rel, False, True, exact)


def _parse_composer_lock(path, rel, pkgs, include_dev):
    data = json.loads(path.read_text(encoding="utf-8"))
    # composer.lock は依存を平坦に並べるだけで直接/推移的の区別を持たない。
    # 隣の composer.json があればそこから直接依存を復元する。
    direct_names: set = set()
    sibling = path.parent / "composer.json"
    if sibling.exists():
        try:
            cj = json.loads(sibling.read_text(encoding="utf-8"))
            direct_names = set(cj.get("require") or {}) | set(cj.get("require-dev") or {})
        except (json.JSONDecodeError, OSError):
            pass
    sections = ["packages"] + (["packages-dev"] if include_dev else [])
    for section in sections:
        for entry in data.get(section) or []:
            name = entry.get("name")
            direct = (name in direct_names) if direct_names else True
            _add(pkgs, ECO_COMPOSER, name, _clean_version(entry.get("version", "")),
                 rel, section == "packages-dev", direct, True)


def _parse_composer_json(path, rel, pkgs, include_dev):
    data = json.loads(path.read_text(encoding="utf-8"))
    fields = ["require"] + (["require-dev"] if include_dev else [])
    for field in fields:
        for pkg_name, spec in (data.get(field) or {}).items():
            if "/" not in pkg_name or not isinstance(spec, str):
                continue  # php, ext-* などは対象外
            _add(pkgs, ECO_COMPOSER, pkg_name, _clean_version(spec), rel,
                 field == "require-dev", True, False)


# ===========================================================================
# コード使用状況調査のためのヒント生成
# ===========================================================================

# PyPI の配布名とインポート名が一致しない代表例。
# ここに無いものは機械的な推定になるため、SKILL.md 側で「推定である」と扱う。
PYPI_IMPORT_NAMES = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "protobuf": ["google.protobuf"],
    "attrs": ["attr", "attrs"],
    "msgpack-python": ["msgpack"],
    "python-jose": ["jose"],
    "python-magic": ["magic"],
    "python-multipart": ["multipart"],
    "pyjwt": ["jwt"],
    "mysqlclient": ["MySQLdb"],
    "psycopg2-binary": ["psycopg2"],
    "django-cors-headers": ["corsheaders"],
    "djangorestframework": ["rest_framework"],
    "google-cloud-storage": ["google.cloud.storage"],
    "typing-extensions": ["typing_extensions"],
    "setuptools": ["setuptools", "pkg_resources"],
}


def search_hints(eco: str, name: str) -> dict:
    """「このパッケージを実際に使っているか」を grep するための手がかり。

    module_candidates はあくまで推定。配布名とインポート名は一致しないことがある
    （PyYAML → yaml など）。ヒット 0 件でも「使っていない」と即断してはいけない。
    """
    modules, patterns = [], []
    if eco == ECO_NPM:
        modules = [name]
        esc = re.escape(name)
        patterns = [
            rf"require\(['\"]{esc}",
            rf"from ['\"]{esc}",
            rf"import ['\"]{esc}",
            rf"import\(['\"]{esc}",
        ]
    elif eco == ECO_PYPI:
        lower = name.lower()
        base = lower.replace("-", "_")
        cands = list(PYPI_IMPORT_NAMES.get(lower, []))
        cands.append(base)
        for prefix in ("python_", "py_"):
            if base.startswith(prefix):
                cands.append(base[len(prefix):])
        if base.endswith("_python"):
            cands.append(base[: -len("_python")])
        seen = set()
        modules = [m for m in cands if not (m in seen or seen.add(m))]
        for mod in modules:
            esc = re.escape(mod)
            patterns.append(rf"^\s*import\s+{esc}\b")
            patterns.append(rf"^\s*from\s+{esc}[\s.]")
    elif eco == ECO_COMPOSER:
        # composer 名から PSR-4 名前空間を推定する（GuzzleHttp のような内部大文字は復元できない）。
        # そのため grep は必ず大文字小文字を無視して当てること。
        vendor, _, pkg = name.partition("/")
        cap = lambda s: (s[:1].upper() + s[1:]) if s else s
        ns = "".join(cap(p) for p in re.split(r"[-_]", vendor))
        cls = "".join(cap(p) for p in re.split(r"[-_]", pkg))
        modules = [f"{ns}\\{cls}", ns, cls]
        patterns = [
            rf"use\s+{re.escape(ns)}\\",     # use Vendor\...
            rf"\\{re.escape(ns)}\\",         # \Vendor\... （完全修飾）
            re.escape(name),                  # composer 名そのもの
        ]
    return {
        "module_candidates": modules,
        "grep_patterns": patterns,
        "case_insensitive": eco == ECO_COMPOSER,
        "note": "推定値。ヒット 0 件は「未使用」の証拠として単独では不十分。",
    }


# ===========================================================================
# HTTP
# ===========================================================================

def _http_json(url: str, payload: dict | None = None, retries: int = 3):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": USER_AGENT}
    if data:
        headers["Content-Type"] = "application/json"
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            last = exc
            if exc.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
        time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{url}: {type(last).__name__}: {last}")


# ===========================================================================
# KEV カタログ
# ===========================================================================

def load_kev(cache_dir: Path, errors: list, offline: bool = False) -> dict:
    cache = cache_dir / "kev.json"
    if cache.exists() and (time.time() - cache.stat().st_mtime) < KEV_CACHE_TTL:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    if offline:
        errors.append({"stage": "kev", "error": "offline mode: KEV カタログ未取得"})
        return {}
    try:
        data = _http_json(KEV_URL)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data), encoding="utf-8")
        return data
    except RuntimeError as exc:
        errors.append({"stage": "kev", "error": str(exc)})
        if cache.exists():  # 期限切れでも無いよりマシ
            try:
                return json.loads(cache.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {}


def kev_index(kev: dict) -> dict:
    return {
        entry["cveID"]: entry
        for entry in (kev.get("vulnerabilities") or [])
        if entry.get("cveID")
    }


# ===========================================================================
# OSV 問い合わせ
# ===========================================================================

def osv_querybatch(packages: list[dict], errors: list) -> dict:
    """パッケージごとの脆弱性 ID 一覧を返す。key は (eco, name, version)。"""
    result: dict[tuple, list[str]] = {}
    CHUNK = 500
    for start in range(0, len(packages), CHUNK):
        chunk = packages[start:start + CHUNK]
        payload = {
            "queries": [
                {
                    "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                    "version": p["version"],
                }
                for p in chunk
            ]
        }
        try:
            resp = _http_json(OSV_BATCH_URL, payload)
        except RuntimeError as exc:
            errors.append({"stage": "querybatch", "error": str(exc),
                           "packages": len(chunk)})
            continue
        for pkg, res in zip(chunk, (resp or {}).get("results", [])):
            ids = [v["id"] for v in (res.get("vulns") or []) if v.get("id")]
            if ids:
                result[(pkg["ecosystem"], pkg["name"], pkg["version"])] = ids
    return result


def fetch_vulns(vuln_ids: list[str], cache_dir: Path, errors: list) -> dict:
    vulns: dict[str, dict] = {}
    vcache = cache_dir / "vulns"
    vcache.mkdir(parents=True, exist_ok=True)

    def fetch(vid: str):
        cached = vcache / f"{vid}.json"
        if cached.exists() and (time.time() - cached.stat().st_mtime) < KEV_CACHE_TTL:
            try:
                return vid, json.loads(cached.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        try:
            data = _http_json(OSV_VULN_URL + vid)
            if data:
                cached.write_text(json.dumps(data), encoding="utf-8")
            return vid, data
        except RuntimeError as exc:
            return vid, {"__error__": str(exc)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for vid, data in pool.map(fetch, vuln_ids):
            if not data:
                continue
            if "__error__" in data:
                errors.append({"stage": "vuln_detail", "id": vid, "error": data["__error__"]})
                continue
            vulns[vid] = data
    return vulns


def _norm_pkg(eco: str, name: str) -> str:
    """OSV レコード内のパッケージ名と手元の表記を突き合わせるための正規化。

    PyPI は PEP 503 で正規化される（requirements.txt の "PyYAML" は OSV 側では
    "pyyaml"）。ここを厳密一致で比較すると修正版バージョンを取りこぼす。
    """
    if not name:
        return ""
    if eco == ECO_PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == ECO_COMPOSER:
        return name.lower()
    return name  # npm はスコープ含めて大文字小文字を区別する


def _same_package(pkg: dict, eco: str, name: str) -> bool:
    return (pkg.get("ecosystem") == eco
            and _norm_pkg(eco, pkg.get("name", "")) == _norm_pkg(eco, name))


def fixed_versions_for(vuln: dict, eco: str, name: str) -> list[str]:
    fixed = []
    for aff in vuln.get("affected") or []:
        if not _same_package(aff.get("package") or {}, eco, name):
            continue
        for rng in aff.get("ranges") or []:
            # GIT レンジのイベントはコミット SHA。人間に提示する修正版としては使えない。
            if (rng.get("type") or "").upper() == "GIT":
                continue
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
                elif ev.get("last_affected"):
                    fixed.append(f">{ev['last_affected']}")
    seen, out = set(), []
    for f in fixed:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def affected_symbols(vuln: dict, eco: str, name: str) -> list[str]:
    """OSV が「どの関数/シンボルが影響を受けるか」を持っていれば取り出す。"""
    syms = []
    for aff in vuln.get("affected") or []:
        if not _same_package(aff.get("package") or {}, eco, name):
            continue
        eco_spec = aff.get("ecosystem_specific") or {}
        for imp in eco_spec.get("imports") or []:
            path = imp.get("path", "")
            for sym in imp.get("symbols") or []:
                syms.append(f"{path}.{sym}" if path else sym)
            if path and not imp.get("symbols"):
                syms.append(path)
        for fn in eco_spec.get("affected_functions") or []:
            syms.append(fn)
    return sorted(set(syms))


# ===========================================================================
# 組み立て
# ===========================================================================

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def build_findings(packages, vuln_map, vulns, kevidx) -> list[dict]:
    findings = []
    by_key = {(p["ecosystem"], p["name"], p["version"]): p for p in packages}
    for key, ids in vuln_map.items():
        pkg = by_key[key]
        eco, name, version = key
        for vid in ids:
            vuln = vulns.get(vid)
            if not vuln:
                continue
            if vuln.get("withdrawn"):
                continue
            aliases = list(vuln.get("aliases") or [])
            cve_ids = sorted({c for c in [vid] + aliases if CVE_RE.fullmatch(c)})
            if not cve_ids:
                cve_ids = sorted({m.group(0) for a in aliases for m in [CVE_RE.search(a)] if m})
            kev_hit = next((kevidx[c] for c in cve_ids if c in kevidx), None)
            sev = extract_severity(vuln)
            findings.append({
                "osv_id": vid,
                "cve_ids": cve_ids,
                "aliases": aliases,
                "package": {
                    "name": name, "ecosystem": eco, "version": version,
                    "direct": pkg["direct"], "dev": pkg["dev"],
                    "version_exact": pkg["version_exact"],
                    "manifests": pkg["manifests"],
                },
                "summary": vuln.get("summary") or "",
                "details": (vuln.get("details") or "")[:2000],
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
                "cvss": sev,
                "kev": {
                    "listed": bool(kev_hit),
                    "date_added": (kev_hit or {}).get("dateAdded"),
                    "due_date": (kev_hit or {}).get("dueDate"),
                    "ransomware": (kev_hit or {}).get("knownRansomwareCampaignUse"),
                    "required_action": (kev_hit or {}).get("requiredAction"),
                },
                "fixed_versions": fixed_versions_for(vuln, eco, name),
                "affected_symbols": affected_symbols(vuln, eco, name),
                "search_hints": search_hints(eco, name),
                "references": [
                    r.get("url") for r in (vuln.get("references") or [])[:8] if r.get("url")
                ],
            })

    findings = merge_duplicate_findings(findings)

    def sort_key(f):
        return (
            0 if f["kev"]["listed"] else 1,
            -(f["cvss"]["score"] if f["cvss"]["score"] is not None else 5.0),
            f["package"]["name"],
        )

    return sorted(findings, key=sort_key)


def _osv_rank(vid: str) -> int:
    """同じ脆弱性を指す複数レコードのうち、どれを主とするか。GHSA は情報が厚い。"""
    if vid.startswith("GHSA-"):
        return 0
    if vid.startswith("CVE-"):
        return 1
    if vid.startswith("PYSEC-") or vid.startswith("OSV-"):
        return 2
    return 3


def merge_duplicate_findings(findings: list[dict]) -> list[dict]:
    """同一パッケージ・同一 CVE を指す複数の OSV レコードを 1 件にまとめる。

    GHSA と PYSEC が同じ CVE を別レコードで持つことは多い。そのまま出すと
    同じ脆弱性が二重に報告され、まさにアラート疲れの原因になる。
    片方にしか深刻度が無いことも多いので、統合すると精度も上がる。
    """
    groups: dict[tuple, list[dict]] = {}
    singles: list[dict] = []
    for f in findings:
        pkg = f["package"]
        if not f["cve_ids"]:
            singles.append(f)  # CVE 番号が無いものは統合の判断ができない
            continue
        key = (pkg["ecosystem"], pkg["name"], pkg["version"], f["cve_ids"][0])
        groups.setdefault(key, []).append(f)

    merged = []
    for group in groups.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        group.sort(key=lambda f: _osv_rank(f["osv_id"]))
        base = dict(group[0])
        base["osv_ids"] = [f["osv_id"] for f in group]
        base["merged_from"] = len(group)

        def union(field):
            seen, out = set(), []
            for f in group:
                for v in f.get(field) or []:
                    if v not in seen:
                        seen.add(v)
                        out.append(v)
            return out

        base["cve_ids"] = union("cve_ids")
        base["aliases"] = union("aliases")
        base["fixed_versions"] = union("fixed_versions")
        base["affected_symbols"] = union("affected_symbols")
        base["references"] = union("references")[:12]
        # 深刻度は「スコアが取れているもの」を優先し、複数あれば高いほうを採る
        scored = [f["cvss"] for f in group if f["cvss"]["score"] is not None]
        if scored:
            base["cvss"] = max(scored, key=lambda c: c["score"])
        else:
            labeled = [f["cvss"] for f in group if f["cvss"]["label"] != "UNKNOWN"]
            if labeled:
                base["cvss"] = labeled[0]
        if any(f["kev"]["listed"] for f in group):
            base["kev"] = next(f["kev"] for f in group if f["kev"]["listed"])
        if not base.get("summary"):
            base["summary"] = next((f["summary"] for f in group if f["summary"]), "")
        merged.append(base)

    for f in merged + singles:
        f.setdefault("osv_ids", [f["osv_id"]])
        f.setdefault("merged_from", 1)
    return merged + singles


def parse_package_arg(arg: str) -> dict | None:
    """"npm:lodash@4.17.20" 形式をパースする。"""
    if ":" not in arg or "@" not in arg:
        return None
    eco, rest = arg.split(":", 1)
    at = rest.rfind("@")
    if at <= 0:
        return None
    aliases = {"npm": ECO_NPM, "pypi": ECO_PYPI, "pip": ECO_PYPI,
               "packagist": ECO_COMPOSER, "composer": ECO_COMPOSER}
    eco_norm = aliases.get(eco.strip().lower(), eco.strip())
    return {
        "ecosystem": eco_norm, "name": rest[:at], "version": rest[at + 1:],
        "manifests": ["<cli>"], "dev": False, "direct": True, "version_exact": True,
    }


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="OSV.dev に依存関係を問い合わせる")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--project-root", default=None, help="config.yml の scan.project_root を上書き")
    ap.add_argument("--out", default="-", help="出力先。'-' で標準出力")
    ap.add_argument("--detect-only", action="store_true", help="依存ファイルの検出結果だけ出す")
    ap.add_argument("--packages", nargs="*", default=None,
                    help="ecosystem:name@version 形式で依存を直接指定")
    ap.add_argument("--packages-file", default=None,
                    help="1 行 1 件で ecosystem:name@version を書いたファイル")
    ap.add_argument("--no-kev", action="store_true", help="KEV カタログを引かない")
    ap.add_argument("--offline", action="store_true", help="キャッシュのみ使用（ネットワーク不使用）")
    ap.add_argument("--cache-dir", default=str(here / ".cache"))
    args = ap.parse_args()

    config = load_config(Path(args.config))
    errors: list[dict] = []

    root_raw = args.project_root or cfg_get(config, "scan.project_root", "..")
    project_root = (Path(args.config).resolve().parent / root_raw).resolve()
    excludes = cfg_get(config, "exclude_paths", DEFAULT_EXCLUDES) or DEFAULT_EXCLUDES
    max_depth = int(cfg_get(config, "scan.max_depth", 6) or 6)
    include_dev = bool(cfg_get(config, "scan.include_dev_dependencies", True))
    cache_dir = Path(args.cache_dir)

    # --- 依存の収集 -------------------------------------------------------
    pkgs: dict = {}
    manifests: list[dict] = []
    explicit = list(args.packages or [])
    if args.packages_file:
        explicit += [
            l.strip() for l in Path(args.packages_file).read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")
        ]

    if explicit:
        for arg in explicit:
            parsed = parse_package_arg(arg)
            if parsed:
                pkgs[(parsed["ecosystem"], parsed["name"], parsed["version"])] = parsed
            else:
                errors.append({"stage": "input", "error": f"解析できない指定: {arg}"})
    else:
        configured = cfg_get(config, "scan.manifests", "auto")
        if isinstance(configured, list) and configured:
            for rel in configured:
                p = (project_root / rel).resolve()
                if p.exists() and p.name in MANIFEST_NAMES:
                    eco, prio = MANIFEST_NAMES[p.name]
                    manifests.append({"path": str(p), "rel_path": rel, "file": p.name,
                                      "ecosystem": eco, "priority": prio, "dir": str(p.parent)})
                else:
                    errors.append({"stage": "input", "error": f"見つからない/未対応: {rel}"})
        else:
            manifests = discover_manifests(project_root, excludes, max_depth,
                                           self_dir=here)
        for m in manifests:
            parse_manifest(m, pkgs, errors, include_dev)

    packages = list(pkgs.values())

    if args.detect_only:
        out = {
            "project_root": str(project_root),
            "manifests": [{k: m[k] for k in ("rel_path", "ecosystem")} for m in manifests],
            "packages_found": len(packages),
            "by_ecosystem": {
                eco: sum(1 for p in packages if p["ecosystem"] == eco)
                for eco in sorted({p["ecosystem"] for p in packages})
            },
            "errors": errors,
        }
        _emit(out, args.out)
        return 0

    # --- OSV / KEV --------------------------------------------------------
    if args.offline:
        vuln_map, vulns = {}, {}
        errors.append({"stage": "osv", "error": "offline mode: OSV 未照会"})
    else:
        vuln_map = osv_querybatch(packages, errors) if packages else {}
        all_ids = sorted({vid for ids in vuln_map.values() for vid in ids})
        vulns = fetch_vulns(all_ids, cache_dir, errors) if all_ids else {}

    kevidx = {} if args.no_kev else kev_index(load_kev(cache_dir, errors, args.offline))
    findings = build_findings(packages, vuln_map, vulns, kevidx)

    out = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project_root": str(project_root),
        "manifests": [
            {"rel_path": m["rel_path"], "ecosystem": m["ecosystem"], "file": m["file"]}
            for m in manifests
        ],
        "packages_scanned": len(packages),
        "packages_by_ecosystem": {
            eco: sum(1 for p in packages if p["ecosystem"] == eco)
            for eco in sorted({p["ecosystem"] for p in packages})
        },
        "kev_catalog": {
            "loaded": bool(kevidx),
            "entries": len(kevidx),
        },
        "findings_count": len(findings),
        "findings": findings,
        "errors": errors,
    }
    _emit(out, args.out)
    # 通信に失敗している場合は非ゼロで返す（結果が空なのか未取得なのかを区別するため）
    return 2 if any(e.get("stage") in ("querybatch", "osv") for e in errors) else 0


def _emit(obj: dict, dest: str):
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if dest == "-":
        sys.stdout.write(text + "\n")
    else:
        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {path} ({len(text)} bytes)\n")


if __name__ == "__main__":
    sys.exit(main())
