#!/usr/bin/env python3
"""ミドルウェア・実行環境の CVE を NVD（CPE 照合）で引く。

osv_query.py が扱うのは OSV.dev に照会できるエコシステム（npm / PyPI / Composer）
だけで、Apache / nginx / OpenSSL / PHP 本体のようなミドルウェアは死角になる。
このスクリプトは config.yml の `scan.middleware` に宣言された製品を
NVD API 2.0 の CPE 照合で引き、osv_query.py と同じ findings スキーマで出力する。

宣言ベースにしている理由: 実行環境はリポジトリの外にあり、コードからバージョンを
確実に検出できない。不確かな自動検出で「照会した気になる」より、宣言されたものを
確実に照会するほうが安全（検出の提案は SKILL.md で Claude が行う）。

API キーは不要。あれば NVD_API_KEY 環境変数から読む（レート制限が
5 req/30s → 50 req/30s に緩むだけで、機能は変わらない）。

注意: NVD には解析遅延（新しい CVE への CPE 付与の遅れ)がある。
結果が 0 件でも「脆弱性なし」ではなく「NVD 照会で該当なし」でしかない。

使い方:
    python3 scripts/nvd_query.py                            # config の宣言を照会
    python3 scripts/nvd_query.py --products nginx@1.18.0    # 直接指定
    python3 scripts/nvd_query.py --list-products            # 対応製品の一覧
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_query import (  # noqa: E402
    HTTP_TIMEOUT, KEV_CACHE_TTL, USER_AGENT,
    cfg_get, kev_index, load_config, load_kev, severity_label,
)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 製品名 → CPE prefix の対応表。
# 同じ製品でも年代によって vendor が違うことがある（nginx は nginx→f5 に移管、
# curl は haxx→curl）。古い CVE を取りこぼさないよう複数 prefix を全部引く。
# ここに無い製品を足すときは https://nvd.nist.gov/products/cpe/search で
# prefix を確認して追記する。
CPE_TABLE: dict[str, list[str]] = {
    "apache-httpd": ["cpe:2.3:a:apache:http_server"],
    "nginx":        ["cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx"],
    "openssl":      ["cpe:2.3:a:openssl:openssl"],
    "php":          ["cpe:2.3:a:php:php"],
    "mysql":        ["cpe:2.3:a:oracle:mysql", "cpe:2.3:a:mysql:mysql"],
    "mariadb":      ["cpe:2.3:a:mariadb:mariadb"],
    "postgresql":   ["cpe:2.3:a:postgresql:postgresql"],
    "redis":        ["cpe:2.3:a:redis:redis", "cpe:2.3:a:redislabs:redis"],
    "memcached":    ["cpe:2.3:a:memcached:memcached"],
    "tomcat":       ["cpe:2.3:a:apache:tomcat"],
    "nodejs":       ["cpe:2.3:a:nodejs:node.js"],
    "curl":         ["cpe:2.3:a:curl:curl", "cpe:2.3:a:haxx:curl"],
    "ruby":         ["cpe:2.3:a:ruby-lang:ruby"],
    "python":       ["cpe:2.3:a:python:python"],
    "haproxy":      ["cpe:2.3:a:haproxy:haproxy"],
}

# 別名の吸収（apache とだけ書かれても引けるように）
ALIASES = {
    "apache": "apache-httpd",
    "httpd": "apache-httpd",
    "node": "nodejs",
    "node.js": "nodejs",
}


# ===========================================================================
# バージョン候補の自動検出（--suggest）
#
# リポジトリの中のヒント（Dockerfile 等）から宣言の「候補」を出す。
# ここで出るのはあくまで候補であり、照会はしない。理由:
#   - `php:8.1` のようなタグはパッチ版を固定しない（pull した日によって違う）
#   - 本番がコンテナですらない場合、リポジトリには何のヒントも無い
# 正確なバージョンはサーバでの実測（php -v 等）でしか分からない。
# ===========================================================================

IMAGE_TO_PRODUCT = {
    "php": "php", "nginx": "nginx", "node": "nodejs", "python": "python",
    "ruby": "ruby", "httpd": "apache-httpd", "mysql": "mysql",
    "mariadb": "mariadb", "postgres": "postgresql", "redis": "redis",
    "memcached": "memcached", "tomcat": "tomcat", "haproxy": "haproxy",
}

VERSION_FILE_PRODUCT = {
    ".nvmrc": "nodejs", ".node-version": "nodejs",
    ".python-version": "python", ".ruby-version": "ruby",
    ".php-version": "php",
}

TOOL_VERSIONS_MAP = {"nodejs": "nodejs", "node": "nodejs",
                     "python": "python", "ruby": "ruby", "php": "php"}


def _split_image_ref(ref: str) -> tuple[str, str]:
    """'docker.io/library/php:8.1-apache@sha256:..' -> ('php', '8.1-apache')"""
    ref = ref.split("@")[0]
    tail = ref.split("/")[-1]
    name, _, tag = tail.partition(":")
    return name.lower(), tag


def _version_from_text(text: str) -> str | None:
    m = re.search(r"\d+(?:\.\d+)*", text or "")
    return m.group(0) if m else None


def _mk_candidate(product: str, raw: str, source: str, version: str | None) -> dict:
    exact = bool(version) and version.count(".") >= 2
    if not version:
        note = "バージョン不明。サーバで実測して宣言する"
    elif not exact:
        note = "パッチ版まで不明。サーバでの実測を推奨（このまま宣言すると下限で照会）"
    else:
        note = "タグ/範囲由来。実環境と一致するかはサーバで確認を推奨"
    return {"name": product, "version": version, "version_exact": exact,
            "raw": raw, "source": source, "note": note}


def suggest_products(project_root: Path, excludes: list, max_depth: int,
                     self_dir: Path) -> dict:
    candidates: list[dict] = []
    unsupported: list[dict] = []
    excl = set(excludes or [])

    def add_image(ref: str, source: str):
        name, tag = _split_image_ref(ref)
        if name == "scratch":
            return
        product = IMAGE_TO_PRODUCT.get(name)
        if product:
            candidates.append(_mk_candidate(product, ref, source,
                                            _version_from_text(tag)))
        else:
            unsupported.append({"image": ref, "source": source})

    for dirpath, dirnames, filenames in os.walk(project_root):
        d = Path(dirpath)
        try:
            depth = len(d.relative_to(project_root).parts)
        except ValueError:
            depth = 0
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [x for x in dirnames
                       if x not in excl and (d / x).resolve() != self_dir]
        for fn in filenames:
            path = d / fn
            rel = str(path.relative_to(project_root))
            low = fn.lower()
            try:
                if low.startswith("dockerfile"):
                    for i, line in enumerate(
                            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)",
                                     line, re.IGNORECASE)
                        if m:
                            add_image(m.group(1), f"{rel}:{i}")
                elif re.fullmatch(r"(docker-)?compose[^/]*\.ya?ml", low):
                    for i, line in enumerate(
                            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        m = re.match(r"\s*image:\s*[\"']?([^\s\"'#]+)", line)
                        if m:
                            add_image(m.group(1), f"{rel}:{i}")
                elif low == ".tool-versions":
                    for i, line in enumerate(
                            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] in TOOL_VERSIONS_MAP:
                            candidates.append(_mk_candidate(
                                TOOL_VERSIONS_MAP[parts[0]], line.strip(),
                                f"{rel}:{i}", _version_from_text(parts[1])))
                elif fn in VERSION_FILE_PRODUCT:
                    first = path.read_text(encoding="utf-8",
                                           errors="replace").strip().splitlines()
                    if first:
                        candidates.append(_mk_candidate(
                            VERSION_FILE_PRODUCT[fn], first[0].strip(),
                            f"{rel}:1", _version_from_text(first[0])))
                elif fn == "package.json":
                    data = json.loads(path.read_text(encoding="utf-8"))
                    node = (data.get("engines") or {}).get("node")
                    if node:
                        candidates.append(_mk_candidate(
                            "nodejs", f"engines.node: {node}",
                            f"{rel} (engines.node)", _version_from_text(node)))
                elif fn == "composer.json":
                    data = json.loads(path.read_text(encoding="utf-8"))
                    php = (data.get("require") or {}).get("php")
                    if php:
                        candidates.append(_mk_candidate(
                            "php", f"require.php: {php}",
                            f"{rel} (require.php)", _version_from_text(php)))
            except (OSError, json.JSONDecodeError):
                continue

    # 同じ (製品, バージョン) は 1 件にまとめる（検出元は最初のもの）
    seen, deduped = set(), []
    for c in candidates:
        key = (c["name"], c["version"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return {"candidates": deduped, "unsupported_images": unsupported}


def _norm_version(v: str) -> tuple[str, bool]:
    """宣言されたバージョンを照会用に正規化する。

    '8.1' のようにパッチ版が無い宣言は下限 '8.1.0' として照会する
    （version_exact: false）。多めに報告する方向にしか倒れない。
    """
    v = v.strip().lstrip("v")
    parts = v.split(".")
    exact = len(parts) >= 3
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts), exact


def _nvd_get(params: dict, api_key: str | None, retries: int = 4):
    url = NVD_CVE_URL + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            # NVD は過負荷時に 403 を返すことがあるのでリトライ対象に含める
            if exc.code not in (403, 429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
        time.sleep(6 * (attempt + 1))
    raise RuntimeError(f"{url}: {type(last).__name__}: {last}")


def _extract_cvss(cve: dict) -> dict:
    """NVD の metrics から CVSS を取り出す。v3.1 → v3.0 → v4.0 → v2 の順。"""
    metrics = cve.get("metrics") or {}
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Primary（NVD 自身の評価）を優先
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        return {
            "score": float(score),
            "label": severity_label(float(score)),
            "vector": data.get("vectorString"),
            "version": ver,
            "source": f"nvd_v{ver.replace('.', '')}",
        }
    return {"score": None, "label": "UNKNOWN", "vector": None,
            "version": None, "source": "unavailable"}


def _fixed_versions(cve: dict, prefixes: list[str]) -> list[str]:
    """脆弱レンジの versionEndExcluding を「修正版の候補」として集める。"""
    fixed = set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                crit = m.get("criteria") or ""
                if not any(crit.startswith(p + ":") for p in prefixes):
                    continue
                end = m.get("versionEndExcluding")
                if end:
                    fixed.add(end)
    return sorted(fixed)


def _description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def query_product(name: str, version_query: str, version_raw: str,
                  version_exact: bool, api_key: str | None,
                  cache_dir: Path, offline: bool, errors: list) -> list[dict]:
    """1 製品を照会して findings のリストを返す。"""
    prefixes = CPE_TABLE[name]
    by_cve: dict[str, dict] = {}

    for prefix in prefixes:
        cpe_name = f"{prefix}:{version_query}:*:*:*:*:*:*:*"
        cache = cache_dir / "nvd" / f"{name}-{version_query}-{prefix.split(':')[3]}.json"
        data = None
        if cache.exists() and (time.time() - cache.stat().st_mtime) < KEV_CACHE_TTL:
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = None
        if data is None:
            if offline:
                errors.append({"stage": "nvd", "product": f"{name}@{version_raw}",
                               "error": "offline mode: NVD 未照会"})
                continue
            try:
                data = _nvd_get({"cpeName": cpe_name, "isVulnerable": "",
                                 "resultsPerPage": "2000"}, api_key)
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(data), encoding="utf-8")
            except RuntimeError as exc:
                errors.append({"stage": "nvd", "product": f"{name}@{version_raw}",
                               "error": str(exc)})
                continue
            # レート制限（キー無し 5req/30s）を尊重する
            time.sleep(1 if api_key else 7)

        if data.get("totalResults", 0) > len(data.get("vulnerabilities") or []):
            errors.append({"stage": "nvd", "product": f"{name}@{version_raw}",
                           "error": f"結果が 2000 件を超えており一部のみ取得 "
                                    f"({data['totalResults']} 件)"})

        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cid = cve.get("id")
            if not cid or cve.get("vulnStatus") == "Rejected":
                continue
            if cid in by_cve:
                continue
            by_cve[cid] = {
                "osv_id": cid,
                "cve_ids": [cid],
                "aliases": [],
                "package": {
                    "name": name, "ecosystem": "middleware", "version": version_raw,
                    "direct": True, "dev": False, "version_exact": version_exact,
                    "manifests": ["config.yml (scan.middleware)"],
                },
                "summary": _description(cve)[:300],
                "details": _description(cve)[:2000],
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "cvss": _extract_cvss(cve),
                "kev": {"listed": False, "date_added": None, "due_date": None,
                        "ransomware": None, "required_action": None},
                "fixed_versions": _fixed_versions(cve, prefixes),
                "affected_symbols": [],
                "search_hints": {"module_candidates": [name], "grep_patterns": []},
                "references": [
                    r.get("url") for r in (cve.get("references") or [])[:8]
                    if r.get("url")
                ],
            }
    return list(by_cve.values())


def parse_product_arg(arg: str, errors: list) -> tuple[str, str] | None:
    if "@" not in arg:
        errors.append({"stage": "input", "error": f"name@version 形式で指定: {arg}"})
        return None
    name, _, version = arg.partition("@")
    name = ALIASES.get(name.strip().lower(), name.strip().lower())
    if name not in CPE_TABLE:
        errors.append({"stage": "input",
                       "error": f"未対応の製品: {name}（--list-products で一覧。"
                                f"CPE_TABLE への追記も可）"})
        return None
    if not version.strip():
        errors.append({"stage": "input", "error": f"バージョンが空: {arg}"})
        return None
    return name, version.strip()


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="ミドルウェアの CVE を NVD (CPE) で引く")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--products", nargs="*", default=None,
                    help="name@version 形式（例: nginx@1.18.0）。省略時は config の scan.middleware")
    ap.add_argument("--out", default="-", help="出力先。'-' で標準出力")
    ap.add_argument("--no-kev", action="store_true")
    ap.add_argument("--offline", action="store_true", help="キャッシュのみ使用")
    ap.add_argument("--cache-dir", default=str(here / ".cache"))
    ap.add_argument("--list-products", action="store_true", help="対応製品の一覧を表示")
    ap.add_argument("--suggest", action="store_true",
                    help="リポジトリ内のヒント（Dockerfile 等）から宣言候補を出す。照会はしない")
    ap.add_argument("--project-root", default=None,
                    help="--suggest の走査対象。省略時は config の scan.project_root")
    args = ap.parse_args()

    if args.list_products:
        for name, prefixes in sorted(CPE_TABLE.items()):
            print(f"{name:14s} {' / '.join(prefixes)}")
        return 0

    config = load_config(Path(args.config))
    errors: list[dict] = []
    cache_dir = Path(args.cache_dir)
    api_key = os.environ.get("NVD_API_KEY") or None

    if args.suggest:
        root_raw = args.project_root or cfg_get(config, "scan.project_root", "..")
        project_root = (Path(args.config).resolve().parent / root_raw).resolve()
        excludes = cfg_get(config, "exclude_paths", []) or []
        max_depth = int(cfg_get(config, "scan.max_depth", 6) or 6)
        result = suggest_products(project_root, excludes, max_depth, self_dir=here)
        out = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "project_root": str(project_root),
            "declared": cfg_get(config, "scan.middleware", []) or [],
            **result,
            "note": "これは宣言の候補であり、照会はしていない。正確なバージョンは"
                    "サーバでの実測（php -v / nginx -v 等）で確認して scan.middleware に宣言する",
        }
        text = json.dumps(out, ensure_ascii=False, indent=2)
        if args.out == "-":
            sys.stdout.write(text + "\n")
        else:
            path = Path(args.out)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text + "\n", encoding="utf-8")
            sys.stderr.write(f"wrote {path}\n")
        return 0

    # --- 対象の決定 -------------------------------------------------------
    products: list[tuple[str, str]] = []
    if args.products is not None:
        for arg in args.products:
            parsed = parse_product_arg(arg, errors)
            if parsed:
                products.append(parsed)
    else:
        declared = cfg_get(config, "scan.middleware", []) or []
        for entry in declared:
            if not isinstance(entry, dict):
                errors.append({"stage": "input", "error": f"不正な middleware 宣言: {entry!r}"})
                continue
            parsed = parse_product_arg(
                f"{entry.get('name', '')}@{entry.get('version', '')}", errors)
            if parsed:
                products.append(parsed)

    # --- 照会 -------------------------------------------------------------
    findings: list[dict] = []
    for name, version in products:
        version_query, version_exact = _norm_version(version)
        if not version_exact:
            errors.append({"stage": "input_note",
                           "error": f"{name}@{version} はパッチ版まで不明のため"
                                    f"下限 {version_query} で照会（多めに出る）"})
        findings.extend(query_product(name, version_query, version, version_exact,
                                      api_key, cache_dir, args.offline, errors))

    # KEV 照合（OSV 側と同じカタログ・同じキャッシュを使う）
    kevidx = {} if args.no_kev else kev_index(load_kev(cache_dir, errors, args.offline))
    for f in findings:
        hit = kevidx.get(f["osv_id"])
        if hit:
            f["kev"] = {
                "listed": True,
                "date_added": hit.get("dateAdded"),
                "due_date": hit.get("dueDate"),
                "ransomware": hit.get("knownRansomwareCampaignUse"),
                "required_action": hit.get("requiredAction"),
            }

    findings.sort(key=lambda f: (
        0 if f["kev"]["listed"] else 1,
        -(f["cvss"]["score"] if f["cvss"]["score"] is not None else 5.0),
        f["package"]["name"],
    ))

    out = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "nvd_cpe",
        "api_key_used": bool(api_key),
        "products": [f"{n}@{v}" for n, v in products],
        "kev_catalog": {"loaded": bool(kevidx), "entries": len(kevidx)},
        "findings_count": len(findings),
        "findings": findings,
        "errors": errors,
        # NVD は新しい CVE への CPE 付与が遅れることがある。
        "note": "0 件は「NVD 照会で該当なし」であって「脆弱性なし」の保証ではない",
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.out == "-":
        sys.stdout.write(text + "\n")
    else:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {path} ({len(text)} bytes)\n")

    return 2 if any(e.get("stage") == "nvd" for e in errors) else 0


if __name__ == "__main__":
    sys.exit(main())
