#!/usr/bin/env python3
"""ignore ルールの適用（quiet-cve 共通モジュール）。

手元トリアージ（SKILL.md Step 3）と CI（ci_summary.py）の両方がここを使う。
適用ロジックが 2 箇所にあると、片方だけ直して挙動が食い違う事故が起きるため。

## ignore の寿命種別

無視する理由には「腐らないもの」と「腐るもの」がある。

- **腐らない理由**: アドバイザリの撤回・誤検知、実行環境的に非該当
  （Windows 限定の脆弱性で Linux にしかデプロイしない等）。
  コードがどう変わっても無効にならないので、`expires: never`（永久 ignore）を許す。
- **腐る理由**: 「該当機能を使っていない」「実行経路で到達しない」系。
  コードが変われば**無言で**無効になるので、永久 ignore は絶対に許さない。
  さらにカレンダー期限より賢い失効条件として、根拠ファイルの変更検知を持つ。

種別は VEX（CycloneDX）の justification 語彙で宣言する:

    腐らない（expires: never 可）:
      false_positive / platform_not_applicable
    腐る（expires: never は設定エラーで実行停止）:
      vulnerable_code_not_in_execute_path
      vulnerable_code_cannot_be_controlled_by_adversary
      inline_mitigations_already_exist

justification 未指定の既存エントリは従来どおり「日付の期限が必須・never 不可」。

## 根拠ファイルの変更検知

腐るカテゴリのエントリに evidence_files と verified_at_commit を書くと、
`git diff --name-only <commit> -- <files>` で判定時点からの変更を確認し、
変更があれば**期限内でも**「根拠ファイル変更あり・再確認が必要」として再浮上させる。
git が使えない / コミットが見つからない場合は警告を出してカレンダー期限のみで
動作する（黙って無視しない）。カレンダー期限は「依存の依存が変わった」等の
間接的な変化を拾う安全網としてそのまま残る（併用）。

使い方（CLI）:
    python3 scripts/ignore_rules.py --scan .cache/scan.json --out .cache/triage-input.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_query import _emit, _norm_pkg, cfg_get, load_config  # noqa: E402

# VEX (CycloneDX) 準拠の justification 語彙
ROT_PROOF = {
    "false_positive",
    "platform_not_applicable",
}
ROTTING = {
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

# 再浮上の種別 → レポート用の短いラベル
RESURFACE_LABEL = {
    "expired": "除外期限切れ",
    "evidence_changed": "根拠ファイル変更",
    "invalid_justification": "justification 不正",
    "missing_expiry": "期限未設定",
}


class IgnoreConfigError(ValueError):
    """設定として成立していない ignore。実行を止めるべきもの。"""


def validate_rules(config: dict) -> None:
    """腐るカテゴリ + expires: never は設定エラーとして実行を停止させる。"""
    for section in ("cves", "packages"):
        for rule in cfg_get(config, f"ignore.{section}", []) or []:
            if not isinstance(rule, dict):
                continue
            j = rule.get("justification")
            if j in ROTTING and _is_never(rule.get("expires")):
                ident = rule.get("id") or rule.get("name") or "?"
                raise IgnoreConfigError(
                    f"ignore 設定エラー: {ident} は justification: {j} なのに "
                    f"expires: never が指定されている。\n"
                    f"「使っていない / 到達しない」系の判断は、コードが変わると無言で無効になるため、"
                    f"永久 ignore を許可していない。日付で期限を書くこと。例:\n"
                    f"    - id: {ident}\n"
                    f"      justification: {j}\n"
                    f'      expires: "2026-12-31"\n'
                    f"（永久 ignore が許されるのは false_positive / platform_not_applicable のみ）"
                )


def _is_never(value) -> bool:
    return isinstance(value, str) and value.strip().lower() == "never"


def _parse_expires(value) -> date | None:
    if isinstance(value, date):
        return value
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def _finding_ids(finding: dict) -> set[str]:
    ids = set(finding.get("cve_ids") or [])
    ids.add(finding.get("osv_id") or "")
    ids.update(finding.get("aliases") or [])
    return {i for i in ids if i}


def _match_rule(finding: dict, cve_rules: list, pkg_rules: list) -> dict | None:
    ids = _finding_ids(finding)
    pkg = finding.get("package") or {}
    eco = pkg.get("ecosystem") or ""
    norm_name = _norm_pkg(eco, pkg.get("name") or "")

    for rule in cve_rules:
        if isinstance(rule, dict) and str(rule.get("id") or "") in ids:
            return rule
    for rule in pkg_rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("ecosystem") or "") != eco:
            continue
        if _norm_pkg(eco, str(rule.get("name") or "")) == norm_name:
            return rule
    return None


def _evidence_changed(rule: dict, project_root: Path | None,
                      warnings: list) -> bool | None:
    """根拠ファイルが verified_at_commit 以降に変わったか。

    True = 変更あり / False = 変更なし / None = 判定不能（警告済み・期限のみで動作）。
    git diff <commit> -- <paths> は「コミット vs 作業ツリー」の比較なので、
    未コミットの変更も拾う（安全側）。
    """
    files = [str(f) for f in (rule.get("evidence_files") or [])]
    commit = str(rule.get("verified_at_commit") or "").strip()
    ident = rule.get("id") or rule.get("name") or "?"

    if not files and not commit:
        return None
    if not files or not commit:
        warnings.append({
            "stage": "ignore", "rule": ident,
            "error": "evidence_files と verified_at_commit は両方そろって初めて"
                     "変更検知が効く。片方だけなので、カレンダー期限のみで判定する",
        })
        return None
    if project_root is None:
        warnings.append({
            "stage": "ignore", "rule": ident,
            "error": "project_root が不明のため根拠ファイルの変更検知を実行できない。"
                     "カレンダー期限のみで判定する",
        })
        return None

    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), "diff", "--name-only", commit,
             "--", *files],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        warnings.append({
            "stage": "ignore", "rule": ident,
            "error": f"git を実行できない（{exc}）。カレンダー期限のみで判定する",
        })
        return None
    if result.returncode != 0:
        warnings.append({
            "stage": "ignore", "rule": ident,
            "error": f"git diff が失敗（{(result.stderr or '').strip()[:150]}）。"
                     f"コミット {commit} が見つからない場合は shallow clone の可能性。"
                     f"カレンダー期限のみで判定する",
        })
        return None
    return bool(result.stdout.strip())


def apply_ignores(findings: list[dict], config: dict, today: date,
                  project_root: Path | None = None,
                  warnings: list | None = None):
    """(残った findings, 無視した件数, 再浮上リスト) を返す。

    再浮上した finding には finding["ignore_resurfaced"] =
    {kind, note, reason} が付く。kind は RESURFACE_LABEL のキー。
    """
    if warnings is None:
        warnings = []
    cve_rules = cfg_get(config, "ignore.cves", []) or []
    pkg_rules = cfg_get(config, "ignore.packages", []) or []

    kept: list[dict] = []
    resurfaced: list[dict] = []
    ignored = 0

    def resurface(finding: dict, rule: dict, kind: str, note: str):
        entry = {
            "rule": rule.get("id") or rule.get("name"),
            "kind": kind,
            "note": note,
            "reason": rule.get("reason") or "",
        }
        resurfaced.append(entry)
        finding = dict(finding)
        finding["ignore_resurfaced"] = {
            "kind": kind, "note": note, "reason": entry["reason"],
        }
        kept.append(finding)

    for finding in findings:
        rule = _match_rule(finding, cve_rules, pkg_rules)
        if rule is None:
            kept.append(finding)
            continue

        j = rule.get("justification")
        expires_raw = rule.get("expires")

        # 1) justification が語彙に無い → 抑制せず再浮上（設定の書き間違いを隠さない）
        if j is not None and j not in ROT_PROOF and j not in ROTTING:
            resurface(finding, rule, "invalid_justification",
                      f"不正な justification: {j}"
                      f"（許可: {', '.join(sorted(ROT_PROOF | ROTTING))}）")
            continue

        # 2) expires: never — 腐らないカテゴリのみ許可
        if _is_never(expires_raw):
            if j in ROT_PROOF:
                ignored += 1  # 永久 ignore
                continue
            # j is None（腐るカテゴリ + never は validate_rules で既に停止している）
            resurface(finding, rule, "missing_expiry",
                      "expires: never は justification が腐らないカテゴリ"
                      "（false_positive / platform_not_applicable）の場合のみ。"
                      "日付で期限を書く")
            continue

        # 3) 日付期限の判定
        expires = _parse_expires(expires_raw)
        if expires is None:
            resurface(finding, rule, "missing_expiry", "expires 未設定または不正")
            continue
        if expires < today:
            resurface(finding, rule, "expired", f"{expires} に失効")
            continue

        # 4) 期限内 → 根拠ファイルの変更検知（指定があれば）
        changed = _evidence_changed(rule, project_root, warnings)
        if changed:
            commit = rule.get("verified_at_commit")
            resurface(finding, rule, "evidence_changed",
                      f"根拠ファイルに {commit} 以降の変更あり・再確認が必要"
                      f"（{', '.join(str(f) for f in rule.get('evidence_files') or [])}）")
            continue

        ignored += 1

    # 同じルールが複数 finding に当たっても、再浮上の通知は 1 回で足りる
    seen, unique = set(), []
    for e in resurfaced:
        key = (e["rule"], e["kind"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return kept, ignored, unique


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(
        description="config.yml の ignore を scan 結果へ適用する（SKILL.md Step 3）")
    ap.add_argument("--scan", required=True, nargs="+",
                    help="osv_query.py / nvd_query.py --out の JSON（複数可）")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--project-root", default=None,
                    help="根拠ファイル変更検知の git 実行場所。省略時は scan の project_root")
    ap.add_argument("--today", default=None, help="期限判定に使う日付（テスト用）")
    ap.add_argument("--out", default="-", help="出力先。'-' で標準出力")
    args = ap.parse_args()

    config = load_config(Path(args.config))
    try:
        validate_rules(config)
    except IgnoreConfigError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1

    scans = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.scan]
    findings = [f for s in scans for f in (s.get("findings") or [])]

    root = args.project_root or next(
        (s.get("project_root") for s in scans if s.get("project_root")), None)
    if root is None:
        root_raw = cfg_get(config, "scan.project_root", "..")
        root = (Path(args.config).resolve().parent / root_raw).resolve()

    today = (datetime.strptime(args.today, "%Y-%m-%d").date()
             if args.today else datetime.now(timezone.utc).date())

    warnings: list = []
    kept, ignored, resurfaced = apply_ignores(
        findings, config, today, project_root=Path(root), warnings=warnings)

    _emit({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project_root": str(root),
        "findings_count": len(kept),
        "findings": kept,
        "ignored_count": ignored,
        "resurfaced": resurfaced,
        "warnings": warnings,
    }, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
