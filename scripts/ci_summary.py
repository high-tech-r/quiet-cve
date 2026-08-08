#!/usr/bin/env python3
"""osv_query.py の出力を CI 向けに要約する。

CI 上では Claude が動かないため、SKILL.md Step 4（コード実使用判定）が実行できない。
つまり **このスクリプトは最終判定を下さない**。全 finding を `usage: unknown` として
扱い、「人間がトリアージすべきものが何件あるか」だけを出す。

とくに `影響なし`（not_affected）は絶対に出力しない。根拠なしに安心を配らない、
という設計原則を CI 側でも守るため、上位ルールに当たらなかったものは
`untriaged`（未判定）に置く。CI の出力は検知であって判定ではない。

分類は SKILL.md Step 5 の表を `usage: unknown` に固定して適用したもの:

    1. kev.listed かつ kev_always_act        -> act
    4. CVSS >= act_cvss                      -> watch
    6. CVSS 不明 (label: UNKNOWN)            -> thresholds.unknown_severity
    7. 上記以外                              -> untriaged（CI では not_affected にしない）

スコアが無くラベルだけの finding（`cvss.source: advisory_label`）は、
severity_label() と同じ境界（CRITICAL/HIGH = 7.0 以上, MEDIUM = 4.0 以上）で
ラベルを下限スコアとみなす。推定を上振れさせる方向なので、見逃しは増えない。

Step 3 の ignore 適用もここで行う。osv_query.py は ignore を知らないため、
これをやらないと握りつぶしたはずの CVE が CI 側で再浮上する。
`expires` 切れの項目は無視されず「除外期限切れ」として報告に載る。

使い方:
    python3 scripts/ci_summary.py --scan scan.json --out summary.json --markdown body.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_query import _norm_pkg, cfg_get, load_config  # noqa: E402

# advisory_label しか無い場合に、ラベルを下限スコアとして読み替える表。
# severity_label() の境界と同じ値にしてある（片方だけ動かさないこと）。
LABEL_FLOOR = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "NONE": 0.0}

BUCKET_LABEL = {
    "act": "🔴 要対応",
    "watch": "🟡 要トリアージ",
    "untriaged": "⚪ 未判定",
}


# ---------------------------------------------------------------------------
# ignore（SKILL.md Step 3）
# ---------------------------------------------------------------------------

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


def apply_ignores(findings: list[dict], config: dict, today: date):
    """(残った findings, 無視した件数, 期限切れルール) を返す。"""
    cve_rules = cfg_get(config, "ignore.cves", []) or []
    pkg_rules = cfg_get(config, "ignore.packages", []) or []

    expired: list[dict] = []
    kept: list[dict] = []
    ignored = 0

    for finding in findings:
        ids = _finding_ids(finding)
        pkg = finding.get("package") or {}
        eco = pkg.get("ecosystem") or ""
        norm_name = _norm_pkg(eco, pkg.get("name") or "")

        matched = None
        for rule in cve_rules:
            if isinstance(rule, dict) and str(rule.get("id") or "") in ids:
                matched = rule
                break
        if matched is None:
            for rule in pkg_rules:
                if not isinstance(rule, dict):
                    continue
                if str(rule.get("ecosystem") or "") != eco:
                    continue
                if _norm_pkg(eco, str(rule.get("name") or "")) == norm_name:
                    matched = rule
                    break

        if matched is None:
            kept.append(finding)
            continue

        expires = _parse_expires(matched.get("expires"))
        # expires が無い / 読めない ignore は無効。無期限の握りつぶしを作らない。
        if expires is None or expires < today:
            note = "expires 未設定または不正" if expires is None else f"{expires} に失効"
            finding = dict(finding)
            finding["ignore_expired"] = {
                "reason": matched.get("reason") or "",
                "note": note,
            }
            expired.append({
                "rule": matched.get("id") or matched.get("name"),
                "note": note,
                "reason": matched.get("reason") or "",
            })
            kept.append(finding)
        else:
            ignored += 1

    # 同じルールが複数 finding に当たっても、期限切れ通知は 1 回で足りる
    seen, unique_expired = set(), []
    for e in expired:
        if e["rule"] not in seen:
            seen.add(e["rule"])
            unique_expired.append(e)

    return kept, ignored, unique_expired


# ---------------------------------------------------------------------------
# 分類（SKILL.md Step 5 を usage: unknown に固定して適用）
# ---------------------------------------------------------------------------

def effective_score(cvss: dict):
    """数値スコア。無ければラベルから下限を当てる。どちらも無ければ None。"""
    score = cvss.get("score")
    if isinstance(score, (int, float)):
        return float(score)
    return LABEL_FLOOR.get(str(cvss.get("label") or "").upper())


def classify(finding: dict, config: dict) -> tuple[str, str]:
    """(bucket, 理由) を返す。bucket は act | watch | untriaged。"""
    act_cvss = float(cfg_get(config, "thresholds.act_cvss", 7.0) or 7.0)
    kev_always_act = bool(cfg_get(config, "thresholds.kev_always_act", True))
    unknown_severity = str(cfg_get(config, "thresholds.unknown_severity", "watch") or "watch")

    if finding.get("kev", {}).get("listed") and kev_always_act:
        return "act", "KEV 掲載（CVSS を問わず要対応）"

    cvss = finding.get("cvss") or {}
    score = effective_score(cvss)

    if score is None:
        # ルール 6: 深刻度不明。config の指示に従う（既定 watch）。
        if unknown_severity == "act":
            return "act", "深刻度不明（unknown_severity: act）"
        if unknown_severity == "ignore":
            return "untriaged", "深刻度不明（unknown_severity: ignore）"
        return "watch", "深刻度不明（unknown_severity: watch）"

    if score >= act_cvss:
        # ルール 4: 実使用が未確認なので act には上げず watch 止まり。
        return "watch", f"{_score_text(cvss, score)} >= act_cvss({act_cvss})、実使用は未確認"

    return "untriaged", f"{_score_text(cvss, score)} < act_cvss({act_cvss})、実使用は未確認"


def _score_text(cvss: dict, score: float) -> str:
    if cvss.get("score") is None:
        return f"ラベル {cvss.get('label')} 由来の下限 {score}"
    return f"CVSS {score}"


# ---------------------------------------------------------------------------
# 出力
# ---------------------------------------------------------------------------

def _pkg_line(finding: dict) -> str:
    pkg = finding.get("package") or {}
    kind = "直接" if pkg.get("direct") else "推移"
    dev = "・dev" if pkg.get("dev") else ""
    return f"{pkg.get('ecosystem')}:{pkg.get('name')}@{pkg.get('version')} ({kind}{dev})"


def _cve_line(finding: dict) -> str:
    ids = finding.get("cve_ids") or []
    return ", ".join(ids) if ids else (finding.get("osv_id") or "?")


def build_markdown(result: dict, scan: dict, repo_slug: str | None) -> str:
    counts = result["counts"]
    lines: list[str] = []
    lines.append(f"<!-- {result['marker']} -->")
    lines.append("")
    if result["needs_triage"]:
        lines.append(
            "GitHub Actions の定期スキャンで、**人間のトリアージが必要な依存脆弱性**を検出しました。"
        )
    else:
        lines.append(
            "GitHub Actions の定期スキャンを実行しました。"
            "**今回、人間のトリアージが必要なものはありません。**"
        )
    lines.append("")
    lines.append(
        "> ⚠️ これは**検知結果であって判定ではありません**。CI 上では Claude が動かないため、"
        "quiet-cve の中核である「そのコードが脆弱な機能を実際に呼んでいるか」の判定"
        "（SKILL.md Step 4）は実行できていません。全件 `usage: unknown` 扱いです。"
    )
    lines.append("")
    lines.append("| | 件数 |")
    lines.append("|---|---|")
    lines.append(f"| {BUCKET_LABEL['act']}（KEV 掲載） | {counts['act']} |")
    lines.append(f"| {BUCKET_LABEL['watch']} | {counts['watch']} |")
    lines.append(f"| {BUCKET_LABEL['untriaged']} | {counts['untriaged']} |")
    lines.append(f"| ⚫ ignore で除外 | {counts['ignored']} |")
    lines.append("")
    lines.append(
        f"スキャン対象: {scan.get('packages_scanned', 0)} パッケージ / "
        f"マニフェスト {len(scan.get('manifests') or [])} 件 / "
        f"KEV カタログ {(scan.get('kev_catalog') or {}).get('entries', 0)} 件"
    )
    lines.append("")

    if result["expired_ignores"]:
        lines.append("### ⏰ 除外期限切れ")
        lines.append("")
        lines.append("`config.yml` の ignore が失効し、再浮上しました。延長するか対応するか決めてください。")
        lines.append("")
        for e in result["expired_ignores"]:
            lines.append(f"- `{e['rule']}` — {e['note']}（当時の理由: {e['reason'] or '記載なし'}）")
        lines.append("")

    for bucket in ("act", "watch"):
        items = [f for f in result["findings"] if f["bucket"] == bucket]
        if not items:
            continue
        lines.append(f"### {BUCKET_LABEL[bucket]}")
        lines.append("")
        lines.append("| CVE | パッケージ | 深刻度 | 修正版 | CI の見立て |")
        lines.append("|---|---|---|---|---|")
        for f in items[:50]:
            finding = f["finding"]
            cvss = finding.get("cvss") or {}
            score = cvss.get("score")
            sev = f"{score} ({cvss.get('label')})" if score is not None else str(cvss.get("label"))
            fixed = ", ".join((finding.get("fixed_versions") or [])[:3]) or "—"
            lines.append(
                f"| {_cve_line(finding)} | `{_pkg_line(finding)}` | {sev} | {fixed} | {f['reason']} |"
            )
        if len(items) > 50:
            lines.append(f"| … | 他 {len(items) - 50} 件（artifact の scan.json を参照） | | | |")
        lines.append("")

    lines.append("### 次にやること")
    lines.append("")
    if result["needs_triage"]:
        lines.append("手元のリポジトリで Claude Code に quiet-cve のトリアージを実行させてください。")
    else:
        lines.append(
            "急ぐものはありません。「未判定」の中身が気になるときだけ、"
            "手元で Claude Code に quiet-cve のトリアージを実行させてください。"
        )
    lines.append("")
    lines.append("```")
    lines.append("quiet-cve でCVEチェックして")
    lines.append("```")
    lines.append("")
    lines.append(
        "実使用判定まで含めた `reports/YYYY-MM-DD.md` が出ます。"
        "対応不要と判断したものは `config.yml` の `ignore` に**理由と期限を付けて**書いてください。"
    )
    lines.append("")
    if repo_slug:
        lines.append(
            f"生の検出結果（`scan.json`）はこの実行の artifact にあります: "
            f"https://github.com/{repo_slug}/actions"
        )
        lines.append("")
    lines.append(f"<sub>quiet-cve / 実行 {result['generated_at']}</sub>")
    return "\n".join(lines)


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="osv_query.py の結果を CI 向けに要約する")
    ap.add_argument("--scan", required=True, help="osv_query.py --out で書いた JSON")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--out", default="-", help="要約 JSON の出力先")
    ap.add_argument("--markdown", default=None, help="Issue 本文用 Markdown の出力先")
    ap.add_argument("--repo", default=None, help="owner/repo（本文のリンク用）")
    ap.add_argument("--today", default=None, help="ignore の期限判定に使う日付（テスト用）")
    args = ap.parse_args()

    scan = json.loads(Path(args.scan).read_text(encoding="utf-8"))
    config = load_config(Path(args.config))
    today = (
        datetime.strptime(args.today, "%Y-%m-%d").date()
        if args.today else datetime.now(timezone.utc).date()
    )

    findings, ignored, expired = apply_ignores(
        list(scan.get("findings") or []), config, today
    )

    classified = []
    for finding in findings:
        bucket, reason = classify(finding, config)
        if finding.get("ignore_expired"):
            reason = f"{reason} / 除外期限切れ"
        classified.append({"bucket": bucket, "reason": reason, "finding": finding})

    counts = {
        "act": sum(1 for f in classified if f["bucket"] == "act"),
        "watch": sum(1 for f in classified if f["bucket"] == "watch"),
        "untriaged": sum(1 for f in classified if f["bucket"] == "untriaged"),
        "ignored": ignored,
    }
    # 通信に失敗した実行を「0 件 = 安全」と誤読させない
    scan_errors = [e for e in (scan.get("errors") or [])
                   if e.get("stage") in ("querybatch", "osv", "kev")]

    # Issue の体裁は config.yml に従う（ワークフロー側に値を散らさない）。
    # ただし dedupe 用の `quiet-cve` ラベルだけは仕組み上必須なので常に付ける。
    labels = [str(l) for l in (cfg_get(config, "notify.github_issue.labels", []) or [])]
    if "quiet-cve" not in labels:
        labels.append("quiet-cve")

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "marker": "quiet-cve-ci-scan",
        "issue": {
            "labels": labels,
            "title_prefix": str(cfg_get(config, "notify.github_issue.title_prefix", "[CVE]")),
            "assignees": [str(a) for a in (cfg_get(config, "notify.github_issue.assignees", []) or [])],
        },
        "counts": counts,
        "needs_triage": counts["act"] + counts["watch"] > 0 or bool(expired),
        "scan_errors": scan_errors,
        "expired_ignores": expired,
        "findings": classified,
    }

    markdown = build_markdown(result, scan, args.repo)
    if args.markdown:
        Path(args.markdown).write_text(markdown + "\n", encoding="utf-8")

    payload = {k: v for k, v in result.items() if k != "findings"}
    payload["findings"] = [
        {
            "bucket": f["bucket"],
            "reason": f["reason"],
            "cve": _cve_line(f["finding"]),
            "package": _pkg_line(f["finding"]),
        }
        for f in classified
    ]
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out == "-":
        sys.stdout.write(text + "\n")
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {out}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
