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

Step 3 の ignore 適用は共通モジュール ignore_rules.py で行う（手元トリアージと
同じロジック）。期限切れ・根拠ファイル変更・justification 不正の項目は
抑制されず、種別付きで報告に再浮上する。

使い方:
    python3 scripts/ci_summary.py --scan scan.json --out summary.json --markdown body.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_query import cfg_get, load_config  # noqa: E402
from ignore_rules import (  # noqa: E402
    RESURFACE_LABEL, IgnoreConfigError, apply_ignores, validate_rules,
)

# advisory_label しか無い場合に、ラベルを下限スコアとして読み替える表。
# severity_label() の境界と同じ値にしてある（片方だけ動かさないこと）。
LABEL_FLOOR = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "NONE": 0.0}

BUCKET_LABEL = {
    "act": "🔴 要対応",
    "watch": "🟡 要トリアージ",
    "untriaged": "⚪ 未判定",
}


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
    target = (
        f"スキャン対象: {scan.get('packages_scanned', 0)} パッケージ / "
        f"マニフェスト {len(scan.get('manifests') or [])} 件"
    )
    middleware = scan.get("middleware_products") or []
    if middleware:
        target += f" / ミドルウェア {len(middleware)} 件（{', '.join(middleware[:5])}）"
    target += f" / KEV カタログ {(scan.get('kev_catalog') or {}).get('entries', 0)} 件"
    lines.append(target)
    lines.append("")

    if result["resurfaced"]:
        lines.append("### ⏰ 除外の再浮上")
        lines.append("")
        lines.append("`config.yml` の ignore が効力を失い、再浮上しました。再確認するか、宣言を直してください。")
        lines.append("")
        for e in result["resurfaced"]:
            label = RESURFACE_LABEL.get(e.get("kind"), e.get("kind"))
            lines.append(f"- `{e['rule']}`【{label}】 {e['note']}（当時の理由: {e['reason'] or '記載なし'}）")
        lines.append("")
    if result.get("ignore_warnings"):
        lines.append("### ⚠ ignore 適用時の警告")
        lines.append("")
        for w in result["ignore_warnings"]:
            lines.append(f"- `{w.get('rule', '?')}` — {w.get('error')}")
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
    ap.add_argument("--scan", required=True, nargs="+",
                    help="osv_query.py / nvd_query.py --out で書いた JSON（複数可。findings を統合する）")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--out", default="-", help="要約 JSON の出力先")
    ap.add_argument("--markdown", default=None, help="Issue 本文用 Markdown の出力先")
    ap.add_argument("--repo", default=None, help="owner/repo（本文のリンク用）")
    ap.add_argument("--today", default=None, help="ignore の期限判定に使う日付（テスト用）")
    args = ap.parse_args()

    scans = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.scan]
    config = load_config(Path(args.config))
    try:
        validate_rules(config)
    except IgnoreConfigError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    today = (
        datetime.strptime(args.today, "%Y-%m-%d").date()
        if args.today else datetime.now(timezone.utc).date()
    )

    # 複数スキャン（osv_query + nvd_query）の統合。findings スキーマは共通。
    scan = {
        "packages_scanned": sum(int(s.get("packages_scanned") or 0) for s in scans),
        "manifests": [m for s in scans for m in (s.get("manifests") or [])],
        "middleware_products": [p for s in scans for p in (s.get("products") or [])],
        "kev_catalog": {"entries": max(
            (int((s.get("kev_catalog") or {}).get("entries") or 0) for s in scans),
            default=0)},
        "errors": [e for s in scans for e in (s.get("errors") or [])],
    }
    all_findings = [f for s in scans for f in (s.get("findings") or [])]

    # 根拠ファイルの変更検知に使う git 実行場所（scan 結果が知っている）
    project_root = next(
        (Path(s["project_root"]) for s in scans if s.get("project_root")), None)

    ignore_warnings: list = []
    findings, ignored, resurfaced = apply_ignores(
        all_findings, config, today,
        project_root=project_root, warnings=ignore_warnings)

    classified = []
    for finding in findings:
        bucket, reason = classify(finding, config)
        res = finding.get("ignore_resurfaced")
        if res:
            reason = f"{reason} / {RESURFACE_LABEL.get(res.get('kind'), '再浮上')}"
        classified.append({"bucket": bucket, "reason": reason, "finding": finding})

    counts = {
        "act": sum(1 for f in classified if f["bucket"] == "act"),
        "watch": sum(1 for f in classified if f["bucket"] == "watch"),
        "untriaged": sum(1 for f in classified if f["bucket"] == "untriaged"),
        "ignored": ignored,
    }
    # 通信に失敗した実行を「0 件 = 安全」と誤読させない
    scan_errors = [e for e in (scan.get("errors") or [])
                   if e.get("stage") in ("querybatch", "osv", "kev", "nvd")]

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
        "needs_triage": counts["act"] + counts["watch"] > 0 or bool(resurfaced),
        "scan_errors": scan_errors,
        "resurfaced": resurfaced,
        "ignore_warnings": ignore_warnings,
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
