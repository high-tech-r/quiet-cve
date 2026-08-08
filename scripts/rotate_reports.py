#!/usr/bin/env python3
"""保持期間を過ぎた日次レポートを月次サマリーへ集約し、集約後に削除する。

使い方:
    # 何が起きるかだけ見る（削除しない）
    python3 scripts/rotate_reports.py --dry-run

    # 実行（集約 → 検証 → 削除）
    python3 scripts/rotate_reports.py

集約元は日次レポートの Markdown ではなく logs/triage.jsonl。
ログは追記専用で構造化されているため、Markdown を解析するより確実で、
何度実行しても同じ月次サマリーが再生成される。

削除に関する安全弁:
  - `YYYY-MM-DD.md` / `YYYY-MM-DD-2.md` に厳密一致するファイルだけを対象にする
  - monthly_dir 配下は絶対に削除しない
  - ログに該当日の記録が 1 件も無いレポートは削除しない（根拠が失われるため）
  - 月次サマリーを書き出して読み直せることを確認してから削除する
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_query import cfg_get, load_config  # noqa: E402

# reports/2026-05-08.md と reports/2026-05-08-2.md（同日 2 回目以降）だけを対象にする
import re

REPORT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:-(\d+))?\.md$")
ARCHIVED_MARKER = "<!-- quiet-cve:archived "
VERDICT_LABEL = {
    "act": "🔴 要対応",
    "watch": "🟡 様子見",
    "not_affected": "⚪ 影響なし",
}


# ===========================================================================
# 入力
# ===========================================================================

def read_log(path: Path) -> list[dict]:
    """triage.jsonl を読む。壊れた行は飛ばす（1 行の破損で全体を落とさない）。"""
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def row_date(row: dict) -> str | None:
    """ログ 1 行が属する日付 (YYYY-MM-DD)。"""
    for field in ("run_id", "ts"):
        value = row.get(field)
        if isinstance(value, str) and len(value) >= 10:
            head = value[:10]
            try:
                date.fromisoformat(head)
                return head
            except ValueError:
                continue
    return None


def find_reports(report_dir: Path, monthly_dir: Path) -> list[dict]:
    """日次レポートを列挙する。monthly_dir 配下は最初から除外する。"""
    if not report_dir.exists():
        return []
    monthly_resolved = monthly_dir.resolve()
    out = []
    for entry in sorted(report_dir.iterdir()):
        if not entry.is_file():
            continue
        m = REPORT_RE.match(entry.name)
        if not m:
            continue
        if monthly_resolved in entry.resolve().parents:
            continue
        try:
            day = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            continue  # 2026-13-45.md のような日付にならない名前
        out.append({"path": entry, "name": entry.name, "date": day,
                    "month": f"{day.year:04d}-{day.month:02d}"})
    return out


def read_archived_marker(path: Path) -> list[str]:
    """既存の月次サマリーから、集約済みレポート名の一覧を読み戻す。"""
    if not path.exists():
        return []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(ARCHIVED_MARKER):
            body = line[len(ARCHIVED_MARKER):].rstrip(" -->").strip()
            return [x for x in (n.strip() for n in body.split(",")) if x]
    return []


# ===========================================================================
# 月次サマリーの生成
# ===========================================================================

def summarize_month(month: str, rows: list[dict], archived: list[str],
                    latest_run_id: str | None, retention_days: int,
                    generated_at: str) -> str:
    """その月のログ行から月次サマリーの Markdown を組み立てる。"""
    run_ids = sorted({r.get("run_id") for r in rows if r.get("run_id")})
    days = sorted({d for d in (row_date(r) for r in rows) if d})
    verdicts = collections.Counter(r.get("verdict") for r in rows)
    unique_by_verdict: dict[str, set] = collections.defaultdict(set)
    for r in rows:
        key = r.get("cve") or r.get("osv_id")
        if key:
            unique_by_verdict[r.get("verdict")].add(key)

    lines = [
        f"# 月次サマリー — {month}",
        "",
        f"{ARCHIVED_MARKER}{','.join(archived)} -->",
        "",
        f"> 保持期間 {retention_days} 日を過ぎた日次レポートを集約したものです。",
        "> 個別の判断根拠（evidence / reason）は `logs/triage.jsonl` に全件残っています。",
        "",
        f"- 集約日時: {generated_at}",
    ]
    if days:
        lines.append(f"- 対象期間: {days[0]} 〜 {days[-1]}（{len(days)} 日）")
    lines += [
        f"- 実行回数: {len(run_ids)} 回",
        f"- 判定レコード: {len(rows)} 件",
        f"- 集約した日次レポート: {len(archived)} 件（集約後に削除済み）",
        "",
        "## 判定内訳",
        "",
        "| 判定 | 延べ件数 | ユニーク CVE 数 |",
        "|---|---|---|",
    ]
    for verdict in ("act", "watch", "not_affected"):
        lines.append(f"| {VERDICT_LABEL[verdict]} | {verdicts.get(verdict, 0)} "
                     f"| {len(unique_by_verdict.get(verdict, ()))} |")
    other = sum(c for v, c in verdicts.items() if v not in VERDICT_LABEL)
    if other:
        lines.append(f"| （その他・未分類） | {other} | — |")
    lines.append("")

    # --- 要対応 ---------------------------------------------------------
    acts: dict[str, dict] = {}
    for r in rows:
        if r.get("verdict") != "act":
            continue
        key = (r.get("cve") or r.get("osv_id"), r.get("package"))
        prev = acts.get(key)
        if prev is None or (row_date(r) or "") >= (row_date(prev) or ""):
            acts[key] = r

    lines += [f"## 🔴 この月に要対応となった CVE（{len(acts)} 件）", ""]
    if not acts:
        lines += ["この月、人間の対応が必要と判定されたものはありませんでした。", ""]
    else:
        lines += [
            "| CVE | パッケージ | CVSS | KEV | 最終検出 | 修正版 | 通知 | 現況 |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for (cve, pkg), r in sorted(
            acts.items(), key=lambda kv: -(kv[1].get("cvss") or 0)
        ):
            issue = r.get("issue_url")
            notify = f"[issue]({issue})" if issue else (r.get("action_taken") or "—")
            lines.append(
                f"| {cve or '—'} | {pkg or '—'}@{r.get('installed_version') or '—'} "
                f"| {r.get('cvss') if r.get('cvss') is not None else '—'} "
                f"| {'あり' if r.get('kev') else '—'} | {row_date(r) or '—'} "
                f"| {r.get('fixed_version') or '—'} | {notify} "
                f"| {_status(r, latest_run_id)} |"
            )
        lines.append("")

    # --- 繰り返し様子見のもの -------------------------------------------
    watch_counts = collections.Counter(
        (r.get("cve") or r.get("osv_id"), r.get("package"))
        for r in rows if r.get("verdict") == "watch"
    )
    recurring = [(k, c) for k, c in watch_counts.items() if c >= 3]
    lines += [f"## 🟡 繰り返し様子見になったもの（3 回以上・{len(recurring)} 件）", ""]
    if not recurring:
        lines += ["該当なし。", ""]
    else:
        lines += ["様子見のまま残り続けているものは、判断を先送りしている可能性があります。",
                  "対応するか `ignore` に理由付きで入れるか、決めたほうが健全です。", "",
                  "| CVE | パッケージ | 出現回数 | 直近の判断理由 |", "|---|---|---|---|"]
        for (cve, pkg), count in sorted(recurring, key=lambda kv: -kv[1]):
            last = max(
                (r for r in rows
                 if r.get("verdict") == "watch"
                 and (r.get("cve") or r.get("osv_id")) == cve
                 and r.get("package") == pkg),
                key=lambda r: row_date(r) or "",
            )
            reason = (last.get("reason") or "—").replace("|", "\\|")
            lines.append(f"| {cve or '—'} | {pkg or '—'} | {count} | {reason} |")
        lines.append("")

    # --- KEV ------------------------------------------------------------
    kev_rows = [r for r in rows if r.get("kev")]
    kev_cves = sorted({r.get("cve") or r.get("osv_id") for r in kev_rows if r.get("cve") or r.get("osv_id")})
    lines += [f"## KEV 掲載（{len(kev_cves)} 件）", ""]
    if not kev_cves:
        lines += ["該当なし。", ""]
    else:
        lines += ["| CVE | パッケージ | 判定 |", "|---|---|---|"]
        seen = set()
        for r in sorted(kev_rows, key=lambda r: row_date(r) or "", reverse=True):
            key = (r.get("cve") or r.get("osv_id"), r.get("package"))
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"| {key[0] or '—'} | {key[1] or '—'} "
                         f"| {VERDICT_LABEL.get(r.get('verdict'), r.get('verdict') or '—')} |")
        lines.append("")
        downgraded = [r for r in kev_rows if r.get("verdict") == "not_affected"]
        if downgraded:
            lines += [
                f"> ⚠ KEV 掲載でありながら「影響なし」と判定したものが {len(downgraded)} 件あります。",
                "> 判断が妥当だったか、`logs/triage.jsonl` の evidence を確認することを推奨します。",
                "",
            ]

    # --- 集約元 ----------------------------------------------------------
    lines += ["## 集約した日次レポート", ""]
    if archived:
        for name in archived:
            lines.append(f"- `{name}`（集約後に削除）")
    else:
        lines.append("なし。")
    lines.append("")
    return "\n".join(lines)


def _status(row: dict, latest_run_id: str | None) -> str:
    """要対応だったものが、直近の実行でもまだ検出されているか。"""
    if not latest_run_id:
        return "—"
    if row.get("run_id") == latest_run_id:
        return "直近の実行でも検出"
    return "直近の実行では未検出"


# ===========================================================================
# 本体
# ===========================================================================

def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(
        description="保持期間を過ぎた日次レポートを月次サマリーへ集約して削除する")
    ap.add_argument("--config", default=str(here / "config.yml"))
    ap.add_argument("--dry-run", action="store_true",
                    help="集約対象を表示するだけで、書き込みも削除もしない")
    ap.add_argument("--today", default=None,
                    help="基準日を YYYY-MM-DD で上書きする（テスト用）")
    ap.add_argument("--out", default="-", help="結果 JSON の出力先")
    args = ap.parse_args()

    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    base = config_path.parent

    retention = cfg_get(config, "output.retention_days", 0)
    report_dir = (base / cfg_get(config, "output.report_dir", "reports")).resolve()
    monthly_dir = (base / cfg_get(config, "output.monthly_dir", "reports/monthly")).resolve()
    log_path = (base / cfg_get(config, "output.log_file", "logs/triage.jsonl")).resolve()

    today = date.fromisoformat(args.today) if args.today else datetime.now(timezone.utc).date()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    result = {
        "generated_at": generated_at,
        "today": today.isoformat(),
        "retention_days": retention,
        "dry_run": args.dry_run,
        "archived": [],
        "summaries": [],
        "deleted": [],
        "skipped": [],
        "errors": [],
    }

    if not retention or int(retention) <= 0:
        result["note"] = "retention_days が未設定または 0 のため、レポートは無期限に保持されます。"
        _emit(result, args.out)
        return 0

    retention = int(retention)
    cutoff = today - timedelta(days=retention)
    reports = find_reports(report_dir, monthly_dir)
    expired = [r for r in reports if r["date"] < cutoff]

    result["cutoff"] = cutoff.isoformat()
    result["reports_total"] = len(reports)
    result["reports_expired"] = len(expired)

    if not expired:
        result["note"] = (f"保持期間 {retention} 日を過ぎたレポートはありません"
                          f"（{len(reports)} 件を保持中）。")
        _emit(result, args.out)
        return 0

    rows = read_log(log_path)
    if not log_path.exists():
        result["errors"].append({"stage": "log", "error": f"ログが見つかりません: {log_path}"})
    rows_by_date: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        day = row_date(row)
        if day:
            rows_by_date[day].append(row)

    latest_run_id = None
    run_ids = [r.get("run_id") for r in rows if r.get("run_id")]
    if run_ids:
        latest_run_id = max(run_ids)

    # 該当日のログが 1 件も無いレポートは、削除すると根拠が完全に失われるので残す
    deletable, by_month = [], collections.defaultdict(list)
    for rep in expired:
        if rows_by_date.get(rep["date"].isoformat()):
            deletable.append(rep)
            by_month[rep["month"]].append(rep)
        else:
            result["skipped"].append({
                "file": rep["name"],
                "reason": "logs/triage.jsonl に該当日の記録が無いため削除しない",
            })

    for month in sorted(by_month):
        month_rows = [r for day, rs in rows_by_date.items() if day.startswith(month)
                      for r in rs]
        summary_path = monthly_dir / f"{month}.md"
        already = read_archived_marker(summary_path)
        archived = sorted(set(already) | {r["name"] for r in by_month[month]})
        text = summarize_month(month, month_rows, archived, latest_run_id,
                               retention, generated_at)

        entry = {
            "month": month,
            "summary": str(summary_path.relative_to(base)) if summary_path.is_relative_to(base) else str(summary_path),
            "log_records": len(month_rows),
            "archives": [r["name"] for r in by_month[month]],
        }

        if args.dry_run:
            entry["written"] = False
            result["summaries"].append(entry)
            result["archived"] += entry["archives"]
            continue

        try:
            monthly_dir.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(text, encoding="utf-8")
            # 書き戻せたことを確認してから削除に進む
            verify = summary_path.read_text(encoding="utf-8")
            if verify != text or not read_archived_marker(summary_path):
                raise OSError("月次サマリーの検証に失敗しました")
        except OSError as exc:
            result["errors"].append({"stage": "summary", "month": month, "error": str(exc)})
            for rep in by_month[month]:
                result["skipped"].append({"file": rep["name"],
                                          "reason": f"月次サマリーの書き出しに失敗: {exc}"})
            continue

        entry["written"] = True
        result["summaries"].append(entry)
        result["archived"] += entry["archives"]

        for rep in by_month[month]:
            path = rep["path"].resolve()
            # 二重の安全確認: 対象は report_dir 直下で、かつ monthly_dir 配下ではない
            if path.parent != report_dir or monthly_dir in path.parents:
                result["skipped"].append({"file": rep["name"],
                                          "reason": "想定外のパスのため削除しない"})
                continue
            try:
                path.unlink()
                result["deleted"].append(rep["name"])
            except OSError as exc:
                result["errors"].append({"stage": "delete", "file": rep["name"],
                                         "error": str(exc)})

    _emit(result, args.out)
    return 1 if result["errors"] else 0


def _emit(obj: dict, dest: str):
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if dest == "-":
        sys.stdout.write(text + "\n")
    else:
        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {path}\n")


if __name__ == "__main__":
    sys.exit(main())
