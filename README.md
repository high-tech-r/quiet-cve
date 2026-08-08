# quiet-cve

**アラート疲れを起こさない CVE トリアージ。** 既存プロジェクトにこのディレクトリを丸ごと置いて、
Claude Code に読ませるだけで CVE 対応が回るようになる。

```
your-project/
├── src/
├── package.json
└── quiet-cve/      ← これを置くだけ
```

```
Claude Code に: 「quiet-cve で CVE チェックして」
```

---

## なにが違うのか

Dependabot は **検知** の道具で、これは **取捨選択** の道具。

依存関係の CVE を全部通知すると、人は 3 週間で全部無視するようになる。
本当の問題は「脆弱性が見つからないこと」ではなく「見つかりすぎて重要なものが埋もれること」。

quiet-cve は検知した CVE をそのまま流さない。3 つの軸で絞り込む。

| 軸 | 内容 |
|---|---|
| **KEV** | CISA の「実際に悪用が確認された脆弱性」カタログに載っているか |
| **CVSS** | 深刻度スコア（v3 ベクタから正確に計算） |
| **実コード使用状況** | ★ **このプロジェクトが本当にその脆弱な機能を呼んでいるか** |

3 つ目が中核。Claude が親プロジェクトのコードを実際に読み、
アドバイザリから「どの関数・オプションが危険なのか」を特定したうえで、
その呼び出しが実行経路に存在するかを確かめる。

結果は **要対応 / 様子見 / 影響なし** の 3 分類。
そして **判定にはすべて `file:line` の根拠が付く**。
「影響なし」を根拠なしに書かないことが、このツールの設計上いちばん重要な制約。

### 実際の削減率

テストプロジェクト（16 パッケージ）での実測:

| 段階 | 件数 |
|---|---|
| OSV.dev の生の応答 | 151 |
| 重複統合後（GHSA と PYSEC の同一 CVE をまとめる） | 89 |
| **人間に届いた「要対応」** | **2** |

拾ったのは `yaml.load(request.data)` による任意コード実行（CVSS 9.8）。
捨てたのは lodash CVSS 8.1（脆弱なのは `_.template` だが使っているのは `_.merge` だけ）や
minimist CVSS 9.8（推移的依存で CLI 引数解析コードが存在しない）など。
判断を保留したものも含めて、**すべての根拠がレポートに残る**。

→ [出力サンプルを見る](examples/sample-report.md)

---

## 導入

```bash
cd your-project
git clone --depth 1 https://github.com/high-tech-r/quiet-cve.git
rm -rf quiet-cve/.git   # 親リポジトリに .git が入れ子になるのを避ける
```

以上。Python 3.11+ があれば追加インストールは不要（標準ライブラリのみで動く）。
API キーも不要（OSV.dev は認証不要）。

`config.yml` を自分用に書き換えて親リポジトリごとコミットするのが想定した使い方なので、
`.git` は消してしまってよい。更新を追いたい場合は代わりに submodule にする。

**Claude Code のスキルとして常時認識させたい場合**（任意）:

```bash
mkdir -p .claude/skills
ln -s ../../quiet-cve .claude/skills/quiet-cve
```

シンボリックリンクを張らなくても、「quiet-cve の SKILL.md を読んで実行して」と
言えば動く。

### 動作要件

| | |
|---|---|
| Python | 3.11 以上（`tomllib` を使うため。3.8+ でもフォールバックで動く） |
| PyYAML | 任意。無い場合は同梱の簡易 YAML パーサを使う |
| gh CLI | GitHub Issue 起票を有効にする場合のみ |
| ネットワーク | `api.osv.dev` と `www.cisa.gov` への HTTPS |

---

## 対応エコシステム

| エコシステム | ロックファイル（推奨） | マニフェスト |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock` | `package.json` |
| PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock` | `requirements*.txt` |
| Composer | `composer.lock` | `composer.json` |

ロックファイルがあるとバージョンが正確に取れるため、検出精度が上がる。
マニフェストのみの場合はレンジ指定から下限バージョンを推定し、
レポートにその旨が明記される。

（`pnpm-lock.yaml` は未対応。この場合 `package.json` のレンジから下限バージョンを
推定して読む。正確なバージョンで見たいなら `npm install --package-lock-only` で
`package-lock.json` を作れば使われるが、pnpm が実際に入れたバージョンとは
ずれうる点に注意）

---

## 使い方

### 基本

Claude Code に頼むだけ。

```
quiet-cve で CVE チェックして
```

Claude が SKILL.md の手順に従って、依存検出 → OSV 照会 → トリアージ →
`reports/YYYY-MM-DD.md` 生成 → `logs/triage.jsonl` 追記 →
古いレポートの月次集約 まで実行する。

### スクリプト単体で使う

```bash
# 依存ファイルの検出結果だけ確認
python3 scripts/osv_query.py --detect-only

# スキャン実行（JSON を標準出力へ）
python3 scripts/osv_query.py

# ファイルに保存
python3 scripts/osv_query.py --out .cache/scan.json

# 依存を直接指定（プロジェクト検出を使わない）
python3 scripts/osv_query.py --packages npm:lodash@4.17.20 PyPI:requests@2.19.1

# キャッシュのみ・ネットワーク不使用
python3 scripts/osv_query.py --offline
```

古いレポートの集約だけを単体で回すこともできる。

```bash
# 何が集約・削除されるか確認するだけ（削除しない）
python3 scripts/rotate_reports.py --dry-run

# 実行
python3 scripts/rotate_reports.py
```

終了コード `2` は「通信に失敗した項目がある」の意味。
結果が空でも「脆弱性なし」を意味しないので、`errors` フィールドを必ず見ること。

### GitHub Actions で定期実行する

`examples/github-actions/quiet-cve-scan.yml` を `.github/workflows/quiet-cve.yml`
にコピーすれば、毎週の定期スキャンが回る。Settings > Actions > General >
Workflow permissions を **Read and write permissions** にしておくこと（Issue 起票に必要）。

**CI は検知しかしない。** Claude が動かないので、このフレームワークの中核である
コード実使用判定（SKILL.md Step 4）が実行できないからだ。ワークフローがやるのは

1. `osv_query.py` で OSV / KEV に照会する
2. `ci_summary.py` で `config.yml` の `ignore` としきい値を適用し、件数を出す
3. トリアージすべきものがあれば Issue を 1 本立てる（既にあれば本文を差し替える）
4. 生の `scan.json` を artifact に残す
5. 終了コード `2`（通信失敗）ならジョブを失敗させる ← 0 件を「安全」と誤読させないため

までで、`reports/` `logs/` はコミットしない。`usage: unknown` だけのレコードを
追記専用ログに積むと月次集約の質が落ちるので、記録は手元のトリアージ実行に一本化してある。

CI 側の分類は SKILL.md Step 5 の表を `usage: unknown` に固定したものになる。

| CI の分類 | 条件 |
|---|---|
| 🔴 要対応 | KEV 掲載（`kev_always_act`） |
| 🟡 要トリアージ | CVSS ≥ `act_cvss`、または深刻度不明（`unknown_severity`） |
| ⚪ 未判定 | それ以外 |

**`影響なし` は CI からは絶対に出ない。** 根拠なしに安心を配らないという原則を
CI 側でも守るため、上位ルールに当たらなかったものは「未判定」に置く。

Issue は 1 本を使い回す（本文の `<!-- quiet-cve-ci-scan -->` で同定する）。
本文は毎回黙って差し替え、通知が飛ぶコメントを付けるのは KEV 掲載があるときだけ。
溜まらないこと自体がアラート疲れ対策になっている。

```bash
# 手元で CI と同じ要約を再現する
python3 scripts/osv_query.py --out scan.json
python3 scripts/ci_summary.py --scan scan.json --markdown issue-body.md
```

---

## 設定

すべて `config.yml` にある。よく触るのはこのあたり。

```yaml
thresholds:
  act_cvss: 7.0          # 実使用が確認できて、これ以上なら「要対応」
  watch_cvss: 4.0        # これ未満は「様子見」にも上げない
  kev_always_act: true   # KEV 掲載なら CVSS を問わず要対応

triage:
  code_usage_check: true              # ← false にすると Dependabot 相当になる
  min_evidence_for_not_affected: 2    # 「影響なし」に必要な根拠の数
  transitive_policy: downgrade        # 推移的依存は実使用が確認できるまで上げない

notify:
  github_issue:
    enabled: false       # まず false で運用を確認してから on にする

output:
  retention_days: 90     # 日次レポートの保持日数。0 で無期限保持
```

**CVE を無視する場合は、しきい値を下げずに `ignore` に理由と期限を書く。**

```yaml
ignore:
  cves:
    - id: CVE-2024-12345
      reason: "該当機能(XMLパーサ)を使っていない。2026-01-15 に手動確認済み"
      expires: "2026-12-31"   # 日付は必ず引用符で囲む
```

期限を過ぎた除外は自動的に失効し、「⚠ 除外期限切れ」としてレポートに再浮上する。
無期限の握りつぶしを作らないための仕組み。

---

## 出力

### `reports/YYYY-MM-DD.md`

人間が読むレポート。要対応・様子見・影響なしの 3 分類で、
各項目に「何が起きるか」「このプロジェクトでの使用状況」「判断の根拠」「推奨アクション」が付く。
影響なしは `<details>` で折りたたまれる。

### `reports/monthly/YYYY-MM.md`

`retention_days`（既定 90 日）を過ぎた日次レポートは、月次サマリーに集約されてから削除される。
日次レポートが際限なく溜まると、結局誰も見に行かなくなるため。

サマリーには「その月に要対応となった CVE 一覧（通知先の issue リンク付き）」
「3 回以上繰り返し様子見になったもの」「KEV 掲載なのに影響なしと判定したもの（要レビュー）」
が残る。集約元は Markdown ではなく `logs/triage.jsonl` なので、何度実行しても同じ結果になる。

削除しても問題ない理由は、**判断根拠を含む全レコードが `logs/triage.jsonl` に残り続ける**から。
日次レポートはあくまで人間向けの表示物にすぎない。

安全弁として、**ログに該当日の記録が無いレポートは削除されない**（根拠が完全に失われるため）。
月次サマリーの書き出しに失敗した場合も 1 件も削除しない。

```bash
python3 scripts/rotate_reports.py --dry-run   # 何が消えるか先に確認
```

### `logs/triage.jsonl`

1 判定 = 1 行の JSON Lines。追記専用。

```bash
# 判定の内訳
jq -r .verdict logs/triage.jsonl | sort | uniq -c
#    2 act
#    4 not_affected
#    3 watch

# 要対応だったものの一覧
jq -r 'select(.verdict=="act") | "\(.cve) \(.package)@\(.installed_version)"' logs/triage.jsonl

# KEV 掲載なのに影響なしと判断したもの（レビュー対象）
jq -r 'select(.kev and .verdict=="not_affected")' logs/triage.jsonl
```

`jq` が無い環境では Python で同じことができる。

```bash
python3 -c "
import json,collections
rows=[json.loads(l) for l in open('logs/triage.jsonl',encoding='utf-8')]
print(dict(collections.Counter(r['verdict'] for r in rows)))
"
```

### `osv_query.py` の出力

```jsonc
{
  "schema_version": 1,
  "generated_at": "2026-08-07T09:00:00+00:00",
  "project_root": "/path/to/your-project",
  "manifests": [{"rel_path": "package-lock.json", "ecosystem": "npm", "file": "..."}],
  "packages_scanned": 412,
  "packages_by_ecosystem": {"npm": 380, "PyPI": 32},
  "kev_catalog": {"loaded": true, "entries": 1284},
  "findings_count": 7,
  "findings": [
    {
      "osv_id": "GHSA-xxxx-yyyy-zzzz",
      "cve_ids": ["CVE-2024-12345"],
      "package": {
        "name": "multer", "ecosystem": "npm", "version": "1.4.4",
        "direct": true, "dev": false, "version_exact": true,
        "manifests": ["package-lock.json"]
      },
      "summary": "...",
      "cvss": {"score": 7.5, "label": "HIGH", "vector": "CVSS:3.1/AV:N/...", "source": "computed_from_vector"},
      "kev": {"listed": true, "date_added": "2024-06-01", "due_date": "2024-06-22", "ransomware": "Unknown"},
      "fixed_versions": ["1.4.5-lts.1"],
      "affected_symbols": [],
      "search_hints": {
        "module_candidates": ["multer"],
        "grep_patterns": ["require\\(['\"]multer", "from ['\"]multer"]
      },
      "references": ["https://github.com/..."]
    }
  ],
  "errors": []
}
```

`cvss.source` の意味:

| 値 | 意味 |
|---|---|
| `computed_from_vector` | CVSS v3 ベクタから計算した正確なスコア |
| `advisory_label` | v3 ベクタが無く、アドバイザリの深刻度ラベルのみ（`score` は `null`） |
| `unavailable` | 深刻度情報なし。`thresholds.unknown_severity` の扱いになる |

---

## 設計思想

**1. 捨てる根拠を作ることが仕事**

検知は簡単で、無視の判断が難しい。このツールの価値は
「なぜこの CVE を今日対応しなくてよいのか」を根拠付きで残すところにある。

**2. 不明を未使用に丸めない**

判定は `used` / `unused` / `unknown` の 3 値。動的ロードで追えない、
生成コードで読めない —— そういうときは `unknown` にして「様子見」に落とす。
`unused` と書けるのは根拠が 2 つ以上揃ったときだけ。
誤った安心を配るくらいなら、余分に報告するほうがいい。

**3. 握りつぶしに期限を付ける**

`ignore` には `expires` が必須。期限が切れれば自動的に再浮上する。
「一度無視したものが永久に見えなくなる」状態を作らない。

**4. 決定は設定ファイルに、判断はモデルに**

しきい値・除外・通知は `config.yml` に固定する（再現性のため）。
「このコードはこの脆弱な関数を呼んでいるか」という判断だけをモデルに任せる。
モデルがしきい値を勝手に緩めることは SKILL.md で禁じている。

**5. 追記専用のログ**

`logs/triage.jsonl` は書き換えない。判定が時間とともにどう変わったか
（`unknown` が `used` になった、など）を追えることが、運用の改善につながる。

だからこそ日次レポートは捨てられる。表示物（`reports/`）は期限を切って月次に畳み、
記録（`logs/`）だけが無期限に残る。溜まる一方のレポートは読まれなくなるので、
畳むこと自体がアラート疲れ対策の一部になっている。

---

## ロードマップ

- [x] npm / PyPI / Composer 対応
- [x] KEV + CVSS + 実コード使用状況によるトリアージ
- [x] Markdown レポート / JSON Lines ログ
- [x] GitHub Issue 起票
- [x] GitHub Actions での定期実行（cron）
- [ ] pnpm / Go modules / RubyGems / Cargo 対応
- [ ] EPSS（悪用可能性スコア）の取り込み
- [ ] 前回実行との差分レポート（新規 CVE のみ通知）

---

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
