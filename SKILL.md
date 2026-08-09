---
name: quiet-cve
description: 親プロジェクトの依存関係を OSV.dev で照会し、KEV/CVSS/実コード使用状況でトリアージして「要対応 / 様子見 / 影響なし」に分類し、reports/ にレポート、logs/ に JSON Lines を出力する。CVEチェック、脆弱性スキャン、依存関係の安全確認、セキュリティ監査を求められたときに使う。
---

# quiet-cve

依存関係の CVE を **全部通知しない** ためのフレームワーク。

検知した脆弱性をそのまま人間に流すとアラート疲れを起こし、結果として全部無視される。
このスキルの仕事は「検知」ではなく **「捨てる根拠を作ること」** にある。
KEV 掲載の有無、CVSS、そして **親プロジェクトが実際にその脆弱な機能を使っているか**
をコードを読んで確かめ、本当に人間の時間を使う価値があるものだけを届ける。

判定には必ず **根拠（file:line）** を残す。根拠なしに「影響なし」と書いてはいけない。

---

## 実行手順

### Step 0. 準備

1. `config.yml` を読む。以降のしきい値・除外・通知設定はすべてここが正。
   ユーザーがオプションを口頭で指定した場合のみ、それが config を上書きする。
2. `scan.project_root`（既定 `..`）が親プロジェクトのルート。
3. 実行 ID として UTC の ISO8601 タイムスタンプを 1 つ決め、レポートとログで共有する。

### Step 1. 依存ファイルの検出

```bash
python3 scripts/osv_query.py --detect-only
```

検出されたマニフェストとパッケージ数を確認する。
**0 件だった場合はここで止まり**、ユーザーに「どのファイルを見ればよいか」を聞く。
（`config.yml` の `scan.manifests` に明示指定できることを伝える）

対応形式:

| エコシステム | ロックファイル（優先） | マニフェスト（バージョンは近似） |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock` | `package.json` |
| PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock` | `requirements*.txt` |
| Packagist | `composer.lock` | `composer.json` |

`version_exact: false` のパッケージは、レンジ指定から下限バージョンを推定している。
誤検知・見逃しの両方がありうるので、レポートにその旨を明記する。

### Step 1b. 宣言されていない資産の棚卸し

`scan.include_undeclared_assets` が false ならスキップする。

Step 1 は「宣言された依存」しか見えない。ここではロックファイルに載らないもの
—— SCA ツールの死角 —— を走査する。

| 資産 | 見つけ方 | バージョンの取り出し |
|---|---|---|
| CDN 読み込み | HTML/テンプレート類（`.html` `.php` `.twig` `.blade.php` `.erb` `.ejs` `.jsx` `.tsx` `.vue` 等）を `<script src=` `<link href=` と CDN ドメイン（cdnjs.cloudflare.com / cdn.jsdelivr.net / unpkg.com / ajax.googleapis.com / code.jquery.com 等）で Grep | URL に含まれることが多い（`/jquery/3.4.1/`、`bootstrap@5.1.0`） |
| 手動配置ライブラリ | `js/` `assets/` `static/` `public/` `lib/` 等のファイル名（`jquery-3.4.1.min.js`）と先頭バナーコメント（`/*! jQuery v3.4.1`） | ファイル名またはバナー |
| フォーク・改造版 | 同上。バナーが改変・削除されていることがある | 特定できなければ「不明」のまま |

規則:

1. Grep とファイル先頭の確認（バナーは先頭 5 行まで）だけで済ませる。中身は深読みしない。
   開くファイルは 50 件まで。超えたら「n 件中 m 件のみ確認」とレポートに書く。
2. `exclude_paths` は原則尊重する。ただしこの棚卸しに限り、`vendor` 等に
   パッケージマネージャ管理外のファイルが直接コミットされていないかの
   **ファイル名の確認**までは行ってよい。
3. `ecosystem:name@version` まで特定できたものは Step 2 で追加照会する。
   検出元（`index.html:12` など）を控えておき、レポートに書く。
4. バージョンが特定できなかった資産は、**照会せずに黙って落とすのではなく**、
   レポートの「宣言されていない資産」表に「特定できず・手動確認を推奨」で載せる。
   unknown を unused に丸めないのと同じ原則。
5. Apache / nginx / OpenSSL / PHP 本体などのミドルウェア・実行環境は
   この棚卸しの対象外。**Step 1c で扱う。**

### Step 1c. ミドルウェア・実行環境の照合（NVD CPE）

`scan.middleware` に宣言があれば照会する:

```bash
python3 scripts/nvd_query.py --out .cache/scan-middleware.json
```

- findings は osv_query.py と同じスキーマで出るので、Step 3 以降で他と同様に扱う。
- **宣言が空のとき**: まず候補を機械的に集める:

  ```bash
  python3 scripts/nvd_query.py --suggest
  ```

  Dockerfile の FROM / docker-compose の image / `.nvmrc` `.tool-versions` /
  package.json の engines / composer.json の require.php を走査し、
  根拠（file:line）付きの候補が出る。候補があればユーザーに提示し、
  **サーバでの実測**（`nginx -v; php -v | head -1; openssl version` を本番で、
  コンテナなら `docker compose exec` で中から実行）と `scan.middleware` への宣言を促す。
  config を勝手に書き換えない。候補も無ければ何もしない。
- コンテナのタグ（`php:8.1` 等）はパッチ版を固定しない（pull した日で変わる）。
  タグから読めた版をそのまま「実環境の版」として扱わないこと。
- パッチ版が不明な宣言（`version: "8.1"`）は下限（8.1.0）で照会される。
  多めに出る方向なので照会してよいが、レポートに「バージョン不正確」を明記する
  （`version_exact: false` と errors の `input_note` に出る）。
- NVD には解析遅延（新しい CVE への CPE 付与の遅れ）がある。結果が 0 件でも
  「脆弱性なし」と書かず、「宣言されたミドルウェアについて NVD 照会で該当なし」と書く。
- ミドルウェアの実使用判定（Step 4）はコードの grep ではなく、**設定ファイルと用途**で
  行う。例:「nginx の HTTP/2 の脆弱性 → `nginx.conf` に `http2` があるか」
  「PHP CGI の脆弱性 → CGI/FastCGI 構成か、対象 OS か」。判断できなければ unknown。
- 対応製品は `--list-products` で一覧できる。無い製品は CPE_TABLE に追記できる。

### Step 2. OSV.dev への照会

```bash
python3 scripts/osv_query.py --out .cache/scan.json
```

Step 1b で特定できた資産があれば、追加で照会して両方の findings を対象にする:

```bash
python3 scripts/osv_query.py --packages npm:jquery@3.4.1 npm:bootstrap@4.3.1 \
  --out .cache/scan-undeclared.json
```

- ネットワークが使えない場合は `--offline`（キャッシュのみ）。結果が空でも
  「脆弱性なし」と書いてはいけない。`errors` を見て「未照会」と明記する。
- 終了コード 2 は「通信に失敗した項目がある」の意味。`errors` を必ずレポートに載せる。

出力 JSON の 1 件（finding）が持つもの:

- `osv_id` / `cve_ids` / `aliases`
- `package`: `name`, `ecosystem`, `version`, `direct`（直接依存か）, `dev`, `version_exact`
- `cvss`: `score`, `label`, `vector`, `source`
  （`source: advisory_label` はスコア無しでラベルのみ。`unavailable` は深刻度不明）
- `kev`: `listed`, `date_added`, `due_date`, `ransomware`, `required_action`
- `fixed_versions`: 修正済みバージョン
- `affected_symbols`: OSV が持っていれば影響を受ける関数名（多くの場合は空）
- `search_hints`: `module_candidates` と `grep_patterns` — Step 4 の grep に使う
- `references`: アドバイザリ URL

### Step 3. 除外の適用

`config.yml` の `ignore` を適用する。ただし **黙って消さない**。

- `ignore.cves[].expires` が実行日より前なら、除外は **失効**。
  通常のトリアージ対象に戻し、レポートに「⚠ 除外期限切れ」と明示する。
- 有効な除外はレポート末尾の「設定により除外」に理由付きで一覧化する。
- ログには `config_ignored: true` で記録する（後で「無視した件数」を集計するため）。

### Step 4. コード実使用状況の判定 ★ここが本フレームワークの中核

`triage.code_usage_check` が false ならスキップし、全件 `usage: "unknown"` とする。

各 finding について、以下を **この順で** 調べる。上位で決着したら下位は省略してよい。

1. **依存の種別を見る**
   `package.direct` が false（推移的依存）なら、親プロジェクトのコードが直接呼ぶとは限らない。
   `config.yml` の `triage.transitive_policy` が `downgrade` の場合、
   実使用が確認できないかぎり「要対応」に上げない。

2. **脆弱な箇所を特定する**
   `summary` / `details` / `references` のアドバイザリを読み、
   **どの関数・オプション・エンドポイントが問題なのか** を先に言語化する。
   例:「`lodash.merge` にプロトタイプ汚染」「YAML の `Loader` 未指定時のみ」
   「管理画面のファイルアップロード経路のみ」。
   ここを飛ばして「パッケージ名で grep して有無だけ見る」のは**やってはいけない**。
   それでは Dependabot と同じになる。

3. **インポートの実在を確認する**
   `search_hints.grep_patterns` を Grep で当てる。`config.yml` の `exclude_paths` は除外する。
   ヒット 0 件なら「そのパッケージ自体を親コードから直接使っていない」。

4. **脆弱な機能の使用を確認する**
   3 でヒットしたファイルを読み、2 で特定した関数・オプションが実際に使われているかを見る。
   読むファイル数は `triage.max_files_per_package` を上限とする。
   打ち切った場合は「n 件中 m 件のみ確認」とレポートに書く。

5. **到達可能性を見る**
   テストコード専用か、本番の実行経路に乗るか、`dev` 依存のみか。
   ただし `dev` 依存でも CI で秘密情報に触れる経路は「影響なし」にしない。

判定結果は次の 3 値:

| usage | 意味 | 必要な根拠 |
|---|---|---|
| `used` | 脆弱な機能を使っている | 該当箇所の `file:line` を 1 つ以上 |
| `unused` | 使っていない | `min_evidence_for_not_affected`（既定 2）以上の根拠 |
| `unknown` | 判断できなかった | 何が確認できなかったかを書く |

**迷ったら `unknown`。`unknown` は `unused` ではない。**
確認コストが高い、動的ロードで追えない、生成コードで読めない ——
こうしたときに `unused` と書くのは誤った安心を配ることになる。

### Step 5. 分類

`config.yml` の `thresholds` を適用して 3 分類する。上から順に評価し、最初に当たったものを採用する。

| # | 条件 | 判定 |
|---|---|---|
| 1 | `kev.listed` かつ `kev_always_act: true` | **要対応** (`act`) |
| 2 | `usage: used` かつ CVSS ≥ `act_cvss` | **要対応** (`act`) |
| 3 | `usage: used` かつ CVSS ≥ `watch_cvss` | 様子見 (`watch`) |
| 4 | `usage: unknown` かつ CVSS ≥ `act_cvss` | 様子見 (`watch`) |
| 5 | `usage: unused` かつ根拠が規定数を満たす | 影響なし (`not_affected`) |
| 6 | CVSS 不明 (`label: UNKNOWN`) | `thresholds.unknown_severity` に従う（既定 `watch`） |
| 7 | 上記以外 | 影響なし (`not_affected`) |

補足規則:

- KEV 掲載かつ `usage: unused` でも、**要対応から様子見への引き下げは可**（根拠が揃っている場合のみ）。
  ただしレポートに「KEV 掲載だが未使用と判断」と目立つ形で書き、引き下げた理由を明記する。
- `version_exact: false`（レンジからの推定）の finding は 1 段階引き下げない。
  誤ったバージョン推定で見逃すより、余分に報告するほうが安全。
- 同じ CVE が複数パッケージ・複数マニフェストで出た場合は 1 件にまとめ、
  影響を受ける箇所を列挙する。

### Step 6. レポート生成

`config.yml` の `output.report_dir` に `YYYY-MM-DD.md` で書く。
同日に既にファイルがあり `overwrite_same_day: false` なら `YYYY-MM-DD-2.md` と連番にする。

テンプレート:

````markdown
# CVE スキャン結果 — {YYYY-MM-DD}

- 実行日時: {ISO8601 UTC}
- 対象: `{project_root}`
- 依存ファイル: {rel_path をカンマ区切り}
- スキャンしたパッケージ: {n} 件（npm {a} / PyPI {b} / Packagist {c}）
- KEV カタログ: {読み込み済み {n} 件 | 未取得}

| 分類 | 件数 |
|---|---|
| 🔴 要対応 | {n} |
| 🟡 様子見 | {n} |
| ⚪ 影響なし | {n} |
| ⚫ 設定により除外 | {n} |

{要対応が 0 件なら「今回、人間の対応が必要なものはありません。」と明記する}

---

## 🔴 要対応

### {CVE-ID} — {package}@{version}

| | |
|---|---|
| 深刻度 | CVSS {score} ({label}) |
| KEV | 掲載あり（{date_added} 追加 / 対応期限 {due_date}） |
| 依存 | 直接依存 / 推移的依存 |
| 修正版 | {fixed_versions} |

**何が起きるか**: {脆弱性の内容を 1〜2 文で。CVE 説明の丸写しではなく、
このプロジェクトにとって何が起きるかに翻訳する}

**このプロジェクトでの使用状況**: {used/unused/unknown とその中身}

**判断の根拠**:
- `src/api/upload.js:42` — 脆弱な `parseForm()` を外部リクエスト経路で呼んでいる
- `src/api/upload.js:11` — `require('multer')`

**推奨アクション**: {具体的に。「アップグレードしてください」ではなく
`npm install multer@1.4.5-lts.1` のようにコマンドまで書く}

**参考**: {references の URL}

---

## 🟡 様子見

{同じ形式。ただし簡潔に。なぜ「要対応」にしなかったのかを必ず書く}

---

## ⚪ 影響なし

<details>
<summary>{n} 件（クリックで展開）</summary>

| CVE | パッケージ | CVSS | 影響なしと判断した理由 |
|---|---|---|---|
| CVE-... | lodash@4.17.20 | 7.4 | `merge`/`mergeWith` を使用箇所なし（grep 0 件・直接依存だが呼び出し無し） |

</details>

---

## ⚫ 設定により除外

| CVE | 理由 | 期限 |
|---|---|---|
| CVE-... | ... | 2026-12-31 |

---

## 🔍 宣言されていない資産

{Step 1b で見つかった場合のみ書く。走査して何も無ければ「なし」と 1 行}

| 資産 | 検出元 | バージョン | 扱い |
|---|---|---|---|
| jquery（CDN） | `index.html:12` | 3.4.1 | 照会済み。CVE は上の分類に含まれる |
| slick-carousel（改造版） | `public/js/slick.custom.js:1` | 特定できず | 未照会。手動確認を推奨 |

---

## 実行時の注意

{errors が空でなければここに列挙する。空なら「なし」}
{version_exact: false のパッケージがあればここで明示する}
````

**レポートの書き方の原則**

- 「判断理由つき」がこのレポートの価値。結論だけ書いたレポートは Dependabot に劣る。
- CVE の説明文をそのまま貼らない。このプロジェクトにとっての意味に翻訳する。
- 確認できなかったことは、確認できなかったと書く。

### Step 7. ログ記録

`config.yml` の `output.log_file`（既定 `logs/triage.jsonl`）に **追記**する。
1 finding = 1 行。既存行は絶対に書き換えない。

```json
{"ts":"2026-08-07T09:00:00Z","run_id":"2026-08-07T09:00:00Z","osv_id":"GHSA-xxxx","cve":"CVE-2024-12345","package":"multer","ecosystem":"npm","installed_version":"1.4.4","fixed_version":"1.4.5-lts.1","direct":true,"dev":false,"cvss":7.5,"severity":"HIGH","kev":true,"usage":"used","verdict":"act","reason":"アップロードAPIで脆弱な parseForm を使用","evidence":["src/api/upload.js:42"],"config_ignored":false,"action_taken":"issue_created","issue_url":"https://github.com/your-org/your-project/issues/12"}
```

フィールドは固定。値が無い場合は `null` を入れ、キー自体は省略しない
（後で `jq` で集計するため）。`verdict` は `act` / `watch` / `not_affected` の 3 値。
`action_taken` は `issue_created` / `none` / `ignored` / `skipped_by_config`。

集計例をユーザーに示すとよい（`jq` が無ければ Python を使う）:

```bash
# 判定の内訳
jq -r .verdict logs/triage.jsonl | sort | uniq -c
# 直近の実行で要対応だったもの
jq -r 'select(.verdict=="act") | "\(.cve) \(.package)"' logs/triage.jsonl | tail -20
```

```bash
python3 -c "
import json,collections
rows=[json.loads(l) for l in open('logs/triage.jsonl',encoding='utf-8')]
print(dict(collections.Counter(r['verdict'] for r in rows)))
"
```

### Step 8. 通知（GitHub Issue）

以下を **すべて** 満たすときだけ起票する:

1. 要対応が 1 件以上ある
2. `notify.github_issue.enabled: true`
3. `gh auth status` が通る（通らなければレポートにその旨を書いて終了）

手順:

1. `notify.github_issue.dedupe` が true なら、既存 issue を確認する。
   ```bash
   gh issue list --state open --search "CVE-2024-12345 in:title" --json number,url
   ```
   ヒットしたら起票せず、ログの `action_taken` は `none`、`issue_url` に既存 URL を入れる。
2. `require_confirmation: true` なら、起票する内容（タイトル一覧）を提示して
   ユーザーの承認を得る。**承認なしに起票しない**。
3. 起票する。
   ```bash
   gh issue create \
     --title "[CVE] CVE-2024-12345: multer@1.4.4 (CVSS 7.5, KEV)" \
     --body-file <本文ファイル> \
     --label security --label cve
   ```
   本文はレポートの該当セクションをそのまま使い、末尾にレポートへのリンクを付ける。
4. `granularity: one_per_run` なら、要対応をまとめた issue を 1 件だけ作る。
5. 起票結果を Step 7 のログに反映する（`action_taken`, `issue_url`）。

### Step 9. 古いレポートの集約と削除

**実行の最後に必ず行う。** 通知の有無にかかわらず、要対応が 0 件でも実行する。

`config.yml` の `output.retention_days` を過ぎた日次レポートを月次サマリーに集約し、
集約後に削除する。日次レポートが際限なく溜まると、
そもそもレポートを見に行かなくなる —— これもアラート疲れの一形態。

```bash
python3 scripts/rotate_reports.py
```

判断が必要な処理は無い。**このスクリプトの出力をそのまま信用してよいし、
自分でファイルを消してはいけない。** 削除はスクリプトの安全弁を通す。

- `retention_days` が 0 または未設定なら何もしない（無期限保持）
- 集約元は日次レポートの Markdown ではなく `logs/triage.jsonl`。
  ログは追記専用なので、何度実行しても同じ月次サマリーが再生成される
- 月次サマリーは `reports/monthly/YYYY-MM.md`。ここは削除対象にならない

安全弁（スクリプト側で実装済み。ユーザーに聞かれたら説明できるように）:

1. `YYYY-MM-DD.md` / `YYYY-MM-DD-2.md` に厳密一致するファイルだけを削除対象にする
2. **ログに該当日の記録が 1 件も無いレポートは削除しない**。
   根拠が完全に失われるため。この場合 `skipped` に理由付きで出る
3. 月次サマリーを書き出し、読み直せることを確認してから削除する。
   書き出しに失敗したら 1 件も削除しない
4. `monthly_dir` 配下は絶対に削除しない

出力 JSON を読み、以下をユーザーに報告する:

- `deleted` が空でなければ「N 件の日次レポートを `reports/monthly/YYYY-MM.md` に集約して削除した」
- `skipped` が空でなければ、**必ずファイル名と理由を伝える**。
  黙って残すとユーザーは集約済みだと思い込む
- `errors` が空でなければそのまま提示する

事前に何が起きるか確認したい場合は `--dry-run` を付ける。
ユーザーが「消さないで確認だけしたい」と言った場合はこちらを使う。

---

## やってはいけないこと

- **根拠なしに「影響なし」と書く。** これが唯一の致命的な失敗。
  このフレームワークが信用を失うと、以後すべてのレポートが無視される。
- **パッケージ名を grep しただけで使用状況を判定する。** 脆弱な「機能」を特定してから調べる。
- **OSV への照会に失敗したのに「脆弱性なし」と報告する。** 未照会と 0 件は違う。
- **しきい値を自分の判断で緩める。** 変更が必要なら config.yml の修正をユーザーに提案する。
- **既存のログ行を書き換える。** ログは追記専用。
- **承認なしに GitHub Issue を起票する。**（`require_confirmation: false` の場合を除く）
- **親プロジェクトのファイルを勝手に書き換える。** 依存の更新は提案までにとどめ、実行は指示を待つ。
- **レポートやログを手作業で削除する。** 古いレポートの整理は Step 9 のスクリプトに任せる。
  `logs/triage.jsonl` と `reports/monthly/` は削除対象ではない（全履歴の保管場所）。

## 出力先まとめ

| 用途 | パス | 保持 |
|---|---|---|
| 人間が読む日次レポート | `reports/YYYY-MM-DD.md` | `retention_days` 日 |
| 集約後の月次サマリー | `reports/monthly/YYYY-MM.md` | 無期限 |
| 機械が集計するログ | `logs/triage.jsonl` | 無期限・追記専用 |
| OSV/KEV のキャッシュ・生 JSON | `.cache/` | 一時（コミット不要） |
