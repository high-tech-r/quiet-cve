# quiet-cve

**依存関係の CVE を「本当に対応が必要なものだけ」に絞り込む、Claude Code 用のツールです。**

npm / PyPI / Composer のロックファイルを読んで [OSV.dev](https://osv.dev) に問い合わせ、
見つかった脆弱性ひとつひとつについて **Claude があなたのコードを実際に読み**、
「その脆弱な機能を本当に呼んでいるか」を確かめたうえで、
**要対応 / 様子見 / 影響なし** に仕分けした Markdown のレポートを出します。

判定にはすべて `file:line` の根拠が付きます。

インストールは git clone だけ。実行は、プロジェクトで Claude Code にこう頼むだけです。

```
quiet-cve で CVE チェックして
```

Python 3.11+ があれば追加の依存はありません（標準ライブラリのみ）。
API キーも不要です（OSV.dev は認証不要）。

Dependabot の置き換えではありません。Dependabot が **検知** を、quiet-cve が
**取捨選択** を担当する [併用を推奨します](#dependabot-との違い)。
Dependabot を使えない環境向けには、
[週次スキャンの GitHub Actions テンプレート](#github-actions-で定期実行するdependabot-が使えない環境向け)も同梱しています。

AI によって脆弱性の公表から悪用までの時間が縮み続ける時代に、
防御側の「対応するかどうかの判断」を同じ速度へ引き上げることを狙ったツールです
（→ [設計思想](#設計思想)）。

---

## 動かすとこうなります

同梱のテストプロジェクト（16 パッケージ）での実測値です。

| 段階 | 件数 |
|---|---|
| OSV.dev が返した脆弱性 | 151 |
| 重複を統合したあと（GHSA と PYSEC の同じ CVE をまとめる） | 89 |

この 89 件をコードを読んで仕分けすると、こうなります。

| 分類 | 件数 |
|---|---|
| 🔴 要対応 | **2** |
| 🟡 様子見 | 42 |
| ⚪ 影響なし | 45 |

89 件すべてに理由が付いたうえで、人間が見るべきものが 2 件に絞られる、という状態です。

---

## どんなレポートが出るのか

`reports/2026-08-07.md` として生成されるファイルの抜粋です。

> ### 🔴 要対応
>
> #### CVE-2020-1747 — PyYAML@5.3
>
> | | |
> |---|---|
> | 深刻度 | CVSS 9.8 (CRITICAL) |
> | KEV | 掲載なし |
> | 依存 | 直接依存（`backend/requirements.txt`） |
> | 修正版 | 5.3.1 |
>
> **何が起きるか**: `yaml.load()` を `Loader` 指定なしで呼ぶと、YAML 内に埋め込まれた
> Python オブジェクト構築命令がそのまま実行されます。攻撃者が YAML の中身を制御できる場合、
> **アプリケーション権限での任意コード実行**になります。
>
> **このプロジェクトでの使用状況**: **使用中**。しかも外部入力を直接渡しています。
>
> **判断の根拠**:
> - `backend/loader.py:1` — `import yaml`
> - `backend/loader.py:6` — `yaml.load(request.data)` を `Loader` 引数なしで呼び出し
> - `backend/loader.py:6` — 引数が `request.data`（HTTP リクエストボディ）であり、攻撃者が内容を完全に制御できる
> - 対照的に `backend/loader.py:10` の `yaml.safe_load()` は安全であり、この経路は対象外
>
> **推奨アクション**: バージョンを上げるだけでは不十分です。`loader.py:6` を `yaml.safe_load()` に変更すれば、
> PyYAML のバージョンに関係なくこの攻撃経路は塞がれます。

捨てたほうにも同じだけ理由が付きます。

> ### ⚪ 影響なし
>
> | CVE | パッケージ | CVSS | 影響なしと判断した理由 |
> |---|---|---|---|
> | CVE-2021-23337 | lodash@4.17.20 | 8.1 | 脆弱なのは `_.template`。`app.js:1` で import しているが、使用しているのは `app.js:3` の `_.merge` のみで `_.template` の呼び出しは 0 件 |
> | CVE-2021-44906 | minimist@1.2.0 | 9.8 | 推移的依存。直接 import 0 件、かつ CLI 引数解析を行うコードがプロジェクト内に存在しない |
> | （13 件） | guzzlehttp/guzzle@6.5.0 | 最大 8.0 | プロジェクト内に PHP ソースファイルが 1 件も存在しない（`composer.lock` のみ） |

断定できないものは無理に捨てず、理由を書いて「様子見」に残します。

> ### 🟡 様子見
>
> #### qs@6.7.0 — 3 件（最大 CVSS 7.5、プロトタイプ汚染）
>
> **要対応にしなかった理由**: `qs` を直接 import している箇所はありません（推移的依存）。
> ただし `express` がクエリ文字列のパースに内部で `qs` を使うため、
> 「import が無い = 到達しない」とは言えません。`src/app.js:2` で express を読み込んでいるものの、
> サーバ起動・ルート定義が無く、外部リクエストが実際に処理されるかを確認できませんでした。

→ [レポート全文を見る](examples/sample-report.md) ／ [出力サンプル一覧](examples/README.md)

---

## 導入

`quiet-cve` は、調べたいプロジェクトの中に **ディレクトリごと置いて** 使います。

```
your-project/
├── src/
├── package.json
└── quiet-cve/      ← これを置くだけ
```

```bash
cd your-project
git clone --depth 1 https://github.com/high-tech-r/quiet-cve.git
rm -rf quiet-cve/.git   # 親リポジトリに .git が入れ子になるのを避ける
```

`config.yml` を自分用に書き換えて親リポジトリごとコミットするのが想定した使い方なので、
`.git` は消してしまってよいです。更新を追いたい場合は代わりに submodule にしてください。

**Claude Code のスキルとして常時認識させたい場合**（任意）:

```bash
mkdir -p .claude/skills
ln -s ../../quiet-cve .claude/skills/quiet-cve
```

シンボリックリンクを張らなくても、「quiet-cve の SKILL.md を読んで実行して」と言えば動きます。

### 動作要件

| | |
|---|---|
| Python | 3.11 以上（`tomllib` を使うため。3.8+ でもフォールバックで動く） |
| PyYAML | 任意。無い場合は同梱の簡易 YAML パーサを使う |
| gh CLI | GitHub Issue 起票を有効にする場合のみ |
| ネットワーク | `api.osv.dev` と `www.cisa.gov` への HTTPS |

### 対応エコシステム

| エコシステム | ロックファイル（推奨） | マニフェスト |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock` | `package.json` |
| PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock` | `requirements*.txt` |
| Composer | `composer.lock` | `composer.json` |

ロックファイルがあるとバージョンが正確に取れるため、検出精度が上がります。
マニフェストのみの場合はレンジ指定から下限バージョンを推定し、レポートにその旨が明記されます。

（`pnpm-lock.yaml` は未対応。この場合 `package.json` のレンジから下限バージョンを
推定して読みます。正確なバージョンで見たいなら `npm install --package-lock-only` で
`package-lock.json` を作れば使われますが、pnpm が実際に入れたバージョンとはずれうる点に注意してください）

### ロックファイルに載らない資産

宣言された依存だけを見る SCA ツールには、原理的な死角があります。
CDN 経由で読み込んでいるライブラリ、`public/js/` などに手動で配置されたファイル、
フォーク・改造されてバージョン番号が原型を留めていないもの。
歴史の長いコードベースほど、これらが溜まっています。

quiet-cve は手元実行時にこれらも走査します（`scan.include_undeclared_assets`、既定 on）。
HTML やテンプレートの `<script src>` から CDN の URL を、配置されたファイルの
ファイル名と先頭バナーからライブラリ名とバージョンを拾い、特定できたものは
通常の依存と同じように OSV へ照会してトリアージに乗せます。
**特定できなかったものも黙って落とさず**、「特定できず・手動確認を推奨」として
レポートに列挙します。

実際、CDN 読み込みのまま放置された `jquery 1.12.4` からは、KEV 掲載
（実悪用あり）の CVE-2020-11023 が出てきます。ロックファイルには決して
載らないのに、実際に攻撃されている —— この死角を埋めるための機能です。

ただし対象は **OSV.dev に照会できるエコシステムのライブラリまで**です。
Apache / nginx / OpenSSL / PHP 本体のようなミドルウェア・実行環境の CVE 照合は
対象外です（ロードマップ参照）。

---

## 使い方

### 基本

Claude Code に頼むだけです。

```
quiet-cve で CVE チェックして
```

Claude が `SKILL.md` の手順に従って、次を順に実行します。

1. 依存ファイルを検出する（`package-lock.json` などを自動で探す）
2. ロックファイルに載らない資産も走査する（CDN 読み込み・手動配置されたライブラリ。
   バージョンを特定できたものは照会対象に加え、できなかったものもレポートに列挙する）
3. OSV.dev に問い合わせ、CISA KEV カタログと照合する
4. `config.yml` の `ignore` を適用する（期限切れの除外は自動で失効させる）
5. **各 CVE についてコードを読み、脆弱な機能を実際に使っているか判定する** ← 中核
6. 要対応 / 様子見 / 影響なし に分類する
7. `reports/YYYY-MM-DD.md` を書く
8. `logs/triage.jsonl` に 1 判定 1 行で追記する
9. 条件を満たせば GitHub Issue を起票する（既定では無効）
10. 保持期間を過ぎた古いレポートを月次サマリーに集約して削除する

### いつ実行するか

**毎日回すものではありません。** 毎日必要な仕事（新しい CVE が出ていないかの見張り）は
Dependabot が無料で自動でやるので、quiet-cve のトリアージは
**見張りが何か拾ったときだけ**実行すれば足ります。

- Dependabot のアラート通知が来たとき、または溜まってきたとき
- リリース前の確認
- 習慣にするなら月 1 回程度

トリアージは Claude がコードを読むぶんトークンを消費します。依存もアドバイザリも
変わっていないのに毎日回しても、同じ結果に課金するだけです。

出てきたレポートは 🔴 要対応だけ読んで対処すれば十分です。🟡 様子見と ⚪ 影響なしは
読まなくても、必要になったときのために根拠ごと残っています。対応不要と判断したものを
`ignore` に期限付きで書いておけば、次回以降は静かになります。

どうしても指示を出すことすら自動化したい場合は、ヘッドレス実行を cron に載せられます
（トークンを定期消費する点に注意）。

```bash
claude -p "quiet-cve で CVE チェックして"
```

### スクリプト単体で使う

Claude を介さず、検出と OSV 照会だけを回すこともできます。

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

古いレポートの集約だけを単体で回すこともできます。

```bash
# 何が集約・削除されるか確認するだけ（削除しない）
python3 scripts/rotate_reports.py --dry-run

# 実行
python3 scripts/rotate_reports.py
```

終了コード `2` は「通信に失敗した項目がある」の意味です。
結果が空でも「脆弱性なし」を意味しないので、`errors` フィールドを必ず見てください。

---

## どうやって絞り込んでいるのか

Dependabot は **検知** の道具で、quiet-cve は **取捨選択** の道具です。

依存関係の CVE を全部通知すると、人は 3 週間で全部無視するようになります。
本当の問題は「脆弱性が見つからないこと」ではなく「見つかりすぎて重要なものが埋もれること」です。

そこで 3 つの軸で絞り込みます。

| 軸 | 内容 |
|---|---|
| **KEV** | CISA の「実際に悪用が確認された脆弱性」カタログに載っているか |
| **CVSS** | 深刻度スコア（v3 ベクタから正確に計算する） |
| **実コード使用状況** | ★ **このプロジェクトが本当にその脆弱な機能を呼んでいるか** |

3 つ目が中核です。単にパッケージ名を grep するのではなく、
アドバイザリを読んで「どの関数・オプションが危険なのか」を先に特定し、
**その呼び出しが実行経路に存在するか**を確かめます。
lodash に脆弱性があっても、危ないのが `_.template` で、あなたが使っているのが `_.merge` だけなら、
それは「影響なし」です。

判定は `used` / `unused` / `unknown` の 3 値で、`unused` と書けるのは根拠が 2 つ以上揃ったときだけです。
追いきれなかったものは `unknown` として「様子見」に残します。
**根拠なしに「影響なし」と書かないことが、このツールの設計上いちばん重要な制約です。**

### Dependabot との違い

| | Dependabot | quiet-cve |
|---|---|---|
| 検知（依存とアドバイザリの照合） | ⭕ リアルタイム | ⭕ 週 1 回（同梱の CI テンプレート） |
| **ロックファイルに載らない資産の検知**（CDN 読み込み・手動配置・フォーク改造版） | ✕ | ⭕ Claude が走査（手元実行時） |
| 修正版への更新 PR を自動作成 | ⭕ | ✕ |
| **脆弱な機能を実際に使っているかの判定** | ✕ | ⭕ Claude がコードを読んで判定 |
| 判定の根拠（`file:line`）の記録 | ✕ | ⭕ |
| 「無視する」に理由と期限を強制 | △ dismiss は無期限 | ⭕ 期限切れで自動再浮上 |
| 通知の形 | 脆弱性ごとにアラートが積み上がる | Issue 1 本を使い回す |
| KEV（悪用実績）による優先度昇格 | ✕ | ⭕ |

Dependabot の問題は検知が下手なことではなく、**検知した後の扱いが無い**ことです。
アラートが数百件並び、そのうち本当に危ないものを知る手段がなく、
dismiss には期限が無いので一度消したものは二度と戻ってこない。
quiet-cve が担当するのはこの「後」の部分です。

### 併用を推奨します

役割が「検知」と「取捨選択」で重ならないため、競合しません。置き換えではなく足してください。

1. **Dependabot alerts（と Dependabot security updates）は有効のまま**にする。
   検知の速さと更新 PR の自動作成は Dependabot のほうが優れています
2. アラートが溜まってきたら、手元で quiet-cve のトリアージを実行する
3. 「影響なし」と判定されたものは、根拠つきの判定理由を添えて Dependabot 側で dismiss し、
   quiet-cve の `ignore` にも理由と期限を書く（期限が切れたら再浮上して再確認を促す）
4. Dependabot を使っている場合、quiet-cve の週次 CI（後述）は検知が丸ごと重複するので
   **不要です**

---

## 設定

すべて `config.yml` にあります。よく触るのはこのあたりです。

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

**CVE を無視したい場合は、しきい値を下げずに `ignore` に理由と期限を書いてください。**

```yaml
ignore:
  cves:
    - id: CVE-2024-12345
      reason: "該当機能(XMLパーサ)を使っていない。2026-01-15 に手動確認済み"
      expires: "2026-12-31"   # 日付は必ず引用符で囲む
```

期限を過ぎた除外は自動的に失効し、「⚠ 除外期限切れ」としてレポートに再浮上します。
無期限の握りつぶしを作らないための仕組みです。

---

## GitHub Actions で定期実行する（Dependabot が使えない環境向け）

**Dependabot と併用する構成では、この定期実行は不要です。** 役割は「あなたが何も
していない間に、依存パッケージへ新しい CVE が公表されていないか」の見張りであり、
Dependabot alerts と丸ごと重複します。使うのは、組織のポリシーで Dependabot を
有効にできない、通知をアラート一覧ではなく Issue 1 本に寄せたい、といった環境だけです。

Dependabot に対する数少ない上乗せは次の 2 つで、これだけのために入れる価値があるかは
環境次第です。

- 既知の CVE が後から **KEV（悪用実績カタログ）に載った**とき、要対応に昇格して知らせる
- `config.yml` の `ignore` の**期限切れ**を、手元で実行しなくても Issue で督促する

導入する場合は `examples/github-actions/quiet-cve-scan.yml` を
`.github/workflows/quiet-cve.yml` にコピーしてください。Settings > Actions > General >
Workflow permissions を **Read and write permissions** にする必要があります（Issue 起票に必要）。

**CI は検知しかしません。** Claude が動かないので、このツールの中核である
コード実使用判定が実行できないからです。ワークフローがやるのは

1. `osv_query.py` で OSV / KEV に照会する
2. `ci_summary.py` で `config.yml` の `ignore` としきい値を適用し、件数を出す
3. トリアージすべきものがあれば Issue を 1 本立てる（既にあれば本文を差し替える）
4. 生の `scan.json` を artifact に残す
5. 終了コード `2`（通信失敗）ならジョブを失敗させる ← 0 件を「安全」と誤読させないため

までで、`reports/` `logs/` はコミットしません。`usage: unknown` だけのレコードを
追記専用ログに積むと月次集約の質が落ちるので、記録は手元のトリアージ実行に一本化しています。

CI 側の分類は、実使用が常に不明である前提で次のようになります。

| CI の分類 | 条件 |
|---|---|
| 🔴 要対応 | KEV 掲載（`kev_always_act`） |
| 🟡 要トリアージ | CVSS ≥ `act_cvss`、または深刻度不明（`unknown_severity`） |
| ⚪ 未判定 | それ以外 |

**`影響なし` は CI からは絶対に出ません。** 根拠なしに安心を配らないという原則を
CI 側でも守るため、上位ルールに当たらなかったものは「未判定」に置きます。

Issue は 1 本を使い回します（本文の `<!-- quiet-cve-ci-scan -->` で同定）。
本文は毎回黙って差し替え、通知が飛ぶコメントを付けるのは KEV 掲載があるときだけです。

```bash
# 手元で CI と同じ要約を再現する
python3 scripts/osv_query.py --out scan.json
python3 scripts/ci_summary.py --scan scan.json --markdown issue-body.md
```

---

## 出力されるファイル

### `reports/YYYY-MM-DD.md`

人間が読むレポート。要対応・様子見・影響なしの 3 分類で、
各項目に「何が起きるか」「このプロジェクトでの使用状況」「判断の根拠」「推奨アクション」が付きます。
影響なしは `<details>` で折りたたまれます。

### `reports/monthly/YYYY-MM.md`

`retention_days`（既定 90 日）を過ぎた日次レポートは、月次サマリーに集約されてから削除されます。
日次レポートが際限なく溜まると、結局誰も見に行かなくなるためです。

サマリーには「その月に要対応となった CVE 一覧（通知先の issue リンク付き）」
「3 回以上繰り返し様子見になったもの」「KEV 掲載なのに影響なしと判定したもの（要レビュー）」
が残ります。集約元は Markdown ではなく `logs/triage.jsonl` なので、何度実行しても同じ結果になります。

削除しても問題ない理由は、**判断根拠を含む全レコードが `logs/triage.jsonl` に残り続ける**からです。
日次レポートはあくまで人間向けの表示物にすぎません。

安全弁として、**ログに該当日の記録が無いレポートは削除されません**（根拠が完全に失われるため）。
月次サマリーの書き出しに失敗した場合も 1 件も削除しません。

```bash
python3 scripts/rotate_reports.py --dry-run   # 何が消えるか先に確認
```

### `logs/triage.jsonl`

1 判定 = 1 行の JSON Lines。追記専用です。

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

`jq` が無い環境では Python で同じことができます。

```bash
python3 -c "
import json,collections
rows=[json.loads(l) for l in open('logs/triage.jsonl',encoding='utf-8')]
print(dict(collections.Counter(r['verdict'] for r in rows)))
"
```

### `osv_query.py` の出力

<details>
<summary>スキャン結果の JSON 構造（クリックで展開）</summary>

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

</details>

---

## リポジトリの構成

| | |
|---|---|
| `SKILL.md` | Claude が従う手順書。トリアージの規則はここに書いてある |
| `config.yml` | しきい値・除外・通知・保持期間。触るのは基本ここだけ |
| `scripts/osv_query.py` | 依存検出 → OSV 照会 → KEV 照合 → JSON 出力 |
| `scripts/ci_summary.py` | CI 向けの要約。判定はせず件数だけ出す |
| `scripts/rotate_reports.py` | 期限切れレポートの月次集約と削除 |
| `examples/` | 出力サンプルと GitHub Actions のテンプレート |
| `reports/` `logs/` | 実行結果の出力先 |

---

## 設計思想

**0. 攻撃側の AI には、防御側の AI で**

このツールを作った動機です。AI によって、脆弱性の公表からエクスプロイトが
出回るまでの時間は数週間から数日・数時間へと縮み続けています。公表件数そのものも
増え続けている。「溜まったアラートを人間が手隙のときにまとめて見る」速度では、
もう競争になりません。

一方で防御側のボトルネックは検知ではなく、「このうち自分のコードに実害があるのは
どれか」を選ぶ判断でした。コードを読まないと決められないため自動化できず、
人間の時間が律速だった部分です。quiet-cve はこの判断を AI に任せることで、
**公表から対応判断までの時間を、公表から悪用までの時間に追いつかせる**ための道具です。

（なお、狭義のゼロデイ —— 公表前に悪用される脆弱性 —— はデータベースに
載っていない以上、このツールでは検知できません。守っているのは「公表された
瞬間から始まる競争」のほうです。）

この構成の背景となる考え方は
[こちらの記事](https://qiita.com/udowanllc/items/024e91ccb6393159c798)
にまとまっています。quiet-cve はその実装版という位置づけです。

**1. 捨てる根拠を作ることが仕事**

検知は簡単で、無視の判断が難しい。このツールの価値は
「なぜこの CVE を今日対応しなくてよいのか」を根拠付きで残すところにあります。

**2. 不明を未使用に丸めない**

判定は `used` / `unused` / `unknown` の 3 値。動的ロードで追えない、
生成コードで読めない —— そういうときは `unknown` にして「様子見」に落とします。
`unused` と書けるのは根拠が 2 つ以上揃ったときだけ。
誤った安心を配るくらいなら、余分に報告するほうがいい。

**3. 握りつぶしに期限を付ける**

`ignore` には `expires` が必須。期限が切れれば自動的に再浮上します。
「一度無視したものが永久に見えなくなる」状態を作りません。

**4. 決定は設定ファイルに、判断はモデルに**

しきい値・除外・通知は `config.yml` に固定します（再現性のため）。
「このコードはこの脆弱な関数を呼んでいるか」という判断だけをモデルに任せます。
モデルがしきい値を勝手に緩めることは `SKILL.md` で禁じています。

**5. 追記専用のログ**

`logs/triage.jsonl` は書き換えません。判定が時間とともにどう変わったか
（`unknown` が `used` になった、など）を追えることが、運用の改善につながります。

だからこそ日次レポートは捨てられます。表示物（`reports/`）は期限を切って月次に畳み、
記録（`logs/`）だけが無期限に残る。溜まる一方のレポートは読まれなくなるので、
畳むこと自体がアラート疲れ対策の一部になっています。

**6. 賢さは同じ。違うのは手順と記録**

quiet-cve を使わなくても、Claude Code に「Dependabot のアラートを見て対応して」と
頼めばコードを読んで判断してくれます。頭脳は同じ Claude なので、
1 回の判定の質はそれで十分なことも多い。
このフレームワークが足しているのは賢さではなく、
その場かぎりの会話を運用に変えるための固定です。

- **手順の固定** — その場の指示では、どこまで調べるかがその日の頼み方と
  モデルの裁量で揺れます。SKILL.md は「grep で有無だけ見て判定しない」
  「`影響なし` には根拠 2 つ以上」「迷ったら `unknown`」を毎回強制し、
  KEV 照合や重複統合のような機械仕事はスクリプトが毎回同じにこなします。
- **記録の固定** — 会話の中の「使ってないから大丈夫です」は、会話が終われば消えます。
  3 ヶ月後に同じ CVE を見て「これ前に調べたっけ？」を繰り返さないために、
  全判定を追記専用ログに根拠付きで残します。
- **失効の固定** — その場の「対応不要」は、そのまま永久に不要扱いになりがちです。
  `ignore` の期限切れ再浮上が、判断した当時のコードと今のコードのずれを拾います。

つまり quiet-cve は「Claude にうまく頼むためのプロンプト集」ではなく、
毎回同じ基準で判定され、判断が残り、放置が失効する **運用の器** です。

---

## ロードマップ

- [x] npm / PyPI / Composer 対応
- [x] KEV + CVSS + 実コード使用状況によるトリアージ
- [x] Markdown レポート / JSON Lines ログ
- [x] GitHub Issue 起票
- [x] GitHub Actions での定期実行（cron）
- [x] ロックファイルに載らない資産の棚卸し（CDN 読み込み・手動配置）
- [ ] ミドルウェア・実行環境の照合（Apache / nginx / OpenSSL / PHP 本体。NVD CPE 対応が必要）
- [ ] pnpm / Go modules / RubyGems / Cargo 対応
- [ ] EPSS（悪用可能性スコア）の取り込み
- [ ] 前回実行との差分レポート（新規 CVE のみ通知）

---

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
