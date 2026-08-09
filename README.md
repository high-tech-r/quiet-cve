# quiet-cve

**プロジェクトが抱える CVE を「本当に対応が必要なものだけ」に絞り込む、Claude Code 用のツールです。**

見つかった脆弱性ひとつひとつについて **Claude があなたのコードを実際に読み**、
「その脆弱な機能を本当に呼んでいるか」を確かめたうえで、
**要対応 / 様子見 / 影響なし** に仕分けした Markdown のレポートを出します。
判定にはすべて「どのファイルの何行目を見てそう判断したか」という根拠が付きます
（例: `src/api/upload.js:42` — 脆弱な `parseForm()` を外部リクエスト経路で呼んでいる）。

**Dependabot などの SCA ツールが原理的に検知できないものもチェックできます。**
SCA が見るのは package.json のような「宣言された依存」だけですが、実際のコードベースには
そこに載らない部品 —— CDN から読み込んでいるライブラリ、`public/js/` に手で置かれたファイル、
サーバで動いているミドルウェア —— が必ずあります。quiet-cve はコードを走査して
**実態ベースの部品棚卸し（いわば SBOM の実態版）** を作り、宣言に載らない部品まで照会に載せます。

| 対象 | 検知のしかた | 照会先 |
|---|---|---|
| npm / PyPI / Composer の依存 | ロックファイルを自動検出 | [OSV.dev](https://osv.dev) + CISA KEV |
| CDN 読み込み・手動配置のライブラリ | Claude がコードを走査（**SCA の死角**） | OSV.dev + CISA KEV |
| nginx / OpenSSL / PHP 本体などのミドルウェア | `config.yml` に宣言（**SCA の死角**） | NVD + CISA KEV |

インストールは git clone だけ。実行は、プロジェクトで Claude Code にこう頼むだけです。

```
quiet-cve で CVE チェックして
```

Python 3.11+ があれば追加の依存はありません（標準ライブラリのみ）。
API キーも不要です（OSV.dev・NVD とも認証不要で使えます）。

Dependabot の置き換えではありません。Dependabot が **検知** を、quiet-cve が
**取捨選択** を担当する [併用を推奨します](#dependabot-との違い)。
Dependabot には見えない範囲（宣言したミドルウェア等）の見張りには、
[同梱の週次スキャン（GitHub Actions）](#github-actions-で定期実行する)が使えます。

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
| ネットワーク | `api.osv.dev` と `www.cisa.gov` への HTTPS（ミドルウェア照合を使う場合は `services.nvd.nist.gov` も） |

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

### ミドルウェア・実行環境

Apache / nginx / OpenSSL / PHP 本体のような、パッケージマネージャの外にある
ソフトウェアの CVE も照合できます（データソースは NVD。API キー不要）。

たとえば `php 8.1.0` からは **CVE-2024-4577**（PHP CGI の RCE。KEV 掲載 =
2024 年に実際に大規模悪用）、`nginx 1.18.0` からは **CVE-2023-44487**
（HTTP/2 Rapid Reset）が出ます。どちらもロックファイルには決して現れません。

#### 使い方は 2 ステップ

**Step 1. サーバで実際のバージョンを調べる**（コンテナなら `docker compose exec` で中から）

```bash
nginx -v 2>&1; php -v | head -1; openssl version; node -v
```

**Step 2. 出た番号を `config.yml` に書き写す**

```yaml
scan:
  middleware:
    - name: nginx
      version: "1.18.0"
    - name: php
      version: "8.1.30"
```

以上です。あとは通常のトリアージ実行にミドルウェアの CVE も含まれるようになります。

**バージョンはできるだけパッチ番号まで詳細に書いてください。精度が上がります。**
`"8.1.30"` まで指定すれば「そのバージョンに実際に該当する CVE」だけに絞られ、
すでに修正済みの CVE（8.1.5 で直ったもの等）は混ざりません。`"8.1"` のような
大まかな指定でも動きますが、8.1 系のどこかで該当した CVE がすべて出るため、
そのぶんトリアージの手間が増えます（詳細は後述）。

なぜサーバで調べるのか: **本当のバージョンはサーバの中にしか無い**からです。
Dockerfile の `php:8.1` のようなタグはパッチ版を固定しません。CI が毎デプロイで
ビルドしていれば pull のたびに中身が進み、長く再ビルドしていなければ古いまま ——
どちらもリポジトリからは見えないので、quiet-cve は宣言されたものだけを信じます。

#### サーバをすぐ確認できないとき

助けが 2 つあります。

**その 1: 候補を自動で集める**

```bash
python3 scripts/nvd_query.py --suggest
```

リポジトリ内のヒント（Dockerfile の FROM、docker-compose / `.gitlab-ci.yml` の
image、`.nvmrc` / `.tool-versions`、package.json の `engines`、composer.json の
`require.php`、GitHub Actions の `php-version:` 等）を走査して、
「php 8.1 系を使っているようです（根拠: Dockerfile:2）」という形の宣言候補を出します。
出すのは候補まで。照会はせず、config を勝手に書き換えることもしません。

**その 2: 大まかな番号のまま宣言する**

パッチ版まで分からなければ `version: "8.1"` と書いてください。8.1 系全体
（8.1.0 以上 8.2 未満）をまとめて照会するので、実際のパッチ版が系内のどれでも
該当 CVE は漏れなく含まれます。そのぶん結果は多めに出ますが、
多めに出ている旨はレポートに明記されます。

これはあくまで**見逃さないための保険**です。大まかな宣言では「あなたの環境では
すでに修正済みの CVE」も混ざって出るため、トリアージの手間が増えます。
サーバを確認できたタイミングで `"8.1.30"` のようにパッチ番号まで書き直せば、
該当する CVE だけに絞られて精度が上がります。

#### 補足

- 対応製品は `python3 scripts/nvd_query.py --list-products` で一覧できます
  （apache-httpd / nginx / openssl / php / mysql / postgresql / redis / tomcat /
  nodejs / curl / ruby / python など。表に無い製品は `CPE_TABLE` に追記できます）
- NVD 側の解析には遅れがあるため、**0 件は「NVD 照会で該当なし」であって
  「脆弱性なし」の保証ではありません**。レポートもその前提で書かれます
- `NVD_API_KEY` 環境変数を設定するとレート制限が緩みます（無くても動きます）

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
3. `config.yml` に宣言されたミドルウェア（nginx / OpenSSL / PHP 本体等）を NVD に照会する
4. OSV.dev に問い合わせ、CISA KEV カタログと照合する
5. `config.yml` の `ignore` を適用する（期限切れの除外は自動で失効させる）
6. **各 CVE についてコードを読み、脆弱な機能を実際に使っているか判定する** ← 中核
7. 要対応 / 様子見 / 影響なし に分類する
8. `reports/YYYY-MM-DD.md` を書く
9. `logs/triage.jsonl` に 1 判定 1 行で追記する
10. 条件を満たせば GitHub Issue を起票する（既定では無効）
11. 保持期間を過ぎた古いレポートを月次サマリーに集約して削除する

### いつ実行するか

**毎日回すものではありません。** コストの高い部分（Claude がコードを読む判定）は、
見張り役が何か拾ったときだけ動かせば足ります。ただし検知対象ごとに
「誰が見張っているか」が違うので、そこから頻度を決めてください。

| 対象 | 見張り役（無料・自動） | quiet-cve を動かすタイミング |
|---|---|---|
| ロックファイル依存 | Dependabot（リアルタイム） | アラートが来たとき・溜まったとき |
| ミドルウェア（宣言済み） | 週次 CI（同梱テンプレート） | CI の Issue が更新されたとき |
| CDN・手動配置ライブラリ | **なし**（Claude の走査時のみ見つかる） | **定期実行でカバー（月 1 回程度〜）** |

Dependabot + 週次 CI が回っていれば、上 2 行はトリガー駆動で足ります。
**CDN・手動配置のライブラリだけは誰も見張っていない**ので、月 1 回程度の定期実行か
リリース前の実行でカバーしてください。ここが唯一「頻度と発見の早さ」が
トレードオフになる領域です — 頻度を上げるほど発見は早まりますが、
トリアージは Claude がコードを読むぶんトークンを消費します。
コードも資産も変わらず新しい CVE も出ていなければ、毎日回しても同じ結果に課金するだけです。

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
| **ミドルウェアの CVE 照合**（Apache / nginx / OpenSSL / PHP 本体等） | ✕ | ⭕ NVD CPE 照合（config 宣言ベース） |
| 修正版への更新 PR を自動作成 | ⭕ | ✕ |
| **脆弱な機能を実際に使っているかの判定** | ✕ | ⭕ Claude がコードを読んで判定 |
| 判定の根拠（ファイル名と行番号）の記録 | ✕ | ⭕ |
| 「無視する」に理由と失効条件を強制 | △ dismiss は無期限 | ⭕ 期限切れ・根拠ファイル変更で自動再浮上 |
| 通知の形 | 脆弱性ごとにアラートが積み上がる | Issue 1 本を使い回す |
| KEV（悪用実績）による優先度昇格 | ✕ | ⭕ |

Dependabot の問題は検知が下手なことではなく、**検知した後の扱いが無い**ことです。
アラートが数百件並び、そのうち本当に危ないものを知る手段がなく、
dismiss には期限が無いので一度消したものは二度と戻ってこない。
quiet-cve が担当するのはこの「後」の部分です。

### 「アップグレードしない」という選択肢を作る

Dependabot の出力は更新 PR なので、取れる行動は「マージする」か「dismiss で黙らせる」の
2 つしかありません。Claude Code に PR を渡しても、答えてくれるのは「どう上げるか」です。
「そもそも上げる必要があるか」を判断させても、**その判断を記録する場所がワークフローに無い**
ので、システムはマージするまで鳴り続けます。

パッチ更新ならマージすれば済みます。しかしメジャーアップデートは破壊的変更の改修と
回帰テストで数人日〜数週間かかることがあり、**到達不可能な脆弱性のためにこの工数を
毎回払うのはもったいない**。quiet-cve は「その脆弱な機能に実際に到達できるか」を
判定するので、高くつくアップグレードだけを**根拠付きで見送れます**。
見送りは放置ではありません — 根拠（ファイル名と行番号）と期限付きで記録され、
期限が切れれば自動で再浮上します。

正確に言うと、これで節約されるのは「免除」ではなく**延期**です。古いメジャーに
留まるほど、いつか払うアップグレード費用は膨らみます。quiet-cve が変えるのは
支払いのタイミングの主導権 —— 「CVE が出るたびに割り込みで強制される」を
「自分のリリース計画に載せてまとめて払う」にできることです。

もうひとつ正確に言うと、アップグレードの判断材料は CVE だけではありません
（バグ修正・新機能・EOL・互換性）。quiet-cve が答えるのはそのうち
**セキュリティの一票だけ** ——「この CVE を理由に、今すぐ上げる必要があるか」です。
CVE の観点で急ぐ理由が消えても、他の理由で上げるのは普通のことですし、
逆に他の事情で上げたくなくても、到達可能な CVE があれば容赦なく「要対応」と出ます。
判断を代行するのではなく、**CVE 起因の偽の緊急性を取り除いて、
アップグレードを通常の計画業務に戻す**ための補佐です。

運用の目安: **安い更新（パッチ・マイナー）は黙ってマージ、
高い更新（メジャー・破壊的変更）だけトリアージ。**

### 併用を推奨します

役割が「検知」と「取捨選択」で重ならないため、競合しません。置き換えではなく足してください。

1. **Dependabot alerts（と Dependabot security updates）は有効のまま**にする。
   検知の速さと更新 PR の自動作成は Dependabot のほうが優れています
2. アラートが溜まってきたら、手元で quiet-cve のトリアージを実行する
3. 「影響なし」と判定されたものは、根拠つきの判定理由を添えて Dependabot 側で dismiss し、
   quiet-cve の `ignore` にも理由と期限を書く（期限が切れたら再浮上して再確認を促す）
4. quiet-cve の週次 CI（後述）は、ロックファイル依存の検知としては Dependabot と
   重複します。ただし **`config.yml` に宣言したミドルウェアの見張りは週次 CI に
   しかできない**ので、ミドルウェアを宣言しているなら併用構成でも入れてください

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

**CVE を無視したい場合は、しきい値を下げずに `ignore` に理由を書いてください。**
理由の種類は **VEX（CycloneDX）準拠の `justification`** で宣言します。

```yaml
ignore:
  cves:
    # 「腐る」理由 — コードが変われば無効になるので、日付の期限が必須
    - id: CVE-2024-12345
      reason: "該当機能(XMLパーサ)を使っていない。2026-01-15 に手動確認済み"
      justification: vulnerable_code_not_in_execute_path
      expires: "2026-12-31"        # 日付は必ず引用符で囲む
      evidence_files:              # 任意: これが変わったら期限内でも再浮上
        - src/app.js
      verified_at_commit: "abc1234"

    # 「腐らない」理由 — コードと無関係なので、永久 ignore を許可
    - id: CVE-2023-99999
      reason: "Windows 限定の脆弱性。デプロイ先は Linux のみ"
      justification: platform_not_applicable
      expires: never
```

| justification | 種別 | expires |
|---|---|---|
| `false_positive`（誤検知・撤回） / `platform_not_applicable`（環境的に非該当） | **腐らない** | `never` 可 |
| `vulnerable_code_not_in_execute_path` / `vulnerable_code_cannot_be_controlled_by_adversary` / `inline_mitigations_already_exist` | **腐る** | 日付必須。`never` は設定エラーで実行停止 |
| 未指定（既存の書き方） | 従来どおり | 日付必須 |

「使っていない」系の判断は、コードが変われば**無言で**無効になります。だから腐るカテゴリに
永久 ignore は許しません。代わりに、カレンダー期限より賢い失効条件があります —
`evidence_files` と `verified_at_commit` を書いておくと、**根拠にしたファイルが判定時点から
変わった瞬間に、期限内でも「根拠ファイル変更あり・再確認が必要」として再浮上**します
（git で差分を確認します。git が使えない環境では警告を出してカレンダー期限のみで動きます）。

期限を過ぎた除外も従来どおり自動失効して再浮上します。期限は「依存の依存が変わった」
のような間接的な変化を拾う安全網として、変更検知と併用されます。

---

## GitHub Actions で定期実行する

役割は「あなたが何もしていない間に、新しい CVE が公表されていないか」の見張りです。
Claude なしで機械的にできる照会だけを毎週回します。見張れるのは 2 系統:

| 見張る対象 | Dependabot との関係 |
|---|---|
| ロックファイル依存（OSV 照会） | **重複**。Dependabot が有効ならこの部分は冗長 |
| `config.yml` に宣言したミドルウェア（NVD 照会） | **Dependabot には見えない**。週次 CI だけが見張れる |

つまり **Dependabot を使っていても、ミドルウェアを宣言しているなら入れる価値があります**。
逆にミドルウェアを宣言せず Dependabot も有効なら、ほぼ重複です（残る上乗せは、
既知 CVE が後から KEV に載ったときの昇格通知と、`ignore` の期限切れの督促だけ）。
なお CDN・手動配置ライブラリの検知は Claude が要るため、CI ではできません
（→ [いつ実行するか](#いつ実行するか)）。

導入は `examples/github-actions/quiet-cve-scan.yml` を
`.github/workflows/quiet-cve.yml` にコピーするだけです。Settings > Actions > General >
Workflow permissions を **Read and write permissions** にする必要があります（Issue 起票に必要）。

**CI は検知しかしません。** Claude が動かないので、このツールの中核である
コード実使用判定が実行できないからです。ワークフローがやるのは

1. `osv_query.py` で依存を OSV / KEV に照会する
2. `nvd_query.py` で宣言済みミドルウェアを NVD に照会する（宣言が無ければ何もしない）
3. `ci_summary.py` で両者を統合し、`config.yml` の `ignore` としきい値を適用して件数を出す
4. トリアージすべきものがあれば Issue を 1 本立てる（既にあれば本文を差し替える）
5. 生の `scan.json` / `scan-middleware.json` を artifact に残す
6. 終了コード `2`（通信失敗）ならジョブを失敗させる ← 0 件を「安全」と誤読させないため

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
| `scripts/nvd_query.py` | ミドルウェア（nginx / OpenSSL 等）の NVD CPE 照合 |
| `scripts/ignore_rules.py` | ignore の適用（寿命種別・根拠ファイル変更検知）。手元と CI の共通ロジック |
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

**3. 握りつぶしに期限を付ける — ただし理由の寿命に合わせて**

無視する理由には「腐らないもの」と「腐るもの」があります。アドバイザリの撤回や
プラットフォーム非該当はコードがどう変わっても無効にならないので、永久 ignore を
許します。一方「該当機能を使っていない」系の判断は、コードが変われば**無言で**
無効になる —— だからこちらには永久 ignore を絶対に許さず、日付の期限に加えて
**根拠ファイルの変更検知**（判定時のコミットからの git diff）で失効させます。
「一度無視したものが、根拠が崩れているのに見えないまま」という状態を作りません。

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
  `ignore` の期限切れ再浮上と根拠ファイルの変更検知（判定時のコミットからの git diff）が、
  判断した当時のコードと今のコードのずれを拾います。

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
- [x] ミドルウェア・実行環境の照合（Apache / nginx / OpenSSL / PHP 本体等。NVD CPE・config 宣言ベース）
- [x] ミドルウェアのバージョン候補の自動検出（`--suggest`。照会はあくまで宣言ベース）
- [x] ignore の寿命種別（VEX 準拠の `justification`・`expires: never`・根拠ファイルの変更検知）
- [ ] pnpm / Go modules / RubyGems / Cargo 対応
- [ ] EPSS（悪用可能性スコア）の取り込み
- [ ] 前回実行との差分レポート（新規 CVE のみ通知）

---

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
