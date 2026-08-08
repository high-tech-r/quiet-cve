# CVE スキャン結果 — 2026-08-07

> このファイルは動作確認用のテストプロジェクトに対する実行結果です。
> 出力形式のサンプルとして同梱しています。詳細は [examples/README.md](README.md) を参照。

- 実行日時: 2026-08-07T09:14:00Z
- 対象: `/path/to/fixture-app`
- 依存ファイル: `package-lock.json`, `backend/requirements.txt`, `php/composer.lock`, `po/poetry.lock`, `pf/Pipfile.lock`, `y/yarn.lock`
- スキャンしたパッケージ: 16 件（npm 6 / PyPI 7 / Packagist 3）
- KEV カタログ: 読み込み済み 1,661 件

| 分類 | 件数 |
|---|---|
| 🔴 要対応 | 2 |
| 🟡 様子見 | 42 |
| ⚪ 影響なし | 45 |
| ⚫ 設定により除外 | 0 |

OSV.dev は 89 件の脆弱性を返しましたが、**人間の対応が必要なのは 2 件** です。

---

## 🔴 要対応

### CVE-2020-1747 — PyYAML@5.3

| | |
|---|---|
| 深刻度 | CVSS 9.8 (CRITICAL) |
| KEV | 掲載なし |
| 依存 | 直接依存（`backend/requirements.txt`） |
| 修正版 | 5.3.1 |

**何が起きるか**: `yaml.load()` を `Loader` 指定なしで呼ぶと、YAML 内に埋め込まれた
Python オブジェクト構築命令がそのまま実行されます。攻撃者が YAML の中身を制御できる場合、
**アプリケーション権限での任意コード実行**になります。

**このプロジェクトでの使用状況**: **使用中**。しかも外部入力を直接渡しています。

**判断の根拠**:
- `backend/loader.py:1` — `import yaml`
- `backend/loader.py:6` — `yaml.load(request.data)` を `Loader` 引数なしで呼び出し
- `backend/loader.py:6` — 引数が `request.data`（HTTP リクエストボディ）であり、
  攻撃者が内容を完全に制御できる
- 対照的に `backend/loader.py:10` の `yaml.safe_load()` は安全であり、この経路は対象外

**推奨アクション**:

```bash
pip install 'PyYAML>=5.4'
```

バージョンを上げるだけでは不十分です。`loader.py:6` を修正してください:

```python
# 修正前
return yaml.load(request.data)
# 修正後
return yaml.safe_load(request.data)
```

`safe_load` に変更すれば、PyYAML のバージョンに関係なくこの攻撃経路は塞がれます。

**参考**: https://github.com/yaml/pyyaml/issues/420

---

### CVE-2020-14343 — PyYAML@5.3

| | |
|---|---|
| 深刻度 | CVSS 9.8 (CRITICAL) |
| KEV | 掲載なし |
| 依存 | 直接依存（`backend/requirements.txt`） |
| 修正版 | 5.4 |

**何が起きるか**: CVE-2020-1747 の修正が不完全で、`FullLoader` でも
Python オブジェクト構築を経由した任意コード実行が可能でした。

**このプロジェクトでの使用状況**: **使用中**（CVE-2020-1747 と同一の呼び出し箇所）。

**判断の根拠**:
- `backend/loader.py:6` — `yaml.load(request.data)`（`FullLoader` を指定しても回避されない）

**推奨アクション**: 5.4 以上へ更新。上記の `safe_load` への修正で両 CVE をまとめて解消できます。

**参考**: https://github.com/yaml/pyyaml/pull/386

---

## 🟡 様子見

### django@2.2.0 — 35 件（うち CRITICAL 7 件）

**要対応にしなかった理由**: プロジェクト内に Django を import しているコードが 1 件もなく
（`*.py` 全走査で 0 件）、実使用が確認できません。

**ただし引き下げていない理由**: `requirements.txt` の記述が `django>=2.2.0` というレンジ指定で、
インストールされる実バージョンを特定できていません（`version_exact: false`）。
2.2.0 と仮定して照会した結果なので、実環境が別バージョンの可能性があります。

**推奨アクション**: `pip freeze > requirements.lock` などで実バージョンを固定してから再実行してください。
使っていないなら依存自体を削除するのが最善です。

### flask@0.12.2 — 4 件（最大 CVSS 7.5）

**要対応にしなかった理由**: `backend/loader.py:2` で `from flask import request` を使っており
**Flask 自体は使用中**ですが、各 CVE の脆弱な機能（セッション Cookie のキャッシュ制御、
JSON パーサの DoS）に到達するかを判定できませんでした。アプリの起動コードと
ルーティング定義がプロジェクト内に見当たらず、リクエスト処理経路を追えていません。

**判断の根拠**:
- `backend/loader.py:2` — `from flask import request`（Flask は使用中）
- アプリ生成箇所（`Flask(__name__)`）が見つからず、到達可能性は `unknown`

### qs@6.7.0 — 3 件（最大 CVSS 7.5、プロトタイプ汚染）

**要対応にしなかった理由**: `qs` を直接 import している箇所はありません（推移的依存）。
ただし `express` がクエリ文字列のパースに内部で `qs` を使うため、
「import が無い = 到達しない」とは言えません。`src/app.js:2` で express を読み込んでいるものの、
サーバ起動・ルート定義が無く、外部リクエストが実際に処理されるかを確認できませんでした。

**判断の根拠**:
- `qs` の直接 import: 0 件（`src/` 全走査）
- `src/app.js:2` — `require('express')`（express 経由の間接到達の可能性が残る）
- 到達可能性は `unknown`。`unused` と断定できるだけの根拠が揃っていません。

---

## ⚪ 影響なし

<details>
<summary>45 件（クリックで展開）</summary>

| CVE | パッケージ | CVSS | 影響なしと判断した理由 |
|---|---|---|---|
| CVE-2021-23337 | lodash@4.17.20 | 8.1 | 脆弱なのは `_.template`。`app.js:1` で import しているが、使用しているのは `app.js:3` の `_.merge` のみで `_.template` の呼び出しは 0 件 |
| CVE-2025-13465 | lodash@4.17.20 | 6.5 | 脆弱なのは `_.unset` / `_.omit`。全走査で呼び出し 0 件（使用関数は `_.merge` のみ） |
| CVE-2020-28500 | lodash@4.17.20 | 5.3 | 脆弱なのは `_.trim` / `_.toNumber` の ReDoS。呼び出し 0 件 |
| CVE-2024-29041 | express@4.17.1 | 6.1 | 脆弱なのは `res.location()` / `res.redirect()`。`app.js:2` で import しているが両者の呼び出しは 0 件 |
| CVE-2024-43796 | express@4.17.1 | 5.0 | 同上（`response.redirect()` 経由の XSS）。呼び出し 0 件 |
| CVE-2021-44906 | minimist@1.2.0 | 9.8 | 推移的依存。直接 import 0 件、かつ CLI 引数解析を行うコードがプロジェクト内に存在しない |
| CVE-2020-7598 | minimist@1.2.0 | 5.6 | 同上 |
| （12 件） | urllib3@1.24.1 | 最大 8.1 | 推移的依存。`import urllib3` 0 件、かつ利用元の `requests` も import 0 件 |
| （13 件） | guzzlehttp/guzzle@6.5.0 | 最大 8.0 | プロジェクト内に PHP ソースファイルが 1 件も存在しない（`composer.lock` のみ） |
| （5 件） | jinja2@2.11.2 | 最大 7.8 | 推移的依存。`import jinja2` 0 件、テンプレート描画箇所なし |
| （5 件） | requests@2.19.1 | 最大 7.5 | `import requests` 0 件 |
| CVE-2026-24765 | phpunit/phpunit@8.5.0 | 7.8 | dev 依存かつ PHP ソースが存在しない。CI 設定にも PHPUnit の実行が無い |
| （1 件） | pytest@5.0.0 | 6.8 | dev 依存。テストコードが存在しない |
| CVE-2026-49356 | @babel/core@7.9.0 | 3.2 | 推移的依存。ビルド設定に Babel の利用が無い |

</details>

---

## ⚫ 設定により除外

なし。

---

## 実行時の注意

- `requirements.txt` の `django>=2.2.0` はレンジ指定のため、下限の 2.2.0 で照会しています
  （`version_exact: false`）。実際にインストールされているバージョンとは異なる可能性があります。
- OSV.dev は 89 件を返しましたが、同一 CVE を指す GHSA / PYSEC の重複レコードを統合した後の件数です
  （統合前 151 件）。
- OSV / KEV への照会エラーはありませんでした。
