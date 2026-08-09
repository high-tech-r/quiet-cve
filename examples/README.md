# 出力サンプル

quiet-cve が何を出すのかを、実際の実行結果で示すためのディレクトリ。
**これらは動作確認用のテストプロジェクトに対する結果**であり、
どこかの実プロジェクトの脆弱性を報告するものではない。

| ファイル | 内容 |
|---|---|
| [`sample-report.md`](sample-report.md) | `reports/YYYY-MM-DD.md` に生成されるレポート |
| [`sample-triage.jsonl`](sample-triage.jsonl) | `logs/triage.jsonl` に追記されるログ（抜粋 9 行） |
| [`sample-monthly-summary.md`](sample-monthly-summary.md) | `reports/monthly/YYYY-MM.md`（保持期間切れレポートの集約先） |
| [`github-actions/quiet-cve-scan.yml`](github-actions/quiet-cve-scan.yml) | 定期スキャン用のワークフロー。`.github/workflows/` にコピーして使う |

前 2 つは下記テストプロジェクトの実スキャン結果、
月次サマリーはローテーション動作確認用の合成履歴から生成したものです。

## テストプロジェクトの構成

```
fixture-app/
├── package.json / package-lock.json   # lodash 4.17.20, express 4.17.1, minimist 1.2.0, qs 6.7.0
├── backend/requirements.txt           # PyYAML 5.3, requests 2.19.1, django>=2.2.0, urllib3 1.24.1
├── php/composer.lock                  # guzzlehttp/guzzle 6.5.0, monolog 1.25.0
├── src/app.js                         # lodash と express を import。_.merge のみ使用
└── backend/loader.py                  # yaml.load(request.data) ← 実際に脆弱な使い方
```

## この例が示していること

**16 パッケージから OSV.dev が返した脆弱性は 89 件。人間に届いたのは 2 件。**

| 段階 | 件数 | 何が起きたか |
|---|---|---|
| OSV.dev の生の応答 | 151 | GHSA と PYSEC が同じ CVE を別レコードで返す |
| 重複統合後 | 89 | 同一パッケージ・同一 CVE を 1 件にまとめた |
| トリアージ後（要対応） | **2** | 実際に脆弱な機能を呼んでいるものだけ |

削られた 87 件の内訳と、その判断根拠がレポートに残る。ここが Dependabot との違い。

### 拾えたもの

`backend/loader.py:6` の `yaml.load(request.data)` — `Loader` 指定なしで
HTTP リクエストボディを渡しており、任意コード実行に直結する。
CVSS 9.8 が 2 件、**要対応**。

### 正しく捨てたもの

- **lodash CVE-2021-23337 (CVSS 8.1)** — 脆弱なのは `_.template`。
  `app.js:1` で import はしているが、使っているのは `_.merge` だけ。
  パッケージ名だけを grep していたら「使用中」と誤判定していた。
- **minimist CVE-2021-44906 (CVSS 9.8)** — 推移的依存で、CLI 引数解析のコード自体が存在しない。
  CVSS だけ見れば最優先だが、到達しない。

### 判断を保留したもの（ここが重要）

- **qs CVE-2022-24999 (CVSS 7.5)** — 直接 import は 0 件。だが `express` が
  クエリ文字列の解析に内部で `qs` を使うため、「import が無い = 到達しない」とは言えない。
  → `unknown` として**様子見**に置いた。`unused` と断定していたら誤った安心を配ることになる。
- **django (CRITICAL 7 件)** — import は 0 件だが、`requirements.txt` が
  `django>=2.2.0` というレンジ指定で実バージョンが未確定。
  バージョン推定が外れている可能性があるため引き下げない。

`unknown` を `unused` に丸めないことが、このフレームワークの設計上いちばん重要な制約。
詳しくは [SKILL.md](../SKILL.md) の Step 4 を参照。

## ignore の寿命種別の動作確認パターン

`ignore_rules.py` の検証には、fixture-app を git リポジトリにして（`git init` + 全ファイルを
1 コミット）、config に次の 3 パターンを書いて確認する。

```yaml
ignore:
  cves:
    # ① 腐らない ignore — 永久に抑制される（何度実行しても再浮上しない）
    - id: CVE-XXXX-0001
      reason: "Windows 限定の脆弱性。デプロイ先は Linux のみ"
      justification: platform_not_applicable
      expires: never

    # ② 腐る ignore — 期限内 & 根拠ファイル無変更なら抑制される
    - id: CVE-XXXX-0002
      reason: "該当機能未使用"
      justification: vulnerable_code_not_in_execute_path
      expires: "2099-12-31"
      evidence_files:
        - src/app.js
      verified_at_commit: "<git rev-parse --short HEAD の値>"

    # ③ ②と同じ形で evidence_files に backend/ を指定
```

確認手順:

1. そのまま実行 → ①②③ すべて「設定により除外」に入る（再浮上 0 件）
2. `backend/loader.py` に 1 行追記（コミット不要。作業ツリーの変更も拾う）
   → ③ だけが**期限内なのに**「根拠ファイル変更・再確認が必要」で再浮上する
3. ② の `justification` を残したまま `expires: never` に変える
   → **設定エラーで実行が停止**する（exit 1。修正例つきのメッセージが出る）
4. おまけ: `justification` を `not_a_real_value` に変える → 「justification 不正」で再浮上、
   `verified_at_commit` をでたらめにする → 警告つきでカレンダー期限のみの動作に落ちる
