# 未確認事項

[English](../open-questions.md) | **日本語**（英語版を正とする）

推測で確定させないもの。実カード・公式資料・既存のオープンソース実装で確認できたら、根拠とともに更新する。

## 証明書の構造（実カードと照合する）

| 項目 | 現在の仮置き | 影響する場所 |
|---|---|---|
| 4情報の otherName の OID | `1.2.392.200149.8.5.5.{1 氏名, 2 氏名代替文字, 3 性別, 4 生年月日, 5 住所, 6 住所代替文字}` | `internal/mockjpki`, `circuits/src/cert.nr` の `OID_DATE_OF_BIRTH` |
| 生年月日の表現 | 西暦 `YYYYMMDD` の8桁数字。元号の接頭辞などが付く可能性は未確認 | `cert.nr`（長さ8・数字のみを要求） |
| 生年月日の文字列型 | UTF8String（回路は PrintableString も受け付ける） | `cert.nr` |
| otherName の value の包み方 | `[0] EXPLICIT` の中に文字列が1つ | `cert.nr` |
| 性別の表現 | `"1"` / `"2"`（回路は読まない） | `internal/mockjpki` |
| 拡張の種類・個数・順序 | モックは keyUsage / authorityKeyIdentifier / certificatePolicies / subjectAltName。回路はOIDで探すので順序には依存しないが、上限は12個 | `cert.nr` の `MAX_EXTENSIONS` |
| subjectAltName の要素数 | 上限10個 | `cert.nr` の `MAX_GENERAL_NAMES` |
| issuerUniqueID / subjectUniqueID | 無いものとして扱う（あれば回路は拒否する） | `cert.nr` |
| subject / issuer の内容 | モックは適当な値。回路は読まない | `internal/mockjpki` |
| TBSCertificate の長さ | 回路の上限は 2032 バイト（バッファ2048 − 余白16）。モックは約800バイト | `cert.nr` の `MAX_TBS_LEN` |
| 鍵と署名アルゴリズム | 利用者鍵・CA鍵とも RSA-2048、e=65537、sha256WithRSAEncryption (PKCS#1 v1.5) | 回路全体 |
| CAの階層 | CA鍵が利用者証明書に直接署名する1段構成を仮定。中間CAがあれば回路の拡張が必要 | `main.nr` |

## カードの署名動作（読み取りアプリに必要）

- 署名用APに渡すデータの形式（DigestInfo を渡してカードが PKCS#1 v1.5 パディングを行う、という理解は未確認）。
- APDU、ファイル構成、暗証番号の扱い。既存のオープンソース実装と公式資料で確認してから実装する。
- 署名用電子証明書による署名は法的効力を持ちうる。nonce への署名を「本人確認のための署名」として行わせてよいか、
  メッセージに含めるべき文言・ドメイン分離の妥当性は制度面の確認が必要。

## 設計上の未決事項

- **nullifier の元にする値。** 現在は利用者公開鍵。署名用電子証明書は住所・氏名の変更や更新で再発行されるため、
  そのたびに nullifier が変わる（BANの回避や重複登録が可能になる）。更新をまたいで安定な値は4情報しかないが、
  エントロピーが低く、nullifier からの総当たりで個人が特定されうる。どちらを取るかは未決。
- **証明書を持つ第三者による名寄せ。** nullifier は証明書と app_id から誰でも計算できる。証明書は署名の相手方や
  発行者が保持しているので、彼らは nullifier と本人を結びつけられる。カードの決定的な署名を秘密として
  nullifier に混ぜる案があるが、回路内のRSA検証がもう1回必要になる。
- **有効期限。** 回路は notBefore / notAfter を見ていない。
- **失効確認。** 公的個人認証の認定制度の対象のため PoC では扱わない。
- **年齢計算。** `生年月日 + 閾値×10000 <= current_date`（YYYYMMDD の整数比較）。誕生日当日から満たす扱いで、
  法律上の「誕生日の前日の終了時に加齢」とは1日ずれる（厳しい側）。2月29日生まれは平年では3月1日から満たす。
- **current_date の基準。** サーバがチャレンジ発行時の日本時間の日付を固定する。
