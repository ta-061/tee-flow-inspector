# SBOM (Software Bill of Materials) Directory

## 🤔 SBOMとは？

SBOM（Software Bill of Materials：ソフトウェア部品表）は、ソフトウェアに含まれるすべてのコンポーネント（部品）をリスト化したものです。製品の「成分表示」のようなもので、どのようなライブラリやパッケージが使われているかを明確にします。

### なぜSBOMが重要？
- **セキュリティ**: 既知の脆弱性があるコンポーネントを特定できる
- **ライセンス管理**: 使用しているソフトウェアのライセンスを把握できる
- **依存関係の理解**: ソフトウェアの構成要素を可視化できる

---

## 📚 使用ツールの説明

### 🔍 SBOM生成ツール

#### **Syft（シフト）**
- **開発元**: Anchore社
- **役割**: コンテナイメージやファイルシステムからSBOMを生成
- **特徴**: 多様な形式（CycloneDX、SPDX等）でSBOM出力が可能
- **例**: `syft docker:myimage:latest` でDockerイメージをスキャン

### 📊 SBOM形式

#### **CycloneDX（サイクロンDX）**
- **特徴**: OWASP（セキュリティ団体）が推進する形式
- **利点**: セキュリティ情報に特化、機械処理しやすい
- **拡張子**: `.cdx.json`
- **用途**: セキュリティスキャンや脆弱性管理

#### **SPDX（エスピーディーエックス）**
- **特徴**: Linux Foundationが推進する業界標準
- **利点**: ライセンス情報が詳細、法的コンプライアンスに強い
- **拡張子**: `.spdx.json` または `.spdx`
- **用途**: ライセンス管理、OSS（オープンソースソフトウェア）コンプライアンス

### 🛡️ 脆弱性スキャンツール

#### **Grype（グライプ）**
- **開発元**: Anchore社（Syftと同じ）
- **役割**: SBOMやコンテナイメージの脆弱性をスキャン
- **特徴**: 高速、CVE（脆弱性データベース）と照合
- **例**: `grype docker:myimage:latest` で脆弱性チェック

#### **Trivy（トリビー）**
- **開発元**: Aqua Security社
- **役割**: 包括的なセキュリティスキャナー
- **特徴**: 脆弱性、設定ミス、シークレットなども検出
- **例**: `trivy image myimage:latest` で総合的なセキュリティチェック

---

## 📁 ディレクトリ構造（詳細説明付き）

```
SBOM/
├── 📂 01_docker_sbom/           # Dockerイメージの部品表
│   ├── cyclonedx/              # セキュリティ重視の形式
│   ├── spdx/                   # ライセンス重視の形式
│   └── summary/                # 人間が読める要約
│
├── 📂 02_source_sbom/           # ソースコードの部品表
│   └── src/                    # Pythonコードの依存関係
│
├── 📂 03_vulnerability_reports/ # 脆弱性レポート（危険度評価）
│   ├── grype/                  # Grypeの診断結果
│   └── trivy/                  # Trivyの診断結果
│
├── 📂 04_formatted_sbom/        # 整形済み（読みやすくしたもの）
└── 📂 05_original_sbom/         # オリジナル（元のまま）
```

---

## 📋 SBOM一覧（詳細説明付き）

### 1. Docker Image SBOMs（コンテナの部品表）

| ファイル | 何が分かる？ | いつ使う？ | パス |
|---------|-------------|----------|------|
| **CycloneDX 1.6** | 全コンポーネントとバージョン | セキュリティ監査時 | [📁 見る](./01_docker_sbom/cyclonedx/CycloneDX1.6-Docker-sbom-image.cdx.json) |
| **SPDX 2.3** | ライセンス情報詳細 | ライセンス確認時 | [📁 見る](./01_docker_sbom/spdx/SPDX2.3-Docker-sbom-image.spdx.json) |
| **サマリー** | 概要（人間向け） | クイック確認時 | [📁 見る](./01_docker_sbom/summary/Docker-sbom-summary.txt) |

### 2. 脆弱性レポート（セキュリティ診断結果）

#### 🔴 危険度レベルの説明
- **Critical（緊急）**: 即座に対処が必要な重大な脆弱性
- **High（高）**: 早急な対処を推奨する脆弱性
- **Medium（中）**: 計画的な対処を推奨
- **Low（低）**: リスクは低いが認識しておくべき問題

#### 📊 スキャン結果の場所

| ツール | 何を検出？ | 結果の形式 | 保存場所 |
|--------|-----------|-----------|---------|
| **Grype** | CVE脆弱性 | JSON、テキスト、SARIF | [📁 grype/](./03_vulnerability_reports/grype/) |
| **Trivy** | 脆弱性＋設定ミス | JSON、テキスト、HTML | [📁 trivy/](./03_vulnerability_reports/trivy/) |

---

## 🚀 よく使うコマンド（コピペ用）

### 基本的な使い方

#### 1️⃣ SBOMを生成する
```bash
# Dockerイメージから部品表を作る
syft docker:tee-flow-inspector:local --output cyclonedx-json > my-sbom.json
```

#### 2️⃣ 脆弱性をチェックする
```bash
# 作成したSBOMの脆弱性をチェック
grype sbom:my-sbom.json

# Critical（緊急）レベルのみ表示
grype sbom:my-sbom.json --severity critical
```

#### 3️⃣ レポートを生成する
```bash
# HTMLレポート（ブラウザで見やすい）
trivy sbom my-sbom.json --format template --template "@contrib/html.tpl" --output report.html
```

---

## 📊 このプロジェクトの統計

### 検出されたコンポーネント
- **📦 総コンポーネント数**: 21,023個
- **📚 パッケージ数**: 444個
- **⚙️ 実行可能ファイル**: 1,648個
- **📄 スキャンしたファイル**: 20,578個

### 脆弱性スキャン結果サマリー
最新のスキャン結果は [📁 SCAN_SUMMARY](./03_vulnerability_reports/SCAN_SUMMARY_*.md) をご覧ください。

---

## ❓ FAQ（よくある質問）

### Q: SBOMとは何の略ですか？
**A:** Software Bill of Materials（ソフトウェア部品表）の略です。

### Q: なぜ複数の形式（CycloneDX、SPDX）が必要なの？
**A:** それぞれ得意分野が異なります：
- **CycloneDX**: セキュリティ情報に強い
- **SPDX**: ライセンス情報に強い

### Q: GrypeとTrivyの違いは？
**A:** 両方とも脆弱性スキャナーですが：
- **Grype**: シンプルで高速、CVEに特化
- **Trivy**: より包括的、設定ミスも検出

### Q: どのくらいの頻度でスキャンすべき？
**A:** 最低でも：
- 本番デプロイ前：必須
- 定期スキャン：週1回を推奨
- 重大な脆弱性公開時：即座に

---

## 🔧 トラブルシューティング

### SBOMファイルが大きすぎる場合
```bash
# Git LFSを使用
git lfs track "*.cdx.json"
git lfs track "*.spdx.json"
```

### スキャンが遅い場合
```bash
# SBOMから直接スキャン（イメージスキャンより高速）
grype sbom:./01_docker_sbom/cyclonedx/CycloneDX1.6-Docker-sbom-image.cdx.json
```

---

## 📚 もっと学びたい方へ

### 初心者向けリソース
- [SBOMとは？（IPA解説）](https://www.ipa.go.jp/security/sbom/index.html)
- [コンテナセキュリティ入門](https://www.docker.com/blog/what-is-container-security/)

### 公式ドキュメント
- [CycloneDX 仕様書](https://cyclonedx.org/)
- [SPDX 仕様書](https://spdx.dev/)
- [Syft 使い方](https://github.com/anchore/syft)
- [Grype 使い方](https://github.com/anchore/grype)
- [Trivy 使い方](https://github.com/aquasecurity/trivy)

---

## 📝 更新履歴

| 日付 | 更新内容 | 担当 |
|------|---------|------|
| 2025-10-14 | 初回SBOM生成と脆弱性スキャン | - |
| - | 次回予定：定期スキャンの自動化 | - |

---

## ⚠️ 重要な注意事項

### 🔴 セキュリティ
- **Critical**レベルの脆弱性は**即座に対処**してください
- 本番環境へのデプロイ前は**必ずスキャン**を実行してください

### 📦 ファイルサイズ
- SBOMファイルは数十MBになることがあります
- GitHubには100MB制限があるため、大きなファイルはGit LFSを使用してください

### 🔄 更新頻度
- 脆弱性データベースは日々更新されます
- 定期的な再スキャンを推奨します（最低週1回）

---

*最終更新: 2025年10月14日*
*質問がある場合は、セキュリティチームまたはDevOpsチームにお問い合わせください。*