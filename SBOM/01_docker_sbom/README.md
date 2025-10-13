# Docker Image SBOMs

このディレクトリには、`tee-flow-inspector:local` DockerイメージのSBOMが含まれています。

## ファイル構造

- `cyclonedx/` - CycloneDX形式のSBOM
- `spdx/` - SPDX形式のSBOM
- `syft/` - Syft独自形式のSBOM
- `summary/` - テキスト形式のサマリー

## 生成コマンド

```bash
syft docker:tee-flow-inspector:local --output cyclonedx-json@1.6=CycloneDX1.6-Docker-sbom-image.cdx.json
```
