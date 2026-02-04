---
title: インストール
---

# インストール

## go installを使用（推奨）

InfraGuardをインストールする最も簡単な方法は、`go install`を使用することです：

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

これにより、`infraguard`バイナリが`$GOPATH/bin`ディレクトリ（または`GOPATH`が設定されていない場合は`$HOME/go/bin`）にダウンロード、コンパイル、インストールされます。

GoのbinディレクトリがPATHにあることを確認してください：

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### インストールの確認

```bash
infraguard version
```

バージョン情報が表示されるはずです。

## プリコンパイル済みバイナリのダウンロード

[GitHub Releases](https://github.com/aliyun/infraguard/releases)からプリコンパイル済みバイナリをダウンロードできます。

### 利用可能なプラットフォーム

| プラットフォーム | アーキテクチャ | ファイル名 |
|----------------|--------------|-----------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### インストール手順

1. [Releasesページ](https://github.com/aliyun/infraguard/releases)からプラットフォームに適したバイナリをダウンロードします

2. バイナリを実行可能にします（Linux/macOS）：

```bash
chmod +x infraguard-*
```

3. PATH内のディレクトリに移動します：

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# またはユーザーのみのインストールの場合
mv infraguard-* ~/bin/infraguard
```

4. インストールを確認します：

```bash
infraguard version
```

## ソースからビルド（オプション）

コードを変更する必要がある場合、またはソースからビルドすることを好む場合：

### 前提条件

- **Go 1.24.6以降**
- **Git**
- **Make**

### 手順

```bash
# リポジトリをクローン
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# バイナリをビルド
make build

# オプションでPATHにインストール
sudo cp infraguard /usr/local/bin/
```

## 次のステップ

InfraGuardがインストールされたので、[クイックスタートガイド](./quick-start)に進んで、使用方法を学びましょう。
