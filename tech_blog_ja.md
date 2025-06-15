## はじめに

Amazon CloudWatch Agentは、CPU、メモリ、ディスクなどの基本的なメトリクスやログファイルをEC2システムから収集するのに役立ちます。しかし、カーネル内の機密な動作を監視することはできません - 例えば：

- プロセスが`/etc/shadow`ファイルにアクセスしようとしている？
- コンテナが不明なIPに外部データを送信している？
- `sudo`プロセスによって`usermod`コマンドが実行されている？

これらのイベントはCloudWatchログには記録されません。では、解決策は何でしょうか？

## eBPFから学んだこと

私は**AWS EC2でカーネルを直接監視する**ためのeBPFプログラムを実装しました。この記事では、その結果とデータに「圧倒されない」ための最適化方法を共有します。

## 目標

- CloudWatch Agentがサポートしていないカーネル内の機密活動を観察する。
- 「重要な」データのみを受信し、ノイズを減らして効率を向上させるための最適化。
- eBPF深く理解。

##  全体アーキテクチャ
eBPF + Golang アーキテクチャ

![676afdf808ad153ee0124f4b_66c727d8c0a238c1cd321109_YXNzZXRzL2FydGljbGUvZWJwZi5wbmc%3D.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/4068434/5cccf8cb-66d7-4147-bc70-092d355ba752.png)


```text
[eBPFプログラム (C)] --> [Perfバッファ] --> [Goエージェント] --> [コンソールまたはCloudWatch Logs]
```

- eBPFプログラムはCで書かれ、`openat`、`execve`、`connect`、`sendto`の`syscalls`にアタッチされます。
- データはperfイベントバッファを通じてユーザー空間に転送されます。
- Goエージェントがこのバッファーを読み取り、出力するか他の場所に送信します。


## 今回の監視対象

### 1. **重要ファイルのオープン**

`openat()`をトレースし、機密ファイルでフィルタリング：

```c
const char *critical_files[] = {
    "/etc/shadow",
    "/etc/sudoers",
    "/home/ec2-user/.ssh/authorized_keys",
    ...
};
```

→ これらのファイルへのアクセスはすべてアラートを生成します。

### 2. **危険なコマンド**

`execve()`をトレースし、以下のみをフィルタリング：

- `/usr/sbin/useradd`
- `/usr/bin/passwd`
- `/usr/bin/sudo`
- `/usr/bin/su`

→ ユーザー/グループ操作の動作を検出するのに役立ちます。

### 3. **外部接続**

`connect()`と`sendto()`をトレース：

- 外部IPアドレス（AWS内部ではない）でフィルタリング。
- 以下のようなAWSでよく見られるIPを除外：
  - `169.254.169.254`（Instance Metadata Service）
  - `10.0.0.0/8`
  - `13.112.0.0/14`、`3.114.0.0/16`などの東京リージョンのIPレンジ

```c
if (exclude_ip(ip)) return 0;
```

→ 疑わしい外部への接続のみを報告します。


## 出力結果例

Goエージェントからの出力例：ほぼリアルタイムでコンソルで結果表示されている

![Screenshot 2025-06-15 at 17.15.52.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/4068434/4e6e852c-bc87-4663-88c0-8397e9ebb952.png)

```bash
🚨 SENSITIVE: PID=18293 UID=1007 USER=ebpfuser COMM=bash OP=exec FILE=/usr/bin/sudo
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d
🚨 SENSITIVE: PID=18293 UID=0 USER=root COMM=sudo OP=open FILE=/etc/sudoers.d/90-cloud-init-users
🚨 SENSITIVE: PID=18294 UID=0 USER=root COMM=unix_chkpwd OP=open FILE=/etc/shadow
🌐 EXTERNAL: PID=18296 UID=0 USER=root COMM=curl OP=conn DST=172.217.161.46:0
🌐 EXTERNAL: PID=18296 UID=0 USER=root COMM=curl OP=conn DST=172.217.161.46:0
```

→ Promtail、Fluent Bit、またはCloudWatch Logsに直接送信してダッシュボードを作成したりアラームを設定したりするのが非常に役に立ちます。

## こだわるポイント

### `exclude_ip()`の使用

メタデータサービス、AWS内部IPからのノイズを削減。（AWS EC2利用のでメタデータ情報習得が多くて、結果がノイズがおかった）

### `is_sensitive_file()`の使用

すべてのファイルに対してイベントを送信することを避け、本当に機密な場合のみ送信。

### `BPF_MAP_TYPE_PERCPU_ARRAY`の使用

大きな`event_t`構造体を保存するためにマップを使用してスタック圧迫を軽減。

## ソースコード

### eBPF C：

https://github.com/phandinhloccb/monitor-aws-ec2-by-ebpf/blob/main/sensitive_monitor.bpf.c

### Goエージェント：

https://github.com/phandinhloccb/monitor-aws-ec2-by-ebpf/blob/main/main.go

## 他の手法との比較
他に方法もあるでので、いかに比較する

| ソリューション      | 利点                                                                                                               | 制限                                                                                                 |
| ----------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **eBPF**          | - リアルタイム、カーネル内で実行<br>- ベリファイアによる安全性チェック<br>- カーネル変更不要<br>- 柔軟、カスタムコード | - カーネルの深い理解が必要<br>- まだ広く普及していない                                                |
| **カーネルモジュール** | - 完全な権限、絶対的な力<br>- 深い介入が容易                                                                        | - 高リスク（カーネルクラッシュ）<br>- ベリファイアによるエラーチェックなし<br>- カーネルバージョン間の非互換性 |
| **Datadog Agent** | - 使いやすい、ダッシュボード付き<br>- ログ/メトリクス統合済み                                                        | - 外部へのログ送信が必要<br>- カーネルレベルの深い動作を監視できない                                    |

**eBPFは優れたバランス**：

- eBPF Verifierによるエラーチェックのおかげで、カーネルモジュールより**安全**。
- Datadogのようにすべてのログを外部に送信する必要がなく、**プライベート＆リアルタイム**。


## なぜeBPFが「安全」とみなされるのか？

eBPFがカーネルモジュールの作成と比較して注目される理由の一つは、各eBPFプログラムがカーネルにロードされる前に、Verifierと呼ばれる厳格なチェッカーを通過する必要があることです。

### eBPF Verifierとは？

Verifierは、以下を行うカーネル内のメカニズムです：

- 実行が許可される前にすべてのeBPFバイトコードを分析。
- 以下の条件をチェック：
  - 無限ループがない。
  - 許可された範囲外のメモリアクセスを回避。
  - プログラムの制御フロー論理をチェック。
  - 間違ったポインタの使用や禁止されたsyscallsを使用しない。

Verifierは、割り当てられていないメモリ領域へのアクセス、NULLポインタ、無限ループ、または危険な操作などのエラーを検出した場合、**カーネルにロードしようとした時点でプログラムを拒否します**。

これは、eBPFの特別な設計に基づいています — eBPFプログラムは、カーネルモジュールのように直接実行される機械語ではなく、実行前にカーネルによって徹底的に分析されるバイトコードとして実行されます。Verifierは、eBPFを実行する際のカーネルの安全性と安定性を保証するコンポーネントです。

### Verifierからの明確な利点

| 機能                                  | カーネルモジュール  | eBPF                 |
| ------------------------------------ | ------------------- | --------------------- |
| 実行前の静的チェック                  | ❌                   | ✅                     |
| 危険なメモリアクセスの防止            | ❌                   | ✅                     |
| システム全体のクラッシュからの保護    | ❌                   | ✅                     |
| 非rootユーザーの使用許可              | ❌                   | ✅（適切に設定された場合） |


### 私のプログラムでの例

以下のコードでは、特定のコマンドのみで`execve()`をフィルタリングしています：

```c
if (__builtin_memcmp(data->filename, "/usr/bin/passwd", 17) == 0) {
    bpf_perf_event_output(...);
}
```

間違って書いた場合（例：初期化されていないメモリ領域へのアクセス、またはNULLポインタのデリファレンス）、**verifierはプログラムを拒否し、即座にエラーを報告します**。従来のモジュールのようにカーネルクラッシュを引き起こすことはありません。

---

### なぜカーネルモジュールの作成はクラッシュしやすいのか？

カーネルモジュールは、Linux カーネルに機能を追加する「従来の」方法です。しかし、**カーネル空間で完全な権限で実行される**ため、小さなエラーでもシステム全体がクラッシュする可能性があります。

#### 具体例：

カーネルモジュール内の間違ったコードがシステム全体をクラッシュさせる可能性があります：

```c
char *ptr = NULL;
printk(KERN_INFO "Data: %s\n", ptr);  // NULLポインタのデリファレンス
```

→ このモジュールがロードされると、`NULL`ポインタのデリファレンスによりカーネルパニックが発生します。
#### カーネルパニックが発生の場合：
SSHから強制切断されました。
再接続しようとしてもpingもSSHもできません。
しかし、AWSが自動的にインスタンスを再起動します。
![Screenshot 2025-06-15 at 22.54.25.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/4068434/7dd7909b-50d8-41f0-bcbc-c49ddd81fb1f.png)


## 結論

EC2を観察するためのeBPFの実装により、以下を達成できました：

- 外部エージェントなしでカーネルレベルの動作を検出。
- スマートフィルターによる偽陽性の削減。
- システムの実際の動作をより深く理解。


## 参考資料

- [eBPF Official](https://ebpf.io/)
- [bcc-tools](https://github.com/iovisor/bcc)
- [Cilium eBPF Examples](https://github.com/cilium/ebpf)
- [AWS CloudWatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html)
- [Verifier](https://docs.kernel.org/bpf/verifier.html)
