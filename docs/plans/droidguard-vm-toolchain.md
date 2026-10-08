# DroidGuard 虚拟机开源工具链

目标是为 `the.apk` 里的 so 虚拟机建立和 `tiktok-rec` 的 metasec VM 相同的版本化工具，而不是在 GmsCore 里手写一份永久有效的 DroidGuard。

Java 壳是宿主 ABI。虚拟机在 so 里。指令编号被打乱时，只重做该版本的编码。Java 壳不单独开语言分支。

字节码每次请求都变。它是虚拟机执行的程序，不作为版本单位。

样本、so 和 IDB 不进 GmsCore。

## 已接入的 Cursor MCP

全局 `~/.cursor/mcp.json` 已增加与 `tiktok-rec/.cursor/mcp.json` 相同的两项：

- `ida-pro-mcp`：`/usr/bin/python3.12 /home/bluebird/git/ida-pro-mcp/src/ida_pro_mcp/server.py`，`IDADIR=/home/bluebird/ida-pro-9.2`
- `unidbg-mcp`：`uv --directory /home/bluebird/git/tiktok-rec/tools/unidbg-mcp run unidbg-mcp`

garlic 已经在同一文件里。Ghidra 不走 MCP，走版本工程的 `scripts/`。

Cursor 需要重新加载 MCP 后，本会话才能看到 `ida-pro-mcp` 和 `unidbg-mcp`。

## 工具与职责

| 工具 | 路径 | 用途 |
| --- | --- | --- |
| garlic | 已配置 | 读 `the.apk` 的 Java：`com.google.ccc.abuse.droidguard.DroidGuard` 的 `init`、`ss`、`rb`，以及 JNI |
| ida-pro-mcp | 见上 | `open_binary` 打开 so，反编译 opcode handler，记录入口、分发表、landing、宿主调用 |
| unidbg-mcp | 见上 | 单 opcode 执行。断点打在 IDA 给出的 handler。动态结果只证明当前样本路径 |
| Ghidra 工程 | 新建，结构抄 `tiktok-rec/tools/ghidra-metasec-vm-v05.02.09-alpha.3` | 版本语言、p-code、伪代码、e2e |
| Ghidra 源码依据 | `/home/bluebird/git/ghidra-upstream` | 不把反编译输出当源码 |

Ghidra 工程放在 `~/git/` 下的独立仓库，不放进 GmsCore。一个 so 的 SHA-256 一个分支。共用 p-code 机制和稳定 SLEIGH 核心。本版本的字编码、选择器、根入口和 RVA 只留在该分支。

命令沿用 metasec 的名字：`build`、`check`、`dump-pcode`、`dump-pseudo`、`explain-sleigh`、`compile-pseudo`、`run-pseudo-e2e`。e2e 链接宿主桩，用 `expected.hex` 对拍。so 只作为 dump 的输入，不当运行 oracle。

## 样本

`scripts/fetch-droidguard-vm.py` 按 `NetworkHandleProxyFactory.fetchFromServer` 向 `androidantiabuse/v1/x/create` 发 protobuf，用 `SignatureVerifier` 的公钥验签，把 `Response.content` 写成 `cache/droidguard/<vmKey>/the.apk`。同时写出 `bytecode`、`extra` 和 `the.json`。`cache/` 不入库。

请求与 `NetworkHandleProxyFactory.createRequest` 一致。`versionName` 是 `VersionUtil.versionString`，即 `20.47.14 (<buildType>-{{cl}})`。请求体里的 `versionCode` 是库的 `BuildConfig.VERSION_CODE` `204714000`。`User-Agent` 是 `DroidGuard/` 加上 `VersionUtil.versionCode`，也就是 `204714000` 再加 build type 偏移。字段包含 `hasAccount=false`。不附加 `X-Android-Package` 或证书头。flow 由调用方传入；取虚拟机本体时用 `full`。

类名是 `com.google.ccc.abuse.droidguard.DroidGuard`。so 文件名在 apk 内的 `library.txt`。记录 apk 与 so 的 SHA-256 之后再写 opcode 地址。

## 步骤

1. 重新加载 Cursor MCP。对一份 so 调用 `open_binary`，确认能反编译。对 unidbg-mcp 做一次空载发现，确认 broker 在。
2. 运行 `scripts/fetch-droidguard-vm.py`。用 garlic 列出 Java 入口。按 `library.txt` 抽出 so。
3. IDA 钉锚点并写成一张表：JNI 注册、`init`/`ss` 对应的 native、opcode 分发表、一个 handler 的 RVA、该 handler 调用的宿主函数。表是后续 agent 的唯一地址来源。
4. unidbg 只测这一个 opcode。输入是锚点表里的地址和最小寄存器或内存。输出是 `expected.hex`。
5. 建该 so 的 Ghidra 分支。只改本版本编码。`check` 与 `run-pseudo-e2e` 通过后，这一版 so 可以被宿主桩替换。
6. Java 壳写成 `host-pseudo`：JNI 方法与 `GuardCallback` 的 `a`、`b`、`c`、`d`、`e`。用户拒绝某项宿主调用加在这一层，不进 SLEIGH。
7. 再来一份新 so 时，从最新稳定分支开分支，只改受新二进制影响的文件。不把稳定核心升到未通过 e2e 的版本。

## 多 agent

主 agent 持有锚点表、验收命令和合并。子 agent 不改别人的目录。

- IDA agent：只写锚点表和 opcode 行为说明。使用 `ida-pro-mcp` 的 `open_binary`、`decompile`、`xrefs_to`。不改 Ghidra，不跑 unidbg。
- unidbg agent：只在锚点表交付后写单 opcode 测试和 `expected.hex`。使用 `unidbg-mcp`。不改 SLEIGH。
- Ghidra agent：只改本版本 `encoding/`、`roots/` 和对应测试。不改稳定核心，除非 e2e 证明核心语义错。不手写 Ghidra classpath，不改生成的 `*.sla`。
- Java agent：与 IDA agent 并行。只用 garlic 写宿主 ABI 和 `host-pseudo`。不改 so 的语言定义。

IDA 与 Java 可同时开始。unidbg 等待锚点表。Ghidra 等待锚点表，并在 unidbg 的 `expected.hex` 之后才把该 opcode 标成通过。两个 agent 不写同一版本的 `encoding/`。
