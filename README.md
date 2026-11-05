# AGM3-W09HN 临时 Root：CVE-2022-38181
针对 **Honor Pad 7（AGM3-W09HN）** 的 CVE-2022-38181 设备专用 PoC。它从 ADB 的 `shell` 用户上下文利用 Mali Bifrost 内核驱动，在当前启动周期内获得交互式 **UID 0 shell**。不是 Magisk，不修改启动镜像，也不提供持久化。技术摘录见 [docs/EVIDENCE.md](EVIDENCE.md)。

本项目由 **AI（Kimi K3.1 Pro）完成**，包括目标适配、排错、源码、运行脚本与文档。

> **高风险提示**：内存回收、UAF 和 Mali context teardown 均可能触发内核崩溃或设备重启。使用前必须备份重要数据。不要把设备专用偏移用于其他型号或固件。

## 支持范围

| 项目 | 已验证值 |
|---|---|
| 型号 | AGM3-W09HN / Honor Pad 7 |
| SoC / GPU | MediaTek MT6769V/CU（Helio G80）/ Mali-G52 MC2 |
| 驱动 | Bifrost r20p0-01rel0，kbase UAPI 11.17 |
| 内核 | 4.14.141+，AArch64，39-bit VA |
| 系统 | Android 10 / Magic UI 4.0 / 11.0.2.197 |
| 安全补丁 | 2022-04-01 |
| 前置条件 | 已授权 ADB，`shell` 可读写 `/dev/mali0`，bootloader 保持锁定 |
| 结果 | 当前进程及重启前的临时 root，不含持久化 |

`src/honor_agm3.c` 中的内核物理加载地址和符号偏移来自上述设备固件。脚本和二进制都会检查指纹与安全补丁；不匹配时必须停止，而不是重用偏移碰运气。

本项目不刷机、不解锁 bootloader、不修改 `/system`、`/vendor`、`boot` 或用户数据分区。设备侧仅使用 `/data/local/tmp` 下的指定二进制、压力文件和脚本生成的日志。

## 与其他 PoC 的关系和差异

基础漏洞及利用链来自公开研究，本项目不是漏洞或通用利用思想的原创者：

| 参考实现 | 已有贡献 | 本项目的不同点 |
|---|---|---|
| [GitHub Security Lab / Man Yue Mo 的 Pixel 6 PoC](https://github.com/github/securitylab/tree/main/SecurityExploits/Android/Mali/CVE_2022_38181) | JIT shrinker UAF、alias 读页表、GPU WRITE_VALUE、SELinux bypass 与 root 基础链 | 保留 AArch64 思路，但重做 AGM3 的 r20p0 UAPI、回收屏障、回收后建表和失败诊断 |
| [R0rt1z2 的 FireTV 移植](https://github.com/R0rt1z2/CVE-2022-38181) | MediaTek 时代 kbase ioctl 布局和移植参考 | 目标不是其 FireTV/32 位环境，而是 AGM3 的 AArch64、4.14 内核及 r20p0 驱动 |
| [Pro-me3us 的 Raven 移植](https://github.com/Pro-me3us/CVE_2022_38181_Raven) | 旧 Bifrost r16p0、Linux 4.9 与 32 位 FireOS 适配 | 不照搬其地址宽度或旧 ABI；按本机 UAPI 11.17 和内核镜像重新确定结构及符号 |

本项目范围内的创新和工程改进如下：

1. **分 CPU 并行 spray**：8 个绑定 CPU 的工作线程分两批执行分配和映射，解决回收页与 per-CPU slab freelist 的错配。真机日志证明，该改动使第二次 `JIT_FREE`、replacement backing 释放和后续 PGD 建表得以完成，而不是仅调整压力大小。
2. **第二次释放的严格屏障**：等待目标 softjob 的 event 并检查 `BASE_JD_EVENT_DONE`，再要求 `qrc == 0 && commit == 0`。避免把 ioctl 失败、遗留 event 或未完成的释放误判为成功。
3. **区分 map 前后候选**：`map_reserved()` 之前存在候选立即失败；之后要求 `hits >= 1` 且 entry 256 为 `0` 或 `2`，才接受 PGD。单独的幂等写入阶段先证明写原语，再允许 FULL。
4. **适配实际 UAPI 与地址语义**：区分 pending cookie 和 mmap 后的 SAME_VA 地址；JIT init 先于普通映射；使用本机 48 字节 atom、16 字节 MEM_QUERY、40 字节 JIT init 信息，并设置 `trim_level=100`。
5. **可诊断的内存压力和生命周期管理**：先读 1.5 GiB 临时文件预热 file-LRU，再以匿名页施压并保留 384 MiB `MemAvailable` 停止线。FULL 成功路径不调用 `unmap_spray()`，避免把已损坏的 GPU context 当作普通映射随意清理。
6. **由 pstore 驱动排错**：通过 `/system/bin/bugreport` 获取 `/sys/fs/pstore/console-ramoops`，把问题定位到第二次 `kbase_jit_free` 所涉及的失效 region/`jit_node` 生命周期，而非盲改 pool 参数。

详细实现以 [src/honor_agm3.c](src/honor_agm3.c) 为准

## 构建

依赖 Android NDK r27c、Android SDK platform-tools、Git Bash，以及 Bash 的 `tee`、`grep` 等常规工具。默认路径为：

```text
C:\Program Files (x86)\Android\AndroidNDK\android-ndk-r27c
C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe
```

在仓库根目录执行：

```bash
./scripts/build.sh
file build/agm3_test_work build/agm3_test_write_work build/agm3_full_work
```

三个输出均应是使用 `/system/bin/linker64` 的 Android AArch64 PIE ELF：

| 文件 | 宏 | 用途 |
|---|---|---|
| `build/agm3_test_work` | `SHELL TEST_MODE` | 验证回收和 PGD 发现，不写内核 payload |
| `build/agm3_test_write_work` | `SHELL TEST_MODE VERIFY_PGD_WRITE` | 向 entry 256 写回原值并验证 |
| `build/agm3_full_work` | `SHELL` | 执行完整提权并进入交互 shell |

可用 `CLANG`、`SYSROOT`、`ADB` 环境变量覆盖工具路径。`-pthread` 不可删除，分 CPU spray 依赖它。

## 标准 FULL 使用方案

确认只连接一台已授权设备；多设备环境可通过 ADB 标准的 `ANDROID_SERIAL` 指定目标。先阅读风险提示并确认设备空间，不要删除用户文件来腾空间。

```bash
./scripts/agm3_adb.sh check
./scripts/agm3_adb.sh pressure
./scripts/agm3_adb.sh test
./scripts/agm3_adb.sh verify
./scripts/agm3_adb.sh shell
```

1. `pressure` 只创建 `/data/local/tmp/agm3_pressure.bin`，即 1536 MiB 的临时零文件。
2. `test` 要求进程返回 0，且日志含 `PGD FOUND AFTER MAP` 和 `TEST PASSED — PGD primitive verified`。
3. `verify` 检查前一阶段日志，再要求 `IDEMPOTENT PGD WRITE VERIFIED` 和 `TEST PASSED`。
4. `shell` 检查本仓库中前两个阶段的成功日志后才推送 FULL。不要跨设备复用日志来绕过顺序。
5. TEST 和验证阶段使用设备端 `timeout 120s`；**FULL 不使用 timeout**。完整交互和 FIFO 操作见 [AGENTS.md](AGENTS.md)。

成功标志是：

```text
uid after trigger: 0 euid: 0 (0 = root)
[+] ROOT (temporary, this process only)
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

`getenforce` 报错本身不是失败判据；以真实 `id` / UID 0 为准。

**不要**给 FULL 加 `timeout`，不要用 `kill -9`、Ctrl-C 或自动清理脚本终止 root shell，也不要在 FULL 中加回 `unmap_spray()`。进程退出和 Mali context teardown 存在导致设备重启的风险；需要结束时应明确接受该风险，而不是强行杀进程。

回收失败时只以新的独立进程重试，最多约 3 次，不无限循环，不在同一进程累积 JIT 对象。失败后先采集：

```bash
./scripts/agm3_adb.sh bugreport after_test_failure
```

bugreport 可能包含应用日志、设备标识及其他私有信息，已由 `.gitignore` 排除，**不要提交或公开原始文件**。

## 故障定位

| 现象 | 处理方式 |
|---|---|
| `trial failed` | 本轮未回收；独立进程有限重试，不进入下一阶段 |
| 第二次 `JIT_FREE` 无 event、报错或 panic | 检查 slab 替换与失效 JIT 对象生命周期；采集 pstore，不盲改 FULL |
| replacement backing 未达 `commit=0` | 视为原语未建立，停止 |
| map 前已有 PGD 候选 | 候选污染，拒绝继续 |
| `PGD write verification failed` | 地址或候选错误，禁止 FULL |
| PGD 后断连或重启 | 等设备恢复，采集 bugreport/pstore，先排查 context teardown |
| `getenforce` 失败但 `id` 为 UID 0 | 不单独判为失败 |

重点检索 `list_del corruption`、`list_add corruption`、`kbase_jit_free`、`kbase_free_alloced_region`、`kbase_gpu_munmap` 和 `kbase_mem_evictable_mark_reclaim`。

## 仓库内容

```text
src/                 最终 PoC 与带原始声明的 Mali UAPI/job 头文件
scripts/build.sh     一次构建三个明确分离的阶段产物
scripts/agm3_adb.sh  设备检查、压力文件、分阶段验证、FULL 与日志采集
docs/EVIDENCE.md     真机验证技术摘录，不含完整私有日志
AGENTS.md            后续接手 agent 的标准操作及禁止事项
logs/                本地运行日志，默认不提交
```

## 许可证与致谢

新增 AGM3 专用修改、脚本和文档使用 [Apache License 2.0](LICENSE)，版权为 **Copyright 2026 lRENyaaa**。

**上游组件不因此改许可**：`mali.h` 与 `mali_base_jm_kernel.h` 保留 `GPL-2.0 WITH Linux-syscall-note` 及 Arm 声明；`midgard.h` 保留 pandecode-standalone 生成来源；各 PoC 的权利归原作者。完整出处与许可以各源文件头部为准。

感谢 Man Yue Mo / GitHub Security Lab、R0rt1z2、Pro-me3us、Arm 及 Panfrost 项目的公开研究和代码。本项目与这些厂商或作者无官方隶属或背书关系。
