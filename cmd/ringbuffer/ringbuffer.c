//go:build ignore

#include "common.h"
// #include "bpf_helper_defs.h"
#include <linux/ptrace.h>

// #ifdef __x86_64__
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rax)
#define PT_REGS_RC(x) ((x)->rax)
// #endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8 comm[80];
    char input[256];  // 添加字段存储输入内容
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// 修改 SEC 声明为 uretprobe
// 修改函数名以匹配生成的代码
SEC("uretprobe/readline")
int UprobeReadline(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    struct event *task_info;
    const char *input = (const char *)PT_REGS_RC(ctx);  // 获取返回值

    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!task_info) {
        return 0;
    }

    task_info->pid = tgid;
    bpf_get_current_comm(&task_info->comm, 80);
    
    // 复制用户输入内容
    bpf_probe_read_user_str(task_info->input, sizeof(task_info->input), input);

    bpf_ringbuf_submit(task_info, 0);
    return 0;
}
