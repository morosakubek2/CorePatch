/*
 * KPM CorePatch - Based on splfix-kpm structure
 * Implements CorePatch functionality via kprobes
 */

#include <stdint.h>
#include <stddef.h>

/* --- Minimal Definitions (Self-Contained like splfix-kpm) --- */

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef unsigned long size_t;
typedef int pid_t;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int bool;
#define true 1
#define false 0

/* Architecture specific register definitions */
#if defined(__aarch64__)
struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};
#define REG_RET regs[0]
#elif defined(__arm__)
struct pt_regs {
    u32 uregs[18];
};
#define REG_RET uregs[0]
#elif defined(__x86_64__)
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10;
    unsigned long r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    unsigned long rip, cs, eflags, rsp, ss, fs_base, gs_base;
};
#define REG_RET rax
#elif defined(__i386__)
struct pt_regs {
    unsigned long ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs;
    unsigned long orig_eax, eip, xcs, eflags, esp, xss;
};
#define REG_RET eax
#else
#error "Unsupported architecture"
#endif

/* KProbe structure definition (simplified) */
struct kprobe {
    const char *symbol_name;
    void *addr;
    int (*pre_handler)(struct kprobe *, struct pt_regs *);
    void *post_handler;
    void *fault_handler;
    void *data;
};

/* External kernel functions (imported by loader) */
extern int register_kprobe(struct kprobe *kp);
extern void unregister_kprobe(struct kprobe *kp);
extern int printk(const char *fmt, ...);
extern int strcmp(const char *cs, const char *ct);

/* --- Configuration --- */
static bool cfg_downgrade = true;
static bool cfg_authcreak = true; // Domyślnie włączone dla lepszej kompatybilności
static bool cfg_digestCreak = true;

/* --- Logging --- */
#define LOG_TAG "CorePatch-KPM"
#define INFO(fmt, ...) printk(LOG_TAG ": " fmt "\n", ##__VA_ARGS__)
#define DBG(fmt, ...) printk(LOG_TAG ": [DBG] " fmt "\n", ##__VA_ARGS__)

/* --- Hook Handlers --- */

static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade) return 0;
    DBG("Bypassing checkDowngrade");
    regs->REG_RET = 0; /* Return success/false depending on context, usually 0 means no error or skip check */
    return 1; /* Skip original function */
}

static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing verifyMessageDigest");
    regs->REG_RET = 1; /* Return true (success) */
    return 1;
}

static int handler_pre_verify(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing verify");
    regs->REG_RET = 1;
    return 1;
}

static int handler_pre_isEqual(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing isEqual");
    regs->REG_RET = 1;
    return 1;
}

static int handler_pre_getMinSigScheme(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing getMinimumSignatureSchemeVersionForTargetSdk");
    regs->REG_RET = 0;
    return 1;
}

static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak) return 0;
    
    /* Check capability type argument (usually 2nd arg, index 1) */
    #if defined(__aarch64__)
    int cap_type = (int)regs->regs[1];
    #elif defined(__arm__)
    int cap_type = (int)regs->uregs[1];
    #elif defined(__x86_64__)
    int cap_type = (int)regs->rdi; /* 1st arg in x64 is rdi, wait, capability is usually 2nd? Depends on signature. Assuming standard hook logic */
    /* For safety in this generic example, we bypass all if enabled */
    #endif
    
    DBG("Bypassing checkCapability");
    regs->REG_RET = 1;
    return 1;
}

static int handler_pre_isVerificationEnabled(struct kprobe *p, struct pt_regs *regs) {
    DBG("Disabling verification agent");
    regs->REG_RET = 0; /* False */
    return 1;
}

static int handler_pre_containsAllocatedTable(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing containsAllocatedTable");
    regs->REG_RET = 0;
    return 1;
}

/* --- Hooks Table --- */
static struct kprobe kp_checkDowngrade = {
    .symbol_name = "checkDowngrade",
    .pre_handler = handler_pre_checkDowngrade,
};

static struct kprobe kp_verifyMessageDigest = {
    .symbol_name = "verifyMessageDigest",
    .pre_handler = handler_pre_verifyMessageDigest,
};

static struct kprobe kp_verify = {
    .symbol_name = "verify",
    .pre_handler = handler_pre_verify,
};

static struct kprobe kp_isEqual = {
    .symbol_name = "isEqual",
    .pre_handler = handler_pre_isEqual,
};

static struct kprobe kp_getMinSigScheme = {
    .symbol_name = "getMinimumSignatureSchemeVersionForTargetSdk",
    .pre_handler = handler_pre_getMinSigScheme,
};

static struct kprobe kp_checkCapability = {
    .symbol_name = "checkCapability",
    .pre_handler = handler_pre_checkCapability,
};

static struct kprobe kp_isVerificationEnabled = {
    .symbol_name = "isVerificationEnabled",
    .pre_handler = handler_pre_isVerificationEnabled,
};

static struct kprobe kp_containsAllocatedTable = {
    .symbol_name = "containsAllocatedTable",
    .pre_handler = handler_pre_containsAllocatedTable,
};

static struct kprobe *kprobes[] = {
    &kp_checkDowngrade,
    &kp_verifyMessageDigest,
    &kp_verify,
    &kp_isEqual,
    &kp_getMinSigScheme,
    &kp_checkCapability,
    &kp_isVerificationEnabled,
    &kp_containsAllocatedTable,
    NULL
};

/* --- Module Entry/Exit --- */

static int __init corepatch_init(void) {
    int i, ret, registered = 0;
    
    INFO("Loading CorePatch-KPM v1.0.0");
    INFO("Configuration: downgrade=%d, authcreak=%d, digestCreak=%d", 
         cfg_downgrade, cfg_authcreak, cfg_digestCreak);

    for (i = 0; kprobes[i] != NULL; i++) {
        ret = register_kprobe(kprobes[i]);
        if (ret < 0) {
            DBG("Failed to hook %s (%d)", kprobes[i]->symbol_name, ret);
        } else {
            DBG("Hooked %s", kprobes[i]->symbol_name);
            registered++;
        }
    }
    
    INFO("Registered %d/%d hooks", registered, i);
    return 0;
}

static void __exit corepatch_exit(void) {
    int i;
    INFO("Unloading CorePatch-KPM");
    for (i = 0; kprobes[i] != NULL; i++) {
        unregister_kprobe(kprobes[i]);
    }
}

/* KPM Entry Point Definition (Standard for KernelPatch) */
/* The loader looks for this specific section/symbol or uses init/exit if defined in ELF */
/* For simple KPMs like splfix, often just having init/exit and correct ELF structure is enough */
/* We define the module info struct manually if needed, but standard GCC attributes often work with Apatch loader */

/* Explicit KPM Mod Structure (Optional but recommended for clarity) */
__attribute__((section(".kp_mod"), used))
const struct {
    const char *name;
    const char *description;
    const char *author;
    int (*init)(void);
    void (*exit)(void);
} kp_mod_info = {
    .name = "CorePatch",
    .description = "Bypass signature verification and downgrades",
    .author = "Morosakubek2",
    .init = corepatch_init,
    .exit = corepatch_exit,
};

/* Override default entry points if the loader expects specific names */
int kpm_main(void) __attribute__((alias("corepatch_init")));
