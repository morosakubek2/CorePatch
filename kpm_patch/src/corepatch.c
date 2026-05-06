/*
 * KPM CorePatch - Kernel Patch Module for Apatch/KernelSU
 * 
 * Implements CorePatch functionality at the kernel level using kprobes.
 * Based on the original CorePatch by coderstory and splfix-kpm structure.
 *
 * License: GPL v2
 */

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * Minimalist Kernel Types & Structures Definitions
 * (Replaces missing linux/*.h headers for freestanding build)
 * ============================================================ */

typedef int bool;
#define true 1
#define false 0
#define NULL ((void *)0)
#define EINVAL 22
#define ENOENT 2

/* Architecture specific register structures */
#if defined(__aarch64__)
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#define REG_RET regs[0]
#elif defined(__arm__)
struct pt_regs {
    unsigned long uregs[18];
};
#define REG_RET uregs[0]
#elif defined(__x86_64__)
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx;
    unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    unsigned long rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, cs;
};
#define REG_RET rax
#elif defined(__i386__)
struct pt_regs {
    unsigned long ebx, ecx, edx, esi, edi, ebp, eax;
    unsigned short ds, __ds, es, __es;
    unsigned short ss, __ss;
    unsigned long eip, cs, eflags, esp;
};
#define REG_RET eax
#else
#error "Unsupported architecture"
#endif

/* Kprobe structure definition (simplified) */
struct kprobe {
    const char *symbol_name;
    void *addr;
    int (*pre_handler)(struct kprobe *, struct pt_regs *);
    void *post_handler;
    void *fault_handler;
    void *data;
};

/* External functions provided by KPM loader / Kernel */
extern int printk(const char *fmt, ...);
extern int register_kprobe(struct kprobe *kp);
extern void unregister_kprobe(struct kprobe *kp);

/* ============================================================
 * Helper Functions (Replacing libc/kernel helpers)
 * ============================================================ */

static int kpm_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

/* Mock function for Android version detection */
static int kpm_get_android_version(void) {
    return 13; /* Default to Android 13 if detection fails */
}

/* ============================================================
 * Module Configuration
 * ============================================================ */

#define KPM_COREPATCH_VERSION "1.0.0"
#define KPM_COREPATCH_NAME "CorePatch-KPM"

static bool cfg_downgrade = true;
static bool cfg_authcreak = false;
static bool cfg_digestCreak = true;
static bool cfg_exactSigCheck = false;
static bool cfg_UsePreSig = false;
static bool cfg_bypassBlock = true;
static bool cfg_sharedUser = false;
static bool cfg_disableVerificationAgent = true;

/* Logging macros */
#define LOG_TAG KPM_COREPATCH_NAME
#define pr_info(fmt, ...) printk("[INFO] " LOG_TAG ": " fmt "\n", ##__VA_ARGS__)
#define pr_err(fmt, ...) printk("[ERROR] " LOG_TAG ": " fmt "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define DBG(fmt, ...) pr_info("DEBUG: " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) do {} while(0)
#endif

/* ============================================================
 * Hook Handlers
 * ============================================================ */

/* 1. checkDowngrade - Allow downgrades */
static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade) return 0;
    DBG("Bypassing checkDowngrade");
    regs->REG_RET = 0; /* Return false/success depending on impl */
    return 1;
}

/* 2. verifyMessageDigest - Break digest verification */
static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing verifyMessageDigest");
    regs->REG_RET = 1; /* Return true */
    return 1;
}

/* 3. verify (StrictJarVerifier) */
static int handler_pre_verify(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing StrictJarVerifier.verify");
    regs->REG_RET = 1;
    return 1;
}

/* 4. isEqual (MessageDigest) */
static int handler_pre_isEqual(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing MessageDigest.isEqual");
    regs->REG_RET = 1;
    return 1;
}

/* 5. getMinimumSignatureSchemeVersionForTargetSdk */
static int handler_pre_getMinSigScheme(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Returning 0 for getMinimumSignatureSchemeVersionForTargetSdk");
    regs->REG_RET = 0;
    return 1;
}

/* 6. checkCapability (SigningDetails) */
static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak) return 0;
    
    /* Check capability type argument (usually 2nd arg, index 1) */
    #if defined(__aarch64__) || defined(__arm__)
    int cap_type = (int)regs->regs[1];
    #elif defined(__x86_64__)
    int cap_type = (int)regs->rdi; /* 1st arg in x64 is rdi, but let's assume standard calling conv */
    /* Note: In ARM64 args are regs[0], regs[1]... In x64 it's rdi, rsi... 
       Adjust based on actual calling convention of target function */
    #elif defined(__i386__)
    int cap_type = (int)regs->edx; 
    #endif
    
    /* Skip PERMISSION (4) and AUTH (16) checks if needed, or bypass all */
    if (cap_type == 4 || cap_type == 16) {
        DBG("Skipping PERMISSION/AUTH capability check");
        return 0;
    }
    
    DBG("Bypassing checkCapability for type %d", cap_type);
    regs->REG_RET = 1;
    return 1;
}

/* 7. isVerificationEnabled */
static int handler_pre_isVerificationEnabled(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_disableVerificationAgent) return 0;
    DBG("Disabling verification agent");
    regs->REG_RET = 0;
    return 1;
}

/* 8. containsAllocatedTable */
static int handler_pre_containsAllocatedTable(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    DBG("Bypassing containsAllocatedTable");
    regs->REG_RET = 0;
    return 1;
}

/* Array of hooks */
static struct kprobe kprobes[] = {
    { .symbol_name = "checkDowngrade", .pre_handler = handler_pre_checkDowngrade },
    { .symbol_name = "verifyMessageDigest", .pre_handler = handler_pre_verifyMessageDigest },
    { .symbol_name = "verify", .pre_handler = handler_pre_verify },
    { .symbol_name = "isEqual", .pre_handler = handler_pre_isEqual },
    { .symbol_name = "getMinimumSignatureSchemeVersionForTargetSdk", .pre_handler = handler_pre_getMinSigScheme },
    { .symbol_name = "checkCapability", .pre_handler = handler_pre_checkCapability },
    { .symbol_name = "isVerificationEnabled", .pre_handler = handler_pre_isVerificationEnabled },
    { .symbol_name = "containsAllocatedTable", .pre_handler = handler_pre_containsAllocatedTable },
    { .symbol_name = NULL } /* Sentinel */
};

/* ============================================================
 * KPM Entry Points
 * ============================================================ */

static int __init kpm_corepatch_init(void) {
    int i, ret, registered = 0;
    int total_hooks = sizeof(kprobes) / sizeof(kprobes[0]) - 1;

    pr_info("Loading " KPM_COREPATCH_NAME " v" KPM_COREPATCH_VERSION);
    pr_info("Detected Android version: %d", kpm_get_android_version());

    pr_info("Configuration: downgrade=%d, authcreak=%d, digestCreak=%d", 
            cfg_downgrade, cfg_authcreak, cfg_digestCreak);

    for (i = 0; i < total_hooks; i++) {
        ret = register_kprobe(&kprobes[i]);
        if (ret < 0) {
            DBG("Failed to hook %s: %d", kprobes[i].symbol_name, ret);
        } else {
            DBG("Hooked %s", kprobes[i].symbol_name);
            registered++;
        }
    }

    pr_info("Successfully registered %d/%d hooks", registered, total_hooks);
    return 0;
}

static void __exit kpm_corepatch_exit(void) {
    int i;
    pr_info("Unloading " KPM_COREPATCH_NAME);
    for (i = 0; kprobes[i].symbol_name != NULL; i++) {
        unregister_kprobe(&kprobes[i]);
    }
    pr_info("Module unloaded");
}

/* ============================================================
 * KPM Configuration API (Optional runtime config)
 * ============================================================ */

int kpm_set_config(const char *key, int value) {
    if (!key) return -EINVAL;
    
    if (kpm_strcmp(key, "downgrade") == 0) cfg_downgrade = !!value;
    else if (kpm_strcmp(key, "authcreak") == 0) cfg_authcreak = !!value;
    else if (kpm_strcmp(key, "digestCreak") == 0) cfg_digestCreak = !!value;
    else if (kpm_strcmp(key, "disableVerificationAgent") == 0) cfg_disableVerificationAgent = !!value;
    else return -ENOENT;

    pr_info("Config updated: %s = %d", key, value);
    return 0;
}

/* Export symbols for KPM loader if needed */
/* In a real KPM, these might be auto-exported by the build system */
