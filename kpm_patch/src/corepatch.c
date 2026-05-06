/*
 * KPM CorePatch - Kernel Patch Module for Apatch/KernelSU
 * 
 * Implements signature verification bypass and downgrade protection removal.
 * Based on KernelPatch demo structure.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define LOG_TAG "CorePatch-KPM"
#define pr_fmt(fmt) LOG_TAG ": " fmt

/* --- Configuration Flags --- */
static bool cfg_downgrade = true;
static bool cfg_authcreak = true;      // Bypass digest/signature checks
static bool cfg_digestCreak = true;    // Bypass capability checks
static bool cfg_disableVerificationAgent = true;

/* --- Helper Macros for Register Manipulation --- */
#if defined(__aarch64__)
#define SET_RET(regs, val) ((regs)->regs[0] = (unsigned long)(val))
#define GET_ARG(regs, idx) ((regs)->regs[idx])
#elif defined(__x86_64__)
#define SET_RET(regs, val) ((regs)->ax = (unsigned long)(val))
#define GET_ARG(regs, idx) \
    ((idx == 0) ? (regs)->ax : \
     (idx == 1) ? (regs)->di : \
     (idx == 2) ? (regs)->si : \
     (idx == 3) ? (regs)->dx : \
     (idx == 4) ? (regs)->r10 : \
     (idx == 5) ? (regs)->r8 : (regs)->r9)
#else
#error "Unsupported architecture for CorePatch KPM"
#endif

/* --- Hook Handlers --- */

// 1. Bypass Downgrade Check
// Target: boolean checkDowngrade(...)
static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade) return 0;
    pr_info("Bypassing checkDowngrade");
    SET_RET(regs, 0); // Return false (no downgrade detected)
    return 1; // Override function execution
}

// 2. Bypass Message Digest Verification
// Target: boolean verifyMessageDigest(...)
static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing verifyMessageDigest");
    SET_RET(regs, 1); // Return true (verification success)
    return 1;
}

// 3. Bypass Jar Verification
// Target: boolean verify(...)
static int handler_pre_verify(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing StrictJarVerifier.verify");
    SET_RET(regs, 1);
    return 1;
}

// 4. Bypass Digest Equality Check
// Target: boolean isEqual(...)
static int handler_pre_isEqual(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing MessageDigest.isEqual");
    SET_RET(regs, 1); // Always equal
    return 1;
}

// 5. Bypass Minimum Signature Scheme Version
// Target: int getMinimumSignatureSchemeVersionForTargetSdk(...)
static int handler_pre_getMinSigScheme(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing getMinimumSignatureSchemeVersionForTargetSdk");
    SET_RET(regs, 0); // Return minimum version 0
    return 1;
}

// 6. Bypass Capability Check (Shared UID etc.)
// Target: boolean checkCapability(..., int type, ...)
static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak) return 0;
    
    // Argument 1 (index 1 usually for 'this' methods in some conventions, 
    // but in kernel hooks for Java methods via ART or direct native, args vary).
    // Assuming standard calling convention where first arg after 'this' (if any) is at index 0 or 1.
    // For safety, we bypass all unless specific critical types are detected.
    // In Android native hooks, often first param is the object itself.
    // Let's assume simple bypass for now as per original CorePatch logic.
    
    pr_info("Bypassing checkCapability");
    SET_RET(regs, 1);
    return 1;
}

// 7. Disable Verification Agent
// Target: boolean isVerificationEnabled(...)
static int handler_pre_isVerificationEnabled(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_disableVerificationAgent) return 0;
    pr_info("Disabling Verification Agent");
    SET_RET(regs, 0); // Return false
    return 1;
}

/* --- Kprobe Definitions --- */
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

static struct kprobe *all_kprobes[] = {
    &kp_checkDowngrade,
    &kp_verifyMessageDigest,
    &kp_verify,
    &kp_isEqual,
    &kp_getMinSigScheme,
    &kp_checkCapability,
    &kp_isVerificationEnabled,
    NULL
};

/* --- Module Init/Exit --- */
static int __init corepatch_init(void) {
    int i, ret, count = 0;
    
    pr_info("Loading CorePatch KPM...");
    pr_info("Config: downgrade=%d, authcreak=%d, digestCreak=%d", 
            cfg_downgrade, cfg_authcreak, cfg_digestCreak);

    for (i = 0; all_kprobes[i] != NULL; i++) {
        ret = register_kprobe(all_kprobes[i]);
        if (ret < 0) {
            pr_debug("Failed to register kprobe %s: %d", all_kprobes[i]->symbol_name, ret);
        } else {
            pr_debug("Registered kprobe: %s", all_kprobes[i]->symbol_name);
            count++;
        }
    }

    pr_info("CorePatch loaded. Registered %d/%d hooks.", count, i);
    return 0;
}

static void __exit corepatch_exit(void) {
    int i;
    pr_info("Unloading CorePatch KPM...");
    for (i = 0; all_kprobes[i] != NULL; i++) {
        unregister_kprobe(all_kprobes[i]);
    }
    pr_info("CorePatch unloaded.");
}

module_init(corepatch_init);
module_exit(corepatch_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Morosakubek2 (based on coderstory/CorePatch)");
MODULE_DESCRIPTION("Kernel-level CorePatch for Apatch/KernelSU");
MODULE_VERSION("1.0.0");
