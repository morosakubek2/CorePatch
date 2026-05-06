// SPDX-License-Identifier: GPL-2.0-only
/*
 * KPM CorePatch - Kernel Patch Module for Apatch/KernelSU
 * 
 * Implements CorePatch functionality at the kernel level using kprobes.
 * Based on the original CorePatch by coderstory and KernelPatch demo examples.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#define LOG_TAG "CorePatch-KPM"
#define pr_fmt(fmt) LOG_TAG ": " fmt

/* Configuration flags */
static bool cfg_downgrade = true;
static bool cfg_authcreak = true;
static bool cfg_digestCreak = true;
static bool cfg_disableVerificationAgent = true;

/* Architecture-specific register access macros */
#if defined(__aarch64__)
#define SET_RET(regs, val) ((regs)->regs[0] = (unsigned long)(val))
#elif defined(__x86_64__)
#define SET_RET(regs, val) ((regs)->ax = (unsigned long)(val))
#elif defined(__arm__)
#define SET_RET(regs, val) ((regs)->ARM_r0 = (unsigned long)(val))
#else
#error "Unsupported architecture for CorePatch KPM"
#endif

/* Hook Handlers */

static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade) return 0;
    pr_info("Bypassing checkDowngrade");
    SET_RET(regs, 0); 
    return 1;
}

static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing verifyMessageDigest");
    SET_RET(regs, 1); 
    return 1;
}

static int handler_pre_verify(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing StrictJarVerifier.verify");
    SET_RET(regs, 1);
    return 1;
}

static int handler_pre_isEqual(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing MessageDigest.isEqual");
    SET_RET(regs, 1);
    return 1;
}

static int handler_pre_getMinSigScheme(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    pr_info("Bypassing getMinimumSignatureSchemeVersionForTargetSdk");
    SET_RET(regs, 0); 
    return 1;
}

static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak) return 0;
    pr_info("Bypassing checkCapability");
    SET_RET(regs, 1);
    return 1;
}

static int handler_pre_isVerificationEnabled(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_disableVerificationAgent) return 0;
    pr_info("Disabling Verification Agent");
    SET_RET(regs, 0); 
    return 1;
}

/* Kprobe Definitions */
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

/* Module Init/Exit */
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
