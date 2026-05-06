/*
 * KPM CorePatch - Based on KernelPatch demo-syscallhook structure
 * 
 * This module implements CorePatch functionality at the kernel level.
 * It relies on the KernelPatch/Apatch loader to resolve kernel symbols
 * (like register_kprobe, pt_regs, etc.) at runtime.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#define KPM_COREPATCH_VERSION "1.0.0"
#define KPM_COREPATCH_NAME "CorePatch-KPM"

MODULE_DESCRIPTION("CorePatch functionality for KernelSU/Apatch - disables signature verification");
MODULE_AUTHOR("Based on work by coderstory");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(KPM_COREPATCH_VERSION);

/* Configuration flags */
static bool cfg_downgrade = true;
static bool cfg_authcreak = false;
static bool cfg_digestCreak = true;
static bool cfg_exactSigCheck = false;
static bool cfg_UsePreSig = false;
static bool cfg_bypassBlock = true;
static bool cfg_sharedUser = false;
static bool cfg_disableVerificationAgent = true;

/* Debug logging */
#define LOG_TAG KPM_COREPATCH_NAME
#define pr_debug_fmt(fmt, ...) pr_info(LOG_TAG ": " fmt "\n", ##__VA_ARGS__)
#define pr_error_fmt(fmt, ...) pr_err(LOG_TAG ": ERROR - " fmt "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define DBG(fmt, ...) pr_debug_fmt(fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...) do {} while(0)
#endif

#define ERR(fmt, ...) pr_error_fmt(fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) pr_info(LOG_TAG ": " fmt "\n", ##__VA_ARGS__)

/* ============================================================
 * Hook handlers
 * ============================================================ */

/* Hook for checkDowngrade method - allows app downgrades */
static struct kprobe kp_checkDowngrade = {
    .symbol_name = "checkDowngrade",
};

static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade)
        return 0;
    
    DBG("Bypassing checkDowngrade");
#if defined(__aarch64__)
    regs->regs[0] = 0;
#elif defined(__arm__)
    regs->ARM_r0 = 0;
#elif defined(__x86_64__)
    regs->ax = 0;
#elif defined(__i386__)
    regs->ax = 0;
#endif
    return 1;
}

/* Hook for verifyMessageDigest - breaks digest verification */
static struct kprobe kp_verifyMessageDigest = {
    .symbol_name = "verifyMessageDigest",
};

static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak)
        return 0;
    
    DBG("Bypassing verifyMessageDigest");
#if defined(__aarch64__)
    regs->regs[0] = 1;
#elif defined(__arm__)
    regs->ARM_r0 = 1;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 1;
#endif
    return 1;
}

/* Hook for verify method in StrictJarVerifier */
static struct kprobe kp_verify = {
    .symbol_name = "verify",
};

static int handler_pre_verify(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak)
        return 0;
    
    DBG("Bypassing verify");
#if defined(__aarch64__)
    regs->regs[0] = 1;
#elif defined(__arm__)
    regs->ARM_r0 = 1;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 1;
#endif
    return 1;
}

/* Hook for isEqual in MessageDigest */
static struct kprobe kp_isEqual = {
    .symbol_name = "isEqual",
};

static int handler_pre_isEqual(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak)
        return 0;
    
    DBG("Bypassing isEqual");
#if defined(__aarch64__)
    regs->regs[0] = 1;
#elif defined(__arm__)
    regs->ARM_r0 = 1;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 1;
#endif
    return 1;
}

/* Hook for getMinimumSignatureSchemeVersionForTargetSdk */
static struct kprobe kp_getMinSigScheme = {
    .symbol_name = "getMinimumSignatureSchemeVersionForTargetSdk",
};

static int handler_pre_getMinSigScheme(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak)
        return 0;
    
    DBG("Returning 0 for getMinimumSignatureSchemeVersionForTargetSdk");
#if defined(__aarch64__)
    regs->regs[0] = 0;
#elif defined(__arm__)
    regs->ARM_r0 = 0;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 0;
#endif
    return 1;
}

/* Hook for checkCapability in SigningDetails */
static struct kprobe kp_checkCapability = {
    .symbol_name = "checkCapability",
};

static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak)
        return 0;
    
#if defined(__aarch64__)
    int cap_type = (int)regs->regs[1];
#elif defined(__arm__)
    int cap_type = (int)regs->ARM_r1;
#elif defined(__x86_64__)
    int cap_type = (int)regs->dx;
#elif defined(__i386__)
    int cap_type = (int)regs->dx;
#endif
    
    if (cap_type == 4 || cap_type == 16) {
        DBG("Skipping PERMISSION/AUTH capability check");
        return 0;
    }
    
    DBG("Bypassing checkCapability for type %d", cap_type);
#if defined(__aarch64__)
    regs->regs[0] = 1;
#elif defined(__arm__)
    regs->ARM_r0 = 1;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 1;
#endif
    return 1;
}

/* Hook for isVerificationEnabled */
static struct kprobe kp_isVerificationEnabled = {
    .symbol_name = "isVerificationEnabled",
};

static int handler_pre_isVerificationEnabled(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_disableVerificationAgent)
        return 0;
    
    DBG("Disabling verification");
#if defined(__aarch64__)
    regs->regs[0] = 0;
#elif defined(__arm__)
    regs->ARM_r0 = 0;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 0;
#endif
    return 1;
}

/* Hook for containsAllocatedTable */
static struct kprobe kp_containsAllocatedTable = {
    .symbol_name = "containsAllocatedTable",
};

static int handler_pre_containsAllocatedTable(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak)
        return 0;
    
    DBG("Bypassing containsAllocatedTable");
#if defined(__aarch64__)
    regs->regs[0] = 0;
#elif defined(__arm__)
    regs->ARM_r0 = 0;
#elif defined(__x86_64__) || defined(__i386__)
    regs->ax = 0;
#endif
    return 1;
}

/* Array of all hooks */
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

/* Handler functions array */
static int (*handlers[])(struct kprobe *, struct pt_regs *) = {
    handler_pre_checkDowngrade,
    handler_pre_verifyMessageDigest,
    handler_pre_verify,
    handler_pre_isEqual,
    handler_pre_getMinSigScheme,
    handler_pre_checkCapability,
    handler_pre_isVerificationEnabled,
    handler_pre_containsAllocatedTable,
};

/* ============================================================
 * KPM Interface Functions
 * ============================================================ */

/* Set configuration option */
// Używamy prostego porównania znaków zamiast strcmp, aby uniknąć zależności
static int kpm_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

KPM_API int kpm_set_config(const char *key, int value) {
    if (!key) return -1; // -EINVAL
    
    if (kpm_strcmp(key, "downgrade") == 0) {
        cfg_downgrade = !!value;
        INFO("Config: downgrade = %d", cfg_downgrade);
    } else if (kpm_strcmp(key, "authcreak") == 0) {
        cfg_authcreak = !!value;
        INFO("Config: authcreak = %d", cfg_authcreak);
    } else if (kpm_strcmp(key, "digestCreak") == 0) {
        cfg_digestCreak = !!value;
        INFO("Config: digestCreak = %d", cfg_digestCreak);
    } else if (kpm_strcmp(key, "exactSigCheck") == 0) {
        cfg_exactSigCheck = !!value;
        INFO("Config: exactSigCheck = %d", cfg_exactSigCheck);
    } else if (kpm_strcmp(key, "UsePreSig") == 0) {
        cfg_UsePreSig = !!value;
        INFO("Config: UsePreSig = %d", cfg_UsePreSig);
    } else if (kpm_strcmp(key, "bypassBlock") == 0) {
        cfg_bypassBlock = !!value;
        INFO("Config: bypassBlock = %d", cfg_bypassBlock);
    } else if (kpm_strcmp(key, "sharedUser") == 0) {
        cfg_sharedUser = !!value;
        INFO("Config: sharedUser = %d", cfg_sharedUser);
    } else if (kpm_strcmp(key, "disableVerificationAgent") == 0) {
        cfg_disableVerificationAgent = !!value;
        INFO("Config: disableVerificationAgent = %d", cfg_disableVerificationAgent);
    } else {
        return -2; // -ENOENT
    }
    
    return 0;
}

/* Get configuration option */
KPM_API int kpm_get_config(const char *key) {
    if (!key) return -1;
    
    if (kpm_strcmp(key, "downgrade") == 0) return cfg_downgrade;
    if (kpm_strcmp(key, "authcreak") == 0) return cfg_authcreak;
    if (kpm_strcmp(key, "digestCreak") == 0) return cfg_digestCreak;
    if (kpm_strcmp(key, "exactSigCheck") == 0) return cfg_exactSigCheck;
    if (kpm_strcmp(key, "UsePreSig") == 0) return cfg_UsePreSig;
    if (kpm_strcmp(key, "bypassBlock") == 0) return cfg_bypassBlock;
    if (kpm_strcmp(key, "sharedUser") == 0) return cfg_sharedUser;
    if (kpm_strcmp(key, "disableVerificationAgent") == 0) return cfg_disableVerificationAgent;
    
    return -2;
}

/* Get module info */
KPM_API const char* kpm_get_info(void) {
    return KPM_COREPATCH_NAME " v" KPM_COREPATCH_VERSION;
}

/* ============================================================
 * Module Init/Exit
 * ============================================================ */

static int __init kpm_corepatch_init(void) {
    int i, ret;
    int registered = 0;
    
    INFO("Loading " KPM_COREPATCH_NAME " v" KPM_COREPATCH_VERSION);
    
    INFO("Configuration:");
    INFO("  downgrade: %d", cfg_downgrade);
    INFO("  authcreak: %d", cfg_authcreak);
    INFO("  digestCreak: %d", cfg_digestCreak);
    INFO("  exactSigCheck: %d", cfg_exactSigCheck);
    INFO("  UsePreSig: %d", cfg_UsePreSig);
    INFO("  bypassBlock: %d", cfg_bypassBlock);
    INFO("  sharedUser: %d", cfg_sharedUser);
    INFO("  disableVerificationAgent: %d", cfg_disableVerificationAgent);
    
    /* Register all kprobes */
    for (i = 0; kprobes[i] != NULL; i++) {
        kprobes[i]->pre_handler = handlers[i];
        
        ret = register_kprobe(kprobes[i]);
        if (ret < 0) {
            DBG("Failed to register kprobe for %s: %d", kprobes[i]->symbol_name, ret);
            /* Continue anyway - some symbols may not exist on all Android versions */
        } else {
            DBG("Registered kprobe for %s", kprobes[i]->symbol_name);
            registered++;
        }
    }
    
    INFO("Successfully registered %d/%d kprobes", registered, i);
    INFO(KPM_COREPATCH_NAME " loaded successfully");
    
    return 0;
}

static void __exit kpm_corepatch_exit(void) {
    int i;
    
    INFO("Unloading " KPM_COREPATCH_NAME);
    
    for (i = 0; kprobes[i] != NULL; i++) {
        unregister_kprobe(kprobes[i]);
    }
    
    INFO(KPM_COREPATCH_NAME " unloaded");
}

module_init(kpm_corepatch_init);
module_exit(kpm_corepatch_exit);
