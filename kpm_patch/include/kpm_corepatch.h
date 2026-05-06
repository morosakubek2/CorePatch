/*
 * KPM Header File - Kernel Patch Module definitions for CorePatch
 * 
 * This file contains the necessary definitions and structures
 * for building KPM modules compatible with KernelSU and Apatch.
 */

#ifndef __KPM_COREPATCH_H__
#define __KPM_COREPATCH_H__

#include <linux/types.h>
#include <linux/version.h>

/* KPM API version */
#define KPM_API_VERSION 1

/* KPM API macro for exported functions */
#ifdef MODULE
#define KPM_API __attribute__((visibility("default")))
#else
#define KPM_API
#endif

/* KPM configuration commands */
#define KPM_CMD_SET_CONFIG    0x01
#define KPM_CMD_GET_CONFIG    0x02
#define KPM_CMD_GET_INFO      0x03

/* Maximum config key length */
#define KPM_MAX_KEY_LEN       64

/* Android version constants */
#define ANDROID_Q             29
#define ANDROID_R             30
#define ANDROID_S             31
#define ANDROID_S_V2          32
#define ANDROID_T             33
#define ANDROID_U             34
#define ANDROID_V             35
#define ANDROID_BAKLAVA       36

/* Signature capability constants */
#define SIGNING_CAP_PERMISSION    4
#define SIGNING_CAP_AUTH          16

/* Installation error codes */
#define INSTALL_FAILED_VERSION_DOWNGRADE  -103
#define INSTALL_PARSE_ERROR_BAD_SIGNATURE -103

/* Configuration structure */
struct kpm_config {
    int downgrade;
    int authcreak;
    int digestCreak;
    int exactSigCheck;
    int UsePreSig;
    int bypassBlock;
    int sharedUser;
    int disableVerificationAgent;
};

/* Default configuration */
static inline void kpm_config_defaults(struct kpm_config *cfg) {
    if (!cfg) return;
    
    cfg->downgrade = 1;
    cfg->authcreak = 0;
    cfg->digestCreak = 1;
    cfg->exactSigCheck = 0;
    cfg->UsePreSig = 0;
    cfg->bypassBlock = 1;
    cfg->sharedUser = 0;
    cfg->disableVerificationAgent = 1;
}

/* KPM module registration macro */
#define KPM_MODULE_REGISTER(name, version, init_fn, exit_fn) \
    static const struct kpm_module_info __kpm_info \
    __attribute__((section(".kpm_info"), used)) = { \
        .name = name, \
        .version = version, \
        .init = init_fn, \
        .exit = exit_fn, \
        .api_version = KPM_API_VERSION, \
    }

/* KPM module info structure */
struct kpm_module_info {
    const char *name;
    const char *version;
    int (*init)(void);
    void (*exit)(void);
    int api_version;
};

/* Helper macros for architecture-specific register access */
#if defined(__aarch64__)
#define ARCH_RET_REG regs[0]
#define ARCH_ARG1_REG regs[0]
#define ARCH_ARG2_REG regs[1]
#define ARCH_ARG3_REG regs[2]
#elif defined(__arm__)
#define ARCH_RET_REG uregs[0]
#define ARCH_ARG1_REG uregs[0]
#define ARCH_ARG2_REG uregs[1]
#define ARCH_ARG3_REG uregs[2]
#elif defined(__x86_64__)
#define ARCH_RET_REG ax
#define ARCH_ARG1_REG di
#define ARCH_ARG2_REG si
#define ARCH_ARG3_REG dx
#elif defined(__i386__)
#define ARCH_RET_REG ax
#define ARCH_ARG1_REG ax  /* First arg on stack for i386 */
#define ARCH_ARG2_REG bx
#define ARCH_ARG3_REG cx
#endif

/* Debug logging helper */
#ifdef DEBUG
#define kpm_dbg(fmt, ...) pr_info("[KPM-DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define kpm_dbg(fmt, ...) do {} while(0)
#endif

#define kpm_info(fmt, ...) pr_info("[KPM] " fmt "\n", ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err("[KPM-ERR] " fmt "\n", ##__VA_ARGS__)

/* Function prototypes for KPM interface */
extern int kpm_set_config(const char *key, int value);
extern int kpm_get_config(const char *key);
extern const char* kpm_get_info(void);

/* Placeholder for Android version detection */
static inline int kpm_get_android_version(void) {
    /* This would be implemented by the KPM loader */
    /* Return a reasonable default or read from kernel */
    return 0;
}

#endif /* __KPM_COREPATCH_H__ */
