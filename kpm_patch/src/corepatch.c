/*
 * KPM CorePatch - Based on KernelPatch demo-syscallhook style
 */

// W tym podejściu NIE includujemy <linux/init.h> ani innych, 
// jeśli nie mamy pełnego drzewa kernela. 
// Definiujemy tylko to, co niezbędne, lub polegamy na nagłówkach z KP.

#include <stdint.h>
#include <stddef.h>

// Jeśli kpbuild/linker oczekuje standardowych nazw, musimy zdefiniować struktury
// Zgodnie z demo-syscallhook, często definiuje się je ręcznie, by uniknąć zależności od wersji kernela.

typedef unsigned long size_t;
typedef long ssize_t;
typedef int pid_t;
typedef uint32_t u32;
typedef uint64_t u64;
typedef _Bool bool;
#define true 1
#define false 0

// Struktura pt_regs dla ARM64 (uproszczona, wystarczająca dla hooków)
struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

// Struktura kprobe
struct kprobe {
    const char *symbol_name;
    void *addr;
    void (*pre_handler)(struct kprobe *, struct pt_regs *);
    void (*post_handler)(struct kprobe *, struct pt_regs *, unsigned long);
    void *data;
};

// Deklaracje funkcji jądra (extern) - zostaną rozwiązane przez Loader Apatch/KernelSU
extern int printk(const char *fmt, ...);
extern int register_kprobe(struct kprobe *p);
extern void unregister_kprobe(struct kprobe *p);
extern int strcmp(const char *cs, const char *ct);

// --- Konfiguracja ---
static bool cfg_downgrade = true;
static bool cfg_authcreak = true; // Domyślnie włączamy bypassy
static bool cfg_digestCreak = true;

// --- Helpery ---
#define INFO(fmt, ...) printk("[CorePatch] " fmt "\n", ##__VA_ARGS__)

// --- Hooki ---

static int handler_pre_checkDowngrade(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_downgrade) return 0;
    // ARM64: wynik w regs[0]
    regs->regs[0] = 0; // Fałsz/Sukces (zależnie od kontekstu, tu wymuszamy przejście)
    return 1; // Skip original function
}

static int handler_pre_verifyMessageDigest(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_authcreak) return 0;
    regs->regs[0] = 1; // True (OK)
    return 1;
}

static int handler_pre_checkCapability(struct kprobe *p, struct pt_regs *regs) {
    if (!cfg_digestCreak) return 0;
    // Sprawdź typ capability (arg1 -> regs[1])
    u32 cap_type = (u32)regs->regs[1];
    if (cap_type == 4 || cap_type == 16) return 0; // Nie łam niektórych
    
    regs->regs[0] = 1; // True
    return 1;
}

// Lista hooków
static struct kprobe kp_checkDowngrade = {
    .symbol_name = "checkDowngrade",
    .pre_handler = handler_pre_checkDowngrade,
};

static struct kprobe kp_verifyDigest = {
    .symbol_name = "verifyMessageDigest",
    .pre_handler = handler_pre_verifyMessageDigest,
};

static struct kprobe kp_checkCap = {
    .symbol_name = "checkCapability",
    .pre_handler = handler_pre_checkCapability,
};

static struct kprobe *kprobes[] = {
    &kp_checkDowngrade,
    &kp_verifyDigest,
    &kp_checkCap,
    NULL
};

// --- Init / Exit ---

// W stylu demo-syscallhook, funkcje init/exit są zwykłymi funkcjami C.
// To narzędzie kpbuild lub loader identyfikuje je po symbolach lub konfiguracji.
// Często wymaga się dodania atrybutu lub specyficznej konwencji nazewniczej.
// W demo-syscallhook jest to często realizowane przez makro MODULE_INIT() definiowane w headerze KP.
// Jeśli nie mamy headera, zdefiniujmy prosty mechanizm rejestracji w konstruktorze? 
// Nie, KPM wymaga jawnego eksportu tabeli inicjalizacyjnej.

// Zakładając, że kpbuild szuka symboli o nazwie "kpm_init" i "kpm_exit" lub podobnych:
// Sprawdźmy dokumentację/demo. W demo-syscallhook.c jest:
// static int __init init() ...
// module_init(init);
// Ale bez nagłówków, module_init nie zadziała.

// ROZWIĄZANIE: Ręczna definicja sekcji .init.text i eksport symboli, 
// LUB założenie, że kpbuild zrobi to za nas jeśli nazwiemy funkcje odpowiednio.
// Większość KPM wymaga struktury "kp_mod". Stwórzmy ją ręcznie, tak jak w poprzednich próbach,
// ale bez makr __init.

static int kpm_corepatch_init(void) {
    int i, ret, count = 0;
    INFO("CorePatch Loaded");
    
    for (i = 0; kprobes[i] != NULL; i++) {
        ret = register_kprobe(kprobes[i]);
        if (ret == 0) count++;
    }
    INFO("Registered %d hooks", count);
    return 0;
}

static void kpm_corepatch_exit(void) {
    int i;
    for (i = 0; kprobes[i] != NULL; i++) {
        unregister_kprobe(kprobes[i]);
    }
    INFO("CorePatch Unloaded");
}

// Struktura opisująca moduł (WYMAGANA przez KernelPatch)
// Nazwa sekcji i struktura muszą zgadzać się z tym, czego oczekuje kpbuild/loader.
// Zazwyczaj jest to .kp_mod lub podobna.
struct kp_module_info {
    const char *name;
    const char *version;
    int (*init)(void);
    void (*exit)(void);
};

// Umieszczamy w specjalnej sekcji, którą loader znajdzie
__attribute__((section(".kp_mod"), used))
const struct kp_module_info kp_mod_info = {
    .name = "CorePatch",
    .version = "1.0.0",
    .init = kpm_corepatch_init,
    .exit = kpm_corepatch_exit,
};
