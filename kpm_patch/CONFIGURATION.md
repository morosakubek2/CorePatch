# KPM CorePatch - Configuration Guide

This document explains all configuration options available in KPM CorePatch.

## Configuration Options

### downgrade (default: true)
**Purpose:** Allows installing older versions of apps over newer ones.

- **true**: Downgrades are permitted
- **false**: Android's default behavior (downgrades blocked)

**Use case:** You want to revert to an older version of an app that works better.

```bash
# Enable downgrades
echo 1 > /sys/module/corepatch/parameters/downgrade

# Or via KernelSU/Apatch interface
kpm_set_config("downgrade", 1)
```

---

### authcreak (default: false)
**Purpose:** Breaks authentication and digest verification checks.

- **true**: Disables signature/digest validation
- **false**: Standard verification enabled

**Use case:** Installing modified APKs with altered contents.

⚠️ **Warning:** This reduces security. Only enable when necessary.

```bash
# Enable auth break
kpm_set_config("authcreak", 1)
```

---

### digestCreak (default: true)
**Purpose:** Bypasses digest verification for app signatures.

- **true**: Signature digest checks bypassed
- **false**: Digest verification enforced

**Use case:** Installing apps with modified resources or code.

```bash
# Enable digest break
kpm_set_config("digestCreak", 1)
```

---

### exactSigCheck (default: false)
**Purpose:** Allows installation even with exact signature mismatches.

- **true**: Exact signature matching disabled
- **false**: Signatures must match exactly

**Use case:** Installing split APKs with different signatures.

```bash
# Enable exact signature check bypass
kpm_set_config("exactSigCheck", 1)
```

---

### UsePreSig (default: false)
**Purpose:** Uses the previous signature when verifying updates.

- **true**: Uses existing installed app's signature
- **false**: Verifies against new APK signature

**Use case:** Updating apps when you've lost the original signing key.

⚠️ **Warning:** Potential security risk. Use with caution.

```bash
# Enable use previous signature
kpm_set_config("UsePreSig", 1)
```

---

### bypassBlock (default: true)
**Purpose:** Bypasses manufacturer-specific installation blocks.

- **true**: Blocks from OEMs (like Nothing OS) are bypassed
- **false**: OEM restrictions enforced

**Use case:** Installing apps blocked by device manufacturer.

```bash
# Enable block bypass
kpm_set_config("bypassBlock", 1)
```

---

### sharedUser (default: false)
**Purpose:** Enables support for shared user ID scenarios.

- **true**: Allows apps with shared UID and different signatures
- **false**: Shared UID requires matching signatures

**Use case:** Advanced scenarios with apps sharing user IDs.

⚠️ **Warning:** Can cause stability issues. Enable only if needed.

```bash
# Enable shared user support
kpm_set_config("sharedUser", 1)
```

---

### disableVerificationAgent (default: true)
**Purpose:** Disables the package verification agent.

- **true**: Verification agent disabled
- **false**: Verification agent active

**Use case:** Preventing Google Play Protect or other verifiers from blocking installs.

```bash
# Disable verification agent
kpm_set_config("disableVerificationAgent", 1)
```

---

## Recommended Configurations

### Basic Usage (Most Users)
For typical downgrade and mod APK installation:
```bash
downgrade=1
digestCreak=1
bypassBlock=1
disableVerificationAgent=1
```

### Maximum Compatibility
For difficult installations (reduced security):
```bash
downgrade=1
authcreak=1
digestCreak=1
exactSigCheck=1
UsePreSig=1
bypassBlock=1
disableVerificationAgent=1
```

### Minimal Security Impact
Only essential patches:
```bash
downgrade=1
digestCreak=0
authcreak=0
```

---

## Setting Configuration

### Method 1: Via KernelSU Manager App
1. Open KernelSU manager
2. Navigate to Superuser or Modules
3. Find CorePatch-KPM
4. Tap on Settings/Configuration
5. Toggle desired options

### Method 2: Via ADB (requires root)
```bash
adb shell
su
echo 1 > /sys/module/corepatch/parameters/downgrade
echo 0 > /sys/module/corepatch/parameters/authcreak
```

### Method 3: Via KPM API
```c
kpm_set_config("downgrade", 1);
kpm_set_config("authcreak", 0);
```

---

## Troubleshooting

### Apps still won't install
1. Enable `authcreak` option
2. Check logcat for specific error messages
3. Ensure module is loaded: `lsmod | grep corepatch`

### System instability after enabling options
1. Disable `sharedUser` if enabled
2. Try minimal configuration first
3. Reboot device after changes

### Module not loading
1. Verify KernelSU/Apatch is properly installed
2. Check kernel supports KPM
3. Review dmesg for loading errors

---

## Security Considerations

⚠️ **Important:** This module disables important security features:

- **Signature verification** protects against malicious app modifications
- **Downgrade protection** prevents rolling back to vulnerable versions
- **Digest checks** ensure app integrity

**Best practices:**
1. Only enable options you actually need
2. Download APKs from trusted sources
3. Disable `authcreak` when not actively installing mods
4. Keep system apps updated manually if using downgrade feature

---

## Support

For issues or questions:
- Check the README.md file
- Review GitHub issues
- Join community discussions on Telegram
