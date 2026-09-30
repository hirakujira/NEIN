// Version-locked E2EE and authentication Keychain fallback. No values logged.
#import <Security/Security.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>
#include "LINEKeychainProfiles.h"
#include "LINEKeychainProfileData.h"

static uintptr_t LMKBase;
static BOOL LMKInstalled;
static BOOL LMKWaitingLogged;
static OSStatus (*LMKAdd)(CFDictionaryRef, CFTypeRef *) = SecItemAdd;
static OSStatus (*LMKCopy)(CFDictionaryRef, CFTypeRef *) = SecItemCopyMatching;
static OSStatus (*LMKDelete)(CFDictionaryRef) = SecItemDelete;
static OSStatus (*LMKUpdate)(CFDictionaryRef, CFDictionaryRef) = SecItemUpdate;
static const LMKKeychainProfile *LMKProfileInUse;

#define LMK_IMAGE_NAME "LINE"

static OSStatus LMKCall(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes, CFTypeRef *result) {
    switch (op) {
        case 0: return LMKAdd(query, result);
        case 1: return LMKCopy(query, result);
        case 2: return LMKDelete(query);
        default: return LMKUpdate(query, attributes);
    }
}

static BOOL LMKAuthQuery(unsigned op, uintptr_t caller, CFDictionaryRef query) {
    BOOL site = LMKProfileInUse &&
        LMKKeychainProfileHasCallSite(
            LMKProfileInUse->authentication_sites,
            LMKProfileInUse->authentication_site_count, op, caller
        );
    if (!site || !query) return NO;
    NSDictionary *q = (__bridge NSDictionary *)query;
    id account = q[(__bridge id)kSecAttrAccount];
    return [q[(__bridge id)kSecClass] isEqual:(__bridge id)kSecClassGenericPassword] &&
           [q[(__bridge id)kSecAttrService] isEqual:@"jp.naver.line"] &&
           [q[(__bridge id)kSecAttrAccessGroup] isEqual:@"ZW4U99SQQ3.jp.naver.line"] &&
           ([account isEqual:@"auth-token"] || [account isEqual:@"auth-token-v3"]);
}

static OSStatus LMKPerform(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes,
                           CFTypeRef *result, uintptr_t caller) {
    OSStatus initial = LMKCall(op, query, attributes, result);
    BOOL authQuery = LMKAuthQuery(op, caller, query);
    BOOL e2eeCall = LMKProfileInUse &&
        LMKKeychainProfileHasCallSite(
            LMKProfileInUse->e2ee_sites,
            LMKProfileInUse->e2ee_site_count, op, caller
        );
    if (!authQuery && !e2eeCall) {
#ifdef LINE_MULTI_MESSAGE_DIAGNOSTICS
        // Observe other failures without changing their query or result.
        if (initial != errSecSuccess && LMDBeginLogging()) {
            NSString *key = [NSString stringWithFormat:@"keychain-%u-%d-%lx", op, (int)initial, (unsigned long)caller];
            if (LMDShouldEmitError(key, initial, @"")) {
                static const char *names[] = {"add", "copy", "delete", "update"};
                LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] keychain-observe op=%s status=%d explicit-group=%d attribute-group=%d caller=LINE+0x%lx",
                    names[op], (int)initial,
                    query && CFDictionaryContainsKey(query, kSecAttrAccessGroup),
                    attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup), (unsigned long)caller]);
            }
            LMDEndLogging();
        }
#endif
        return initial;
    }
    BOOL hasGroup = query && CFDictionaryContainsKey(query, kSecAttrAccessGroup);
    BOOL retried = NO;
    OSStatus finalStatus = initial;
    BOOL attributeGroup = attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup);
    BOOL auditedUpdate = e2eeCall && op == LMK_KEYCHAIN_UPDATE;
    BOOL compatibleGroups = !hasGroup || !attributeGroup ||
        CFEqual(CFDictionaryGetValue(query, kSecAttrAccessGroup),
                CFDictionaryGetValue(attributes, kSecAttrAccessGroup));
    BOOL canRetry = compatibleGroups &&
        ((hasGroup && !attributeGroup) || (auditedUpdate && attributeGroup));
    if (initial == errSecMissingEntitlement && canRetry) {
        NSMutableDictionary *local = [(__bridge NSDictionary *)query mutableCopy];
        [local removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
        NSMutableDictionary *localAttributes = nil;
        if (attributeGroup) {
            localAttributes = [(__bridge NSDictionary *)attributes mutableCopy];
            [localAttributes removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
        }
        retried = YES;
        finalStatus = LMKCall(op, (__bridge CFDictionaryRef)local,
                             localAttributes ? (__bridge CFDictionaryRef)localAttributes : attributes, result);
    }
    static const char *names[] = {"add", "copy", "delete", "update"};
    LMDEmit([NSString stringWithFormat:
        @"[LINELoginDiag] keychain op=%s initial=%d explicit-group=%d attribute-group=%d retry-default=%d final=%d caller=LINE+0x%lx scope=%s",
        names[op], (int)initial, hasGroup, attributeGroup, retried, (int)finalStatus, (unsigned long)caller,
        authQuery ? "auth" : "e2ee"]);
    return finalStatus;
}

__attribute__((noinline)) static OSStatus LMKAddHook(CFDictionaryRef q, CFTypeRef *r) {
    return LMKPerform(0, q, NULL, r, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKCopyHook(CFDictionaryRef q, CFTypeRef *r) {
    return LMKPerform(1, q, NULL, r, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKDeleteHook(CFDictionaryRef q) {
    return LMKPerform(2, q, NULL, NULL, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKUpdateHook(CFDictionaryRef q, CFDictionaryRef a) {
    return LMKPerform(3, q, a, NULL, (uintptr_t)__builtin_return_address(0) - LMKBase);
}

static BOOL LMKReplaceSlots(uintptr_t *slots, const uintptr_t *expected, const uintptr_t *replacement) {
    for (unsigned i = 0; i < 4; i++) if (slots[i] != expected[i]) return NO;
    vm_address_t page = (vm_address_t)slots & ~((vm_address_t)vm_page_size - 1);
    if (((vm_address_t)(slots + 4) - 1) / vm_page_size != page / vm_page_size) return NO;
    vm_address_t region = page;
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region, &regionSize,
                                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS || region > page || region + regionSize < page + vm_page_size) return NO;
    if (info.protection & VM_PROT_EXECUTE) return NO;
    kr = vm_protect(mach_task_self(), page, vm_page_size, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return NO;
    for (unsigned i = 0; i < 4; i++) __atomic_store_n(slots + i, replacement[i], __ATOMIC_RELEASE);
    kr = vm_protect(mach_task_self(), page, vm_page_size, FALSE, info.protection);
    if (kr != KERN_SUCCESS)
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] keychain GOT protection restore failed status=%d", kr]);
    return YES;
}

static void LMKTryInstallKeychainCompat(void) {
    if (LMKInstalled) return;
    const struct mach_header_64 *h = NULL;
    for (uint32_t index = 0; index < _dyld_image_count(); index++) {
        const char *path = _dyld_get_image_name(index);
        const char *name = path ? strrchr(path, '/') : NULL;
        if (name && strcmp(name + 1, LMK_IMAGE_NAME) == 0) {
            h = (const struct mach_header_64 *)_dyld_get_image_header(index);
            break;
        }
    }
    if (!h || h->magic != MH_MAGIC_64 || h->sizeofcmds > 0x8000) {
        if (!LMKWaitingLogged) {
            LMKWaitingLogged = YES;
            LMDEmit([NSString stringWithFormat:
                @"[LINELoginDiag] keychain hooks waiting for %s", LMK_IMAGE_NAME]);
        }
        return;
    }
    const unsigned char *uuid = NULL;
    uintptr_t gotSectionAddress = 0;
    uintptr_t gotSectionSize = 0;
    const char *p = (const char *)(h + 1), *end = p + h->sizeofcmds;
    for (unsigned i = 0; i < h->ncmds; i++) {
        if (p + sizeof(struct load_command) > end) return;
        const struct load_command *lc = (const void *)p;
        if (lc->cmdsize < sizeof(*lc) || p + lc->cmdsize > end) return;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command))
            uuid = ((const struct uuid_command *)lc)->uuid;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const void *)lc;
            if (seg->nsects > (lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64)) return;
            const struct section_64 *s = (const void *)(seg + 1);
            for (unsigned j = 0; j < seg->nsects; j++, s++) {
                if (strncmp(s->sectname, "__got", 16) == 0) {
                    gotSectionAddress = (uintptr_t)s->addr;
                    gotSectionSize = (uintptr_t)s->size;
                }
            }
        }
        p += lc->cmdsize;
    }
    const LMKKeychainProfile *profile =
        uuid && memcmp(uuid, LMKEmbeddedKeychainProfile.uuid, 16) == 0
            ? &LMKEmbeddedKeychainProfile : NULL;
    BOOL sectionOK = profile &&
        gotSectionAddress <= profile->got_address &&
        profile->got_address - gotSectionAddress <= gotSectionSize &&
        gotSectionSize - (profile->got_address - gotSectionAddress) >=
            4 * sizeof(uintptr_t);
    if (!profile || !sectionOK) {
        LMDEmit([NSString stringWithFormat:
            @"[LINELoginDiag] keychain hooks skipped: executable layout mismatch profile=%@ got=%d",
            profile ? [NSString stringWithUTF8String:profile->version] : @"unknown",
            sectionOK]);
        return;
    }
    LMKProfileInUse = profile;
    LMKBase = (uintptr_t)h;
    uintptr_t expected[] = {(uintptr_t)SecItemAdd, (uintptr_t)SecItemCopyMatching,
                            (uintptr_t)SecItemDelete, (uintptr_t)SecItemUpdate};
    uintptr_t replacement[] = {(uintptr_t)LMKAddHook, (uintptr_t)LMKCopyHook,
                               (uintptr_t)LMKDeleteHook, (uintptr_t)LMKUpdateHook};
    BOOL installed = LMKReplaceSlots(
        (uintptr_t *)(LMKBase + profile->got_offset), expected, replacement
    );
    if (installed) LMKInstalled = YES;
    LMDEmit([NSString stringWithFormat:
        @"[LINELoginDiag] %@ keychain hooks installed; E2EE and exact authentication-store group retry installed=%d",
        [NSString stringWithUTF8String:profile->version], installed]);
}

static void LMKImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;
    LMKTryInstallKeychainCompat();
}

static void LMInstallKeychainCompat(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _dyld_register_func_for_add_image(LMKImageAdded);
    });
    LMKTryInstallKeychainCompat();
}
