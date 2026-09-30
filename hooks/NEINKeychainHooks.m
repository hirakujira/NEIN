// Version-locked E2EE and authentication Keychain fallback. No values logged.
#import <Security/Security.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>
#include "NEINKeychainProfiles.h"
#include "NEINKeychainProfileData.h"

static uintptr_t NEINKBase;
static BOOL NEINKInstalled;
static BOOL NEINKWaitingLogged;
static OSStatus (*NEINKAdd)(CFDictionaryRef, CFTypeRef *) = SecItemAdd;
static OSStatus (*NEINKCopy)(CFDictionaryRef, CFTypeRef *) = SecItemCopyMatching;
static OSStatus (*NEINKDelete)(CFDictionaryRef) = SecItemDelete;
static OSStatus (*NEINKUpdate)(CFDictionaryRef, CFDictionaryRef) = SecItemUpdate;
static const NEINKKeychainProfile *NEINKProfileInUse;

#define NEINK_IMAGE_NAME "LINE"

static OSStatus NEINKCall(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes, CFTypeRef *result) {
    switch (op) {
        case 0: return NEINKAdd(query, result);
        case 1: return NEINKCopy(query, result);
        case 2: return NEINKDelete(query);
        default: return NEINKUpdate(query, attributes);
    }
}

static BOOL NEINKAuthQuery(unsigned op, uintptr_t caller, CFDictionaryRef query) {
    BOOL site = NEINKProfileInUse &&
        NEINKKeychainProfileHasCallSite(
            NEINKProfileInUse->authentication_sites,
            NEINKProfileInUse->authentication_site_count, op, caller
        );
    if (!site || !query) return NO;
    NSDictionary *q = (__bridge NSDictionary *)query;
    id account = q[(__bridge id)kSecAttrAccount];
    return [q[(__bridge id)kSecClass] isEqual:(__bridge id)kSecClassGenericPassword] &&
           [q[(__bridge id)kSecAttrService] isEqual:@"jp.naver.line"] &&
           [q[(__bridge id)kSecAttrAccessGroup] isEqual:@"ZW4U99SQQ3.jp.naver.line"] &&
           ([account isEqual:@"auth-token"] || [account isEqual:@"auth-token-v3"]);
}

static OSStatus NEINKPerform(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes,
                           CFTypeRef *result, uintptr_t caller) {
    OSStatus initial = NEINKCall(op, query, attributes, result);
    BOOL authQuery = NEINKAuthQuery(op, caller, query);
    BOOL e2eeCall = NEINKProfileInUse &&
        NEINKKeychainProfileHasCallSite(
            NEINKProfileInUse->e2ee_sites,
            NEINKProfileInUse->e2ee_site_count, op, caller
        );
    if (!authQuery && !e2eeCall) {
#ifdef NEIN_MULTI_MESSAGE_DIAGNOSTICS
        // Observe other failures without changing their query or result.
        if (initial != errSecSuccess && NEINDBeginLogging()) {
            NSString *key = [NSString stringWithFormat:@"keychain-%u-%d-%lx", op, (int)initial, (unsigned long)caller];
            if (NEINDShouldEmitError(key, initial, @"")) {
                static const char *names[] = {"add", "copy", "delete", "update"};
                NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] keychain-observe op=%s status=%d explicit-group=%d attribute-group=%d caller=LINE+0x%lx",
                    names[op], (int)initial,
                    query && CFDictionaryContainsKey(query, kSecAttrAccessGroup),
                    attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup), (unsigned long)caller]);
            }
            NEINDEndLogging();
        }
#endif
        return initial;
    }
    BOOL hasGroup = query && CFDictionaryContainsKey(query, kSecAttrAccessGroup);
    BOOL retried = NO;
    OSStatus finalStatus = initial;
    BOOL attributeGroup = attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup);
    BOOL auditedUpdate = e2eeCall && op == NEINK_KEYCHAIN_UPDATE;
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
        finalStatus = NEINKCall(op, (__bridge CFDictionaryRef)local,
                             localAttributes ? (__bridge CFDictionaryRef)localAttributes : attributes, result);
    }
    static const char *names[] = {"add", "copy", "delete", "update"};
    NEINDEmit([NSString stringWithFormat:
        @"[NEINLoginDiag] keychain op=%s initial=%d explicit-group=%d attribute-group=%d retry-default=%d final=%d caller=LINE+0x%lx scope=%s",
        names[op], (int)initial, hasGroup, attributeGroup, retried, (int)finalStatus, (unsigned long)caller,
        authQuery ? "auth" : "e2ee"]);
    return finalStatus;
}

__attribute__((noinline)) static OSStatus NEINKAddHook(CFDictionaryRef q, CFTypeRef *r) {
    return NEINKPerform(0, q, NULL, r, (uintptr_t)__builtin_return_address(0) - NEINKBase);
}
__attribute__((noinline)) static OSStatus NEINKCopyHook(CFDictionaryRef q, CFTypeRef *r) {
    return NEINKPerform(1, q, NULL, r, (uintptr_t)__builtin_return_address(0) - NEINKBase);
}
__attribute__((noinline)) static OSStatus NEINKDeleteHook(CFDictionaryRef q) {
    return NEINKPerform(2, q, NULL, NULL, (uintptr_t)__builtin_return_address(0) - NEINKBase);
}
__attribute__((noinline)) static OSStatus NEINKUpdateHook(CFDictionaryRef q, CFDictionaryRef a) {
    return NEINKPerform(3, q, a, NULL, (uintptr_t)__builtin_return_address(0) - NEINKBase);
}

static BOOL NEINKReplaceSlots(uintptr_t *slots, const uintptr_t *expected, const uintptr_t *replacement) {
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
        NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] keychain GOT protection restore failed status=%d", kr]);
    return YES;
}

static void NEINKTryInstallKeychainCompat(void) {
    if (NEINKInstalled) return;
    const struct mach_header_64 *h = NULL;
    for (uint32_t index = 0; index < _dyld_image_count(); index++) {
        const char *path = _dyld_get_image_name(index);
        const char *name = path ? strrchr(path, '/') : NULL;
        if (name && strcmp(name + 1, NEINK_IMAGE_NAME) == 0) {
            h = (const struct mach_header_64 *)_dyld_get_image_header(index);
            break;
        }
    }
    if (!h || h->magic != MH_MAGIC_64 || h->sizeofcmds > 0x8000) {
        if (!NEINKWaitingLogged) {
            NEINKWaitingLogged = YES;
            NEINDEmit([NSString stringWithFormat:
                @"[NEINLoginDiag] keychain hooks waiting for %s", NEINK_IMAGE_NAME]);
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
    const NEINKKeychainProfile *profile =
        uuid && memcmp(uuid, NEINKEmbeddedKeychainProfile.uuid, 16) == 0
            ? &NEINKEmbeddedKeychainProfile : NULL;
    BOOL sectionOK = profile &&
        gotSectionAddress <= profile->got_address &&
        profile->got_address - gotSectionAddress <= gotSectionSize &&
        gotSectionSize - (profile->got_address - gotSectionAddress) >=
            4 * sizeof(uintptr_t);
    if (!profile || !sectionOK) {
        NEINDEmit([NSString stringWithFormat:
            @"[NEINLoginDiag] keychain hooks skipped: executable layout mismatch profile=%@ got=%d",
            profile ? [NSString stringWithUTF8String:profile->version] : @"unknown",
            sectionOK]);
        return;
    }
    NEINKProfileInUse = profile;
    NEINKBase = (uintptr_t)h;
    uintptr_t expected[] = {(uintptr_t)SecItemAdd, (uintptr_t)SecItemCopyMatching,
                            (uintptr_t)SecItemDelete, (uintptr_t)SecItemUpdate};
    uintptr_t replacement[] = {(uintptr_t)NEINKAddHook, (uintptr_t)NEINKCopyHook,
                               (uintptr_t)NEINKDeleteHook, (uintptr_t)NEINKUpdateHook};
    BOOL installed = NEINKReplaceSlots(
        (uintptr_t *)(NEINKBase + profile->got_offset), expected, replacement
    );
    if (installed) NEINKInstalled = YES;
    NEINDEmit([NSString stringWithFormat:
        @"[NEINLoginDiag] %@ keychain hooks installed; E2EE and exact authentication-store group retry installed=%d",
        [NSString stringWithUTF8String:profile->version], installed]);
}

static void NEINKImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;
    NEINKTryInstallKeychainCompat();
}

static void NEINInstallKeychainCompat(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _dyld_register_func_for_add_image(NEINKImageAdded);
    });
    NEINKTryInstallKeychainCompat();
}
