#ifndef LINE_KEYCHAIN_PROFILES_H
#define LINE_KEYCHAIN_PROFILES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    LMK_KEYCHAIN_ADD,
    LMK_KEYCHAIN_COPY,
    LMK_KEYCHAIN_DELETE,
    LMK_KEYCHAIN_UPDATE,
};

typedef struct {
    unsigned operation;
    uintptr_t return_offset;
} LMKKeychainCallSite;

typedef struct {
    const char *version;
    const unsigned char *uuid;
    uintptr_t got_address;
    uintptr_t got_offset;
    const LMKKeychainCallSite *authentication_sites;
    size_t authentication_site_count;
    const LMKKeychainCallSite *e2ee_sites;
    size_t e2ee_site_count;
} LMKKeychainProfile;

static inline int
LMKKeychainProfileHasCallSite(const LMKKeychainCallSite *sites, size_t count,
                              unsigned operation, uintptr_t return_offset) {
    for (size_t i = 0; i < count; i++) {
        if (sites[i].operation == operation &&
            sites[i].return_offset == return_offset)
            return 1;
    }
    return 0;
}

#endif
