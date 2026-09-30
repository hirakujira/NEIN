#ifndef NEIN_KEYCHAIN_PROFILES_H
#define NEIN_KEYCHAIN_PROFILES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    NEINK_KEYCHAIN_ADD,
    NEINK_KEYCHAIN_COPY,
    NEINK_KEYCHAIN_DELETE,
    NEINK_KEYCHAIN_UPDATE,
};

typedef struct {
    unsigned operation;
    uintptr_t return_offset;
} NEINKKeychainCallSite;

typedef struct {
    const char *version;
    const unsigned char *uuid;
    uintptr_t got_address;
    uintptr_t got_offset;
    const NEINKKeychainCallSite *authentication_sites;
    size_t authentication_site_count;
    const NEINKKeychainCallSite *e2ee_sites;
    size_t e2ee_site_count;
} NEINKKeychainProfile;

static inline int
NEINKKeychainProfileHasCallSite(const NEINKKeychainCallSite *sites, size_t count,
                              unsigned operation, uintptr_t return_offset) {
    for (size_t i = 0; i < count; i++) {
        if (sites[i].operation == operation &&
            sites[i].return_offset == return_offset)
            return 1;
    }
    return 0;
}

#endif
