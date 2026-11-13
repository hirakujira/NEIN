#import <dlfcn.h>
#import <Foundation/Foundation.h>
#import <mach-o/getsect.h>

#include "NEINThemeConfig.h"

// Theme reskin: every launch re-seeds the skin source theme's files
// (embedded as a tar at build time) into the target owned theme's
// stylesheets-root directory, carrying the target's own manifest identity
// so version checks pass and the shop never re-downloads over the skin.
// The target is a theme the account really owns, and no apply-path,
// ownership, or network behavior is hooked.
//
// The stylesheets root comes from the manager singleton; before the account
// restore finishes it can legitimately be nil, which callers treat as "not
// yet" rather than an error.
static NSURL *NEINStylesheetsRoot(void) {
    Class manager = NSClassFromString(
        @"_TtC17LineSharedUITheme17StylesheetManager");
    if (!manager || ![manager respondsToSelector:@selector(sharedManager)]) {
        return nil;
    }
    id instance = [manager performSelector:@selector(sharedManager)];
    if (![instance respondsToSelector:@selector(stylesheetsRootURL)]) {
        return nil;
    }
    return [instance performSelector:@selector(stylesheetsRootURL)];
}

static const uint8_t *NEINEmbeddedThemeTar(unsigned long *size) {
    // dladdr resolves this dylib's own header, so the embedded section can
    // be read without depending on the linker's dylib header symbol.
    static const uint8_t *data;
    static unsigned long sectionSize;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Dl_info info;
        if (dladdr((const void *)NEINStylesheetsRoot, &info) &&
            info.dli_fbase) {
            data = getsectiondata((const struct mach_header_64 *)info.dli_fbase,
                                  "__DATA", "__nein_theme_pkg",
                                  &sectionSize);
        }
    });
    *size = sectionSize;
    return data;
}

static BOOL NEINSeedPackedTheme(NSURL *root) {
    if (!root) return NO;
    NSFileManager *manager = [NSFileManager defaultManager];
    NSString *target = [root.path stringByAppendingPathComponent:
        [NSString stringWithUTF8String:NEINSkinThemeTarget]];
    unsigned long size = 0;
    const uint8_t *tar = NEINEmbeddedThemeTar(&size);
    if (!tar || size < 1024) return NO;
    // Unconditional: the app can re-download the owned theme's package
    // (theme revision bumps) and overwrite the skin, so every launch walks
    // the archive again. The walk is a few hundred atomic file writes, and
    // the lock keeps concurrent triggers from interleaving.
    static NSLock *lock;
    static dispatch_once_t lockOnce;
    dispatch_once(&lockOnce, ^{ lock = [[NSLock alloc] init]; });
    [lock lock];
    {
        const uint8_t *cursor = tar;
        const uint8_t *end = tar + size;
        while (cursor + 512 <= end) {
            char name[101];
            memcpy(name, cursor, 100);
            name[100] = 0;
            if (name[0] == 0) break;  // end-of-archive marker
            unsigned long long fileSize = 0;
            BOOL octal = YES;
            for (int i = 0; i < 11; i++) {
                char c = cursor[124 + i];
                if (c < '0' || c > '7') {
                    octal = NO;
                    break;
                }
                fileSize = fileSize * 8 + (unsigned)(c - '0');
            }
            unsigned long long blocks = (fileSize + 511) / 512;
            if (!octal || cursor + 512 + fileSize > end) break;
            char type = cursor[156];
            if ((type == '0' || type == 0) && fileSize > 0) {
                NSString *relative =
                    [NSString stringWithFormat:@"%s", name];
                // Skip anything that could escape the seeded directory.
                NSRange dotdot = [relative rangeOfString:@".."];
                if (dotdot.location == NSNotFound) {
                    NSString *destination =
                        [target stringByAppendingPathComponent:relative];
                    [manager createDirectoryAtPath:
                        destination.stringByDeletingLastPathComponent
                        withIntermediateDirectories:YES attributes:nil
                        error:NULL];
                    [[NSData dataWithBytes:cursor + 512 length:fileSize]
                        writeToFile:destination atomically:YES];
                }
            }
            cursor += 512 + blocks * 512;
        }
    }
    [lock unlock];
    return [manager fileExistsAtPath:
        [target stringByAppendingPathComponent:@"theme.json"]];
}

// Resolve the stylesheets root on the main queue (where the manager
// singleton lives), then walk the embedded tar off the main thread so
// launch is not blocked. A nil root means "not yet" and is simply retried
// by the next trigger.
static void NEINSeedFromStylesheetsRoot(void) {
    NSURL *root = NEINStylesheetsRoot();
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NEINSeedPackedTheme(root);
    });
}

// Skin mode: seed as soon as the account restore resolves the stylesheets
// root, and re-run shortly after in case the first pass found the root not
// yet resolved. The owned store is never touched: the target's own row
// comes from the account's real ownership.
static void NEINInstallSkinThemeSeeding(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            NEINSeedFromStylesheetsRoot();
        });
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
            dispatch_get_main_queue(), ^{
                NEINSeedFromStylesheetsRoot();
            });
    });
}
