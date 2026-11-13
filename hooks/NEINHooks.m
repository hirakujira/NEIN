// Restore a usable database location when a re-signed LINE lacks its App Group.
// This is app-private storage. It is NOT shared with app extensions.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include "NEINObjCRuntime.h"
#if defined(NEIN_MULTI_KEYCHAIN_COMPAT) && !defined(NEIN_MULTI_DIAGNOSTICS)
// NEINKeychainHooks.m reports through NEINDEmit from NEINLoginDiagnostics.m.
#error "NEIN_MULTI_KEYCHAIN_COMPAT requires NEIN_MULTI_DIAGNOSTICS"
#endif
#ifdef NEIN_MULTI_ICON_PICKER
#import <UIKit/UIKit.h>
#include "NEINIconPicker.m"
#endif
#include "NEINAppGroups.h"
#ifdef NEIN_MULTI_DIAGNOSTICS
#include "NEINLoginDiagnostics.m"
#endif
#ifdef NEIN_MULTI_KEYCHAIN_COMPAT
#include "NEINKeychainHooks.m"
#endif
#if defined(NEIN_MULTI_REMOVE_ADS) || defined(NEIN_MULTI_HIDE_PROMOTIONAL_TABS)
#include "NEINAdRemovalHooks.m"
#endif
#ifdef NEIN_MULTI_REMOVE_ADS
#include "NEINAdNetworkHooks.m"
#endif
#ifdef NEIN_MULTI_SKIN_THEME
#include "NEINSkinHooks.m"
#endif
#ifdef NEIN_MULTI_IPHONE_DUO
#include "NEINIPhoneDuo.m"
#endif

typedef NSURL *(*NEINContainerIMP)(id, SEL, NSString *);
static NEINContainerIMP NEINOriginalContainer;

static NSURL *NEINLocalContainer(NSFileManager *manager, NSString *identifier) {
    // Exact allowlist above makes the last component safe as a directory name.
#ifdef NEIN_MULTI_TESTING
    NSString *testRoot = NSProcessInfo.processInfo.environment[@"NEIN_MULTI_TEST_ROOT"];
    if (!testRoot.length) return nil;
    NSURL *library = [NSURL fileURLWithPath:testRoot isDirectory:YES];
#else
    NSURL *library = [manager URLsForDirectory:NSLibraryDirectory
                                     inDomains:NSUserDomainMask].firstObject;
#endif
    if (!library) return nil;
    NSURL *root = [library URLByAppendingPathComponent:@"Application Support/LINEContainerCompat" isDirectory:YES];
    NSURL *directory = [root URLByAppendingPathComponent:identifier isDirectory:YES];
    NSError *error = nil;
    if (![manager createDirectoryAtURL:directory withIntermediateDirectories:YES
                            attributes:nil error:&error]) {
        NSLog(@"[NEINContainerCompat] Cannot create local container (domain=%@ code=%ld)",
              error.domain, (long)error.code);
        return nil;
    }
    return directory;
}

static NSURL *NEINContainerURL(id receiver, SEL selector, NSString *identifier) {
    NSURL *original = NEINOriginalContainer(receiver, selector, identifier);
    NSURL *fallback = (!original && NEINIsLINEAppGroup(identifier))
                      ? NEINLocalContainer(receiver, identifier) : nil;
#ifdef NEIN_MULTI_DIAGNOSTICS
    NEINDLogContainer(identifier, original != nil, fallback != nil);
#endif
    return original ?: fallback;
}

static id NEINUnavailableVocabulary(id self, SEL selector) {
    (void)self;
    (void)selector;
    return nil;
}

static void NEINInstallSiriCompat(void) {
    NEINHookClassMethod(NSClassFromString(@"INVocabulary"), @selector(sharedVocabulary),
                        "@", 2, NULL, NULL, (IMP)NEINUnavailableVocabulary, NULL);
}

static void NEINInstallContainerFallback(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // Installed during image initialization, before the app's main() runs.
        if (!NEINHook(NSFileManager.class,
                      @selector(containerURLForSecurityApplicationGroupIdentifier:),
                      "@", 3, "@", NULL, (IMP)NEINContainerURL,
                      (IMP *)&NEINOriginalContainer)) {
            NSLog(@"[NEINContainerCompat] Container method missing or changed; fallback unavailable");
            return;
        }
        NSLog(@"[NEINContainerCompat] v1 loaded; local fallback enabled for LINE groups");
    });
}

#ifndef NEIN_MULTI_TESTING
__attribute__((constructor)) static void NEINHooksLoad(void) {
    @autoreleasepool {
        // The dylib is loaded only by the main LINE executable, even if its
        // bundle identifier changes during signing. Do not activate in appex.
        NSString *executable = NSBundle.mainBundle.infoDictionary[@"CFBundleExecutable"];
        if ([executable isEqualToString:@"LINE"]) {
            NEINInstallContainerFallback();
            NEINInstallSiriCompat();
#ifdef NEIN_MULTI_ICON_PICKER
            NEINInstallIconPicker();
#endif
#ifdef NEIN_MULTI_DIAGNOSTICS
            NEINInstallLoginDiagnostics();
#endif
#ifdef NEIN_MULTI_KEYCHAIN_COMPAT
            NEINInstallKeychainCompat();
#endif
#if defined(NEIN_MULTI_REMOVE_ADS) || defined(NEIN_MULTI_HIDE_PROMOTIONAL_TABS)
            NEINInstallAdRemovalCompat();
#endif
#ifdef NEIN_MULTI_REMOVE_ADS
            NEINInstallAdNetworkBlock();
#endif
#ifdef NEIN_MULTI_SKIN_THEME
            NEINInstallSkinThemeSeeding();
#endif
#ifdef NEIN_MULTI_IPHONE_DUO
            NEINInstallIPhoneDuoCompat();
#endif
        }
    }
}
#endif
