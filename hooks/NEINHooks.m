// Restore a usable database location when a re-signed LINE lacks its App Group.
// This is app-private storage. It is NOT shared with app extensions.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
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
#ifdef NEIN_MULTI_MESSAGE_DIAGNOSTICS
#include "NEINMessageDiagnostics.m"
#endif
#if defined(NEIN_MULTI_REMOVE_ADS) || defined(NEIN_MULTI_HIDE_PROMOTIONAL_TABS)
#include "NEINAdRemovalHooks.m"
#endif
#ifdef NEIN_MULTI_REMOVE_ADS
#include "NEINAdNetworkHooks.m"
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
    Class vocabulary = NSClassFromString(@"INVocabulary");
    Method method = vocabulary
        ? class_getClassMethod(vocabulary, @selector(sharedVocabulary))
        : NULL;
    if (!method || method_getNumberOfArguments(method) != 2) return;
    char returnType[16] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    if (strcmp(returnType, "@") != 0) return;
    method_setImplementation(method, (IMP)NEINUnavailableVocabulary);
}

static void NEINInstallContainerFallback(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method method = class_getInstanceMethod(NSFileManager.class,
                        @selector(containerURLForSecurityApplicationGroupIdentifier:));
        if (!method) {
            NSLog(@"[NEINContainerCompat] Container method missing; fallback unavailable");
            return;
        }
        // Installed during image initialization, before the app's main() runs.
        NEINOriginalContainer = (NEINContainerIMP)method_getImplementation(method);
        method_setImplementation(method, (IMP)NEINContainerURL);
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
#ifdef NEIN_MULTI_MESSAGE_DIAGNOSTICS
            NEINInstallMessageDiagnostics();
#endif
#if defined(NEIN_MULTI_REMOVE_ADS) || defined(NEIN_MULTI_HIDE_PROMOTIONAL_TABS)
            NEINInstallAdRemovalCompat(
#ifdef NEIN_MULTI_REMOVE_ADS
                YES,
#else
                NO,
#endif
#ifdef NEIN_MULTI_HIDE_PROMOTIONAL_TABS
                YES
#else
                NO
#endif
            );
#endif
#ifdef NEIN_MULTI_REMOVE_ADS
            NEINInstallAdNetworkBlock();
#endif
        }
    }
}
#endif
