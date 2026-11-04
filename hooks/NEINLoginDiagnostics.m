// Included only in the diagnostic build. Never log userInfo, localized text,
// request/response bodies, Keychain queries, account identifiers, or secrets.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include "NEINAppGroups.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <stdatomic.h>
#include <string.h>
#include <os/log.h>

static _Thread_local BOOL NEINDLogging;
static atomic_uint NEINDErrorCount, NEINDLocalizationCount, NEINDContainerCount;
static NSString * const NEINDVersion = @"v7";
static const unsigned NEINDMaximumEventCount = 80;
static const unsigned NEINDMaximumDuplicateCount = 3;
static const NSUInteger NEINDMaximumErrorKeys = 512;

static BOOL NEINDBeginLogging(void) {
    if (NEINDLogging) return NO;
    NEINDLogging = YES;
    return YES;
}

static void NEINDEndLogging(void) {
    NEINDLogging = NO;
}

// Callers pass only sanitized fields. Explicit public visibility is necessary:
// NSLog's interpolated strings were redacted on the user's iOS 27 device.
static void NEINDEmit(NSString *message) {
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "%{public}@", message);
#ifdef NEIN_DIAGNOSTICS_TESTING
    // Test-only capture of exactly the string sent to unified logging.
    fprintf(stderr, "%s\n", message.UTF8String);
#endif
}

static BOOL NEINDInterestingKey(NSString *key) {
    return [@[@"common.error.applicationError", @"common.error.systemError",
              @"common.error.unknownError", @"authorize.dt.loginerror.general",
              @"authorize.e2ee.error"] containsObject:key ?: @""];
}

static NSString *NEINDSafeDomain(NSString *domain) {
    // Only fixed, known domains are emitted. Unknown domains may contain data.
    static NSSet<NSString *> *allowed;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        allowed = [NSSet setWithArray:@[
            @"NSOSStatusErrorDomain", @"NSCocoaErrorDomain",
            @"NSPOSIXErrorDomain", @"NSURLErrorDomain", @"SAMKeychainErrorDomain",
            @"SecondAuthFactorPinCodeErrorDomain", @"LoginQRCodeErrorDomain",
            @"SecondaryPwlessLoginErrorDomain", @"RegistrationErrorDomain",
            @"CommonCryptoErrorDomain", @"LEGYHTTPErrorDomain",
            @"AccessTokenRefreshErrorDomain", @"AuthAccountReloginErrorDomain",
            // Additional fixed names found in this exact executable's strings.
            @"TalkThriftErrorDomain", @"LEGYErrorDomain", @"SSServerErrorDomain",
            @"VGuardErrorDomain", @"NLChannelGatewayErrorDomain", @"LIFFErrorDomain",
            @"ChannelPaakAuthnErrorDomain", @"PwlessCredentialErrorDomain",
            @"AccountRestoreErrorDomain", @"PrimaryQrCodeMigrationErrorDomain",
            @"LineEAPIntegrateErrorDomain", @"AccountAuthFactorEapConnectErrorDomain",
            @"LineAuthSeamlessLoginLineAuthSeamlessLoginErrorDomain",
            @"LineAuthPrimaryAccountInitFeatureQueryLineAuthPrimaryAccountInitFeatureQueryErrorDomain",
        ]];
    });
    return [allowed containsObject:domain ?: @""] ? domain : @"other-redacted";
}

static NSString *NEINDSafeGroup(NSString *identifier) {
    return NEINIsLINEAppGroup(identifier) ? identifier : @"other-redacted";
}

static NSString *NEINDLINEFrames(void) {
    void *frames[32];
    int count = backtrace(frames, 32);
    NSMutableArray *offsets = [NSMutableArray array];
    for (int i = 0; i < count && offsets.count < 12; i++) {
        Dl_info info = {0};
        if (!dladdr(frames[i], &info) || !info.dli_fname || !info.dli_fbase) continue;
        const char *name = strrchr(info.dli_fname, '/');
        name = name ? name + 1 : info.dli_fname;
        if (strcmp(name, "LINE") != 0) continue;
        uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
        [offsets addObject:[NSString stringWithFormat:@"LINE+0x%lx", (unsigned long)offset]];
    }
    return [offsets componentsJoinedByString:@","];
}

static BOOL NEINDShouldEmitError(NSString *domain, NSInteger code, NSString *frames) {
    static NSLock *lock;
    static NSMutableDictionary<NSString *, NSNumber *> *counts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; counts = [NSMutableDictionary new]; });
    // Full domain is used only in memory for deduplication, never emitted.
    NSString *key = [NSString stringWithFormat:@"%@|%ld|%@", domain ?: @"", (long)code, frames];
    [lock lock];
    NSNumber *previous = counts[key];
    BOOL emit = previous
        ? previous.unsignedIntValue < NEINDMaximumDuplicateCount
        : counts.count < NEINDMaximumErrorKeys;
    if (emit) counts[key] = @(previous.unsignedIntValue + 1);
    [lock unlock];
    return emit;
}

static void NEINDLogError(NSString *domain, NSInteger code, const char *origin) {
    if (!NEINDBeginLogging()) return;
    NSString *frames = NEINDLINEFrames();
    if (NEINDShouldEmitError(domain, code, frames)) {
        atomic_fetch_add(&NEINDErrorCount, 1);
        NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] error origin=%s domain=%@ code=%ld frames=%@",
              origin, NEINDSafeDomain(domain), (long)code, frames]);
    }
    NEINDEndLogging();
}

static void NEINDLogContainer(NSString *identifier, BOOL original, BOOL fallback) {
    if (!NEINDBeginLogging()) return;
    if (atomic_fetch_add(&NEINDContainerCount, 1) < NEINDMaximumEventCount) {
        NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] container group=%@ original=%d fallback=%d frames=%@",
              NEINDSafeGroup(identifier), original, fallback, NEINDLINEFrames()]);
    }
    NEINDEndLogging();
}

typedef NSString *(*NEINDLocalizedIMP)(id, SEL, NSString *, NSString *, NSString *);
static NEINDLocalizedIMP NEINDOriginalLocalized;
static NSString *NEINDLocalized(id receiver, SEL selector, NSString *key,
                              NSString *value, NSString *table) {
    NSString *result = NEINDOriginalLocalized(receiver, selector, key, value, table);
    if (NEINDInterestingKey(key) && NEINDBeginLogging()) {
        if (atomic_fetch_add(&NEINDLocalizationCount, 1) < NEINDMaximumEventCount)
            NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] error-text key=%@ frames=%@", key, NEINDLINEFrames()]);
        NEINDEndLogging();
    }
    return result;
}

// Match init-family ARC ownership: receiver is consumed, result is retained.
typedef id (*NEINDErrorInitIMP)(id __attribute__((ns_consumed)), SEL,
                             NSString *, NSInteger, NSDictionary *)
                             __attribute__((ns_returns_retained));
static NEINDErrorInitIMP NEINDOriginalErrorInit;
static id NEINDErrorInit(id receiver __attribute__((ns_consumed)), SEL selector,
                      NSString *domain, NSInteger code, NSDictionary *userInfo)
                      __attribute__((ns_returns_retained));
static id NEINDErrorInit(id receiver __attribute__((ns_consumed)), SEL selector,
                      NSString *domain, NSInteger code, NSDictionary *userInfo) {
    id result = NEINDOriginalErrorInit(receiver, selector, domain, code, userInfo);
    NEINDLogError(domain, code, "init");
    return result;
}

typedef id (*NEINDErrorFactoryIMP)(id, SEL, NSString *, NSInteger, NSDictionary *);
static NEINDErrorFactoryIMP NEINDOriginalErrorFactory;
static id NEINDErrorFactory(id receiver, SEL selector, NSString *domain,
                         NSInteger code, NSDictionary *userInfo) {
    id result = NEINDOriginalErrorFactory(receiver, selector, domain, code, userInfo);
    NEINDLogError(domain, code, "factory");
    return result;
}

static void NEINInstallLoginDiagnostics(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method localized = class_getInstanceMethod(NSBundle.class,
                             @selector(localizedStringForKey:value:table:));
        Method errorInit = class_getInstanceMethod(NSError.class,
                             @selector(initWithDomain:code:userInfo:));
        Method errorFactory = class_getClassMethod(NSError.class,
                             @selector(errorWithDomain:code:userInfo:));
        if (!localized || !errorInit || !errorFactory) {
            NEINDEmit(@"[NEINLoginDiag] required methods unavailable; diagnostics skipped");
            return;
        }
        NEINDOriginalLocalized = (NEINDLocalizedIMP)method_getImplementation(localized);
        NEINDOriginalErrorInit = (NEINDErrorInitIMP)method_getImplementation(errorInit);
        NEINDOriginalErrorFactory = (NEINDErrorFactoryIMP)method_getImplementation(errorFactory);
        method_setImplementation(localized, (IMP)NEINDLocalized);
        method_setImplementation(errorInit, (IMP)NEINDErrorInit);
        method_setImplementation(errorFactory, (IMP)NEINDErrorFactory);
        NEINDEmit([NSString stringWithFormat:
            @"[NEINLoginDiag] %@ diagnostics loaded; public sanitized fields; duplicate errors limited",
            NEINDVersion]);
    });
}
