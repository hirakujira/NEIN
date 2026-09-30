// Read-only observations of the post-login path. Never inspect message bodies,
// credentials, request headers, error descriptions, or error userInfo.
#import <objc/message.h>
#include "NEINObjCRuntime.h"

static BOOL NEINMTake(NSString *key) {
    static NSLock *lock;
    static NSMutableDictionary<NSString *, NSNumber *> *counts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; counts = [NSMutableDictionary new]; });
    [lock lock];
    unsigned count = [counts[key] unsignedIntValue];
    BOOL take = count < 8 && (counts[key] != nil || counts.count < 512);
    if (take) counts[key] = @(count + 1);
    [lock unlock];
    return take;
}

static void NEINMEvent(NSString *event, NSString *fields) {
    if (!NEINDBeginLogging()) return;
    if (NEINMTake([event stringByAppendingString:fields]))
        NEINDEmit([NSString stringWithFormat:@"[NEINLoginDiag] message event=%@ %@ frames=%@",
                 event, fields, NEINDLINEFrames()]);
    NEINDEndLogging();
}

static void NEINMError(id error, NSString *event) {
    if (![error isKindOfClass:NSError.class]) return;
    NSError *e = error;
    NEINMEvent(event, [NSString stringWithFormat:@"domain=%@ code=%ld",
                    NEINDSafeDomain(e.domain), (long)e.code]);
}

// Validate Objective-C ABI before wrapping. Each hook keeps the original call
// and result, including nil credentials and real error classification.
static Method NEINMMethod(NSString *className, BOOL meta, NSString *name,
                        const char *result, const char *argument) {
    Class cls = NSClassFromString(className);
    if (meta) cls = object_getClass(cls);
    Method method = cls ? class_getInstanceMethod(cls, NSSelectorFromString(name)) : NULL;
    return NEINMethodHasType(method, result, argument ? 3u : 2u, argument, NULL)
        ? method : NULL;
}

static BOOL NEINMVoidHook(NSString *cls, BOOL meta, NSString *name, NSString *event) {
    Method m = NEINMMethod(cls, meta, name, "v", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    void (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^(id receiver) {
        NEINMEvent(event, @"called=1");
        original(receiver, selector);
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL NEINMObjectHook(NSString *cls, NSString *name, NSString *event) {
    Method m = NEINMMethod(cls, NO, name, "@", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    id (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^id(id receiver) {
        id result = original(receiver, selector);
        NEINMEvent(event, [NSString stringWithFormat:@"present=%d", result != nil]);
        return result;
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL NEINMIntegerHook(NSString *cls, BOOL meta, NSString *name, NSString *event) {
    Method m = NEINMMethod(cls, meta, name, "q", NULL);
    if (!m) m = NEINMMethod(cls, meta, name, "Q", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    NSInteger (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^NSInteger(id receiver) {
        NSInteger result = original(receiver, selector);
        NEINMEvent(event, [NSString stringWithFormat:@"value=%ld", (long)result]);
        return result;
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL NEINMErrorHook(NSString *name) {
    Method m = NEINMMethod(@"TalkErrorManager", YES, name, @encode(BOOL), "@");
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    BOOL (*original)(id, SEL, id) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^BOOL(id receiver, id error) {
        NEINMError(error, [@"check-" stringByAppendingString:name]);
        return original(receiver, selector, error);
    });
    method_setImplementation(m, hook);
    return YES;
}

static void NEINInstallMessageDiagnostics(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned installed = 0;
        installed += NEINMVoidHook(@"_TtC4LINE21FetchOperationService", NO, @"start", @"sync-start");
        installed += NEINMVoidHook(@"_TtC4LINE21FetchOperationService", NO, @"shutdown", @"sync-stop");
        NSString *push = @"_TtC7LEGY_H214ServerPushCall";
        installed += NEINMVoidHook(push, NO, @"resume", @"connection-resume");
        installed += NEINMVoidHook(push, NO, @"pause", @"connection-pause");
        installed += NEINMVoidHook(push, NO, @"startNewSessionIfNeeded", @"connection-start");
        installed += NEINMObjectHook(@"NLAuthenticationManager", @"accessToken", @"access-token");
        installed += NEINMObjectHook(@"NLAuthenticationManager", @"authTokenV3", @"access-token-v3");
        installed += NEINMObjectHook(@"NLAuthenticationManager", @"getAuthenticationToken", @"authentication-token");
        installed += NEINMIntegerHook(@"NLAuthenticationManager", NO, @"authenticationTokenStatus", @"authentication-status");
        installed += NEINMIntegerHook(@"ApplicationType", YES, @"applicationTypeIndex", @"application-type");
        for (NSString *name in @[@"isNetworkError:", @"isTalkError:", @"isFatalError:",
              @"isNotAllowedSecondaryDeviceError:", @"isNotAvailableSession:"])
            installed += NEINMErrorHook(name);
        NEINDEmit([NSString stringWithFormat:
            @"[NEINLoginDiag] %@ message diagnostics loaded; hooks=%u/15; read-only",
            NEINDVersion, installed]);
    });
}
