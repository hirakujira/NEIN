#import <WebKit/WebKit.h>

// Block only the audited ad host suffixes generated into NEINAdDomains.h.
#include "NEINAdDomains.h"
#include "NEINAdDomainMatcher.h"
#include "NEINObjCRuntime.h"

typedef NSURLSessionConfiguration *(*NEINConfigurationClassIMP)(id, SEL);
typedef void (*NEINSetProtocolClassesIMP)(id, SEL, NSArray<Class> *);
typedef WKNavigation *(*NEINWKLoadRequestIMP)(id, SEL, NSURLRequest *);

@interface NEINAdBlockingURLProtocol : NSURLProtocol
@end

static BOOL NEINIsBlockedAdURL(NSURL *URL) {
    return URL && NEINAdHostIsBlocked(URL.host, NEINAdBlockedDomains,
                                    NEINAdBlockedDomainCount);
}

static NSError *NEINBlockedAdRequestError(NSURL *URL) {
    return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost
        userInfo:@{
            NSURLErrorFailingURLErrorKey: URL ?: [NSNull null],
            NSLocalizedDescriptionKey: @"Advertising host blocked",
        }];
}

@implementation NEINAdBlockingURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    return NEINIsBlockedAdURL(request.URL);
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    [self.client URLProtocol:self didFailWithError:NEINBlockedAdRequestError(self.request.URL)];
}

- (void)stopLoading {
}

@end

static void NEINInstallAdProtocol(NSURLSessionConfiguration *configuration) {
    if (!configuration) return;
    NSMutableArray<Class> *classes = [configuration.protocolClasses mutableCopy] ?: [NSMutableArray new];
    if (![classes containsObject:NEINAdBlockingURLProtocol.class]) {
        [classes insertObject:NEINAdBlockingURLProtocol.class atIndex:0];
        configuration.protocolClasses = classes;
    }
}

static NEINConfigurationClassIMP NEINOriginalDefaultConfiguration;
static NEINConfigurationClassIMP NEINOriginalEphemeralConfiguration;
static NEINSetProtocolClassesIMP NEINOriginalSetProtocolClasses;

static NSURLSessionConfiguration *NEINDefaultConfiguration(id self, SEL selector) {
    NSURLSessionConfiguration *configuration = NEINOriginalDefaultConfiguration(self, selector);
    NEINInstallAdProtocol(configuration);
    return configuration;
}

static NSURLSessionConfiguration *NEINEphemeralConfiguration(id self, SEL selector) {
    NSURLSessionConfiguration *configuration = NEINOriginalEphemeralConfiguration(self, selector);
    NEINInstallAdProtocol(configuration);
    return configuration;
}

static void NEINSetProtocolClasses(id self, SEL selector, NSArray<Class> *classes) {
    NSMutableArray<Class> *updated = [classes mutableCopy] ?: [NSMutableArray new];
    if (![updated containsObject:NEINAdBlockingURLProtocol.class]) {
        [updated insertObject:NEINAdBlockingURLProtocol.class atIndex:0];
    }
    NEINOriginalSetProtocolClasses(self, selector, updated);
}

static NEINWKLoadRequestIMP NEINOriginalWKLoadRequest;

static WKNavigation *NEINWKLoadRequest(id self, SEL selector, NSURLRequest *request) {
    if (NEINIsBlockedAdURL(request.URL)) {
        WKWebView *webView = (WKWebView *)self;
        return [webView loadHTMLString:@"" baseURL:nil];
    }
    return NEINOriginalWKLoadRequest(self, selector, request);
}

static void NEINInstallAdNetworkBlock(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [NSURLProtocol registerClass:NEINAdBlockingURLProtocol.class];
        NEINHookClassMethod(NSURLSessionConfiguration.class,
                          @selector(defaultSessionConfiguration), "@", 2, NULL, NULL,
                          (IMP)NEINDefaultConfiguration, (IMP *)&NEINOriginalDefaultConfiguration);
        NEINHookClassMethod(NSURLSessionConfiguration.class,
                          @selector(ephemeralSessionConfiguration), "@", 2, NULL, NULL,
                          (IMP)NEINEphemeralConfiguration, (IMP *)&NEINOriginalEphemeralConfiguration);
        NEINHook(NSURLSessionConfiguration.class, @selector(setProtocolClasses:), "v", 3,
               "@", NULL, (IMP)NEINSetProtocolClasses, (IMP *)&NEINOriginalSetProtocolClasses);
        NEINHook(WKWebView.class, @selector(loadRequest:), "@", 3, "@", NULL,
               (IMP)NEINWKLoadRequest, (IMP *)&NEINOriginalWKLoadRequest);
    });
}
