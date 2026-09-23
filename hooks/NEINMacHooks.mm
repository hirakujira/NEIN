// Experimental macOS LINE ad-blocking hook.
//
// The network side is deliberately narrow: it only affects the audited
// WKWebView ad URLs.  The main macOS LINE UI is Qt/QML, so the native ad
// panels are hidden at the QQuickItem visibility boundary instead of
// intercepting DNS or LINE's general Qt network stack.

#define _DARWIN_C_SOURCE

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>

#include <dlfcn.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>

#ifdef NEIN_ENABLE_QT_AD_HIDING
// The LINE bundle does not ship all Qt development headers.  These small ABI
// declarations cover only exported Qt methods used by this hook; the actual
// implementations remain in LINE's bundled Qt frameworks.
class QMetaObject {
public:
    const char *className() const;
};

class QObject {
public:
    const QMetaObject *metaObject() const;
};

class QQuickItem : public QObject {
public:
    void setVisible(bool visible);
};

#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
class QWidget : public QObject {
public:
    void setVisible(bool visible);
};
#endif
#endif

static const char * const NEINBlockedDomains[] = {
    "ad.line-scdn.net",
    "admob-gmats.uc.r.appspot.com",
    "doubleclick-cn.net",
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "imasdk.googleapis.com",
    "taboola.com",
    "taboolanews.com",
};

static bool NEINHostMatches(const char *host, const char *suffix) {
    if (!host || !suffix) return false;
    while (*host == '.') host++;
    while (*suffix == '.') suffix++;
    const size_t hostLength = strlen(host);
    const size_t suffixLength = strlen(suffix);
    if (hostLength < suffixLength) return false;
    const char *start = host + hostLength - suffixLength;
    if (strcasecmp(start, suffix) != 0) return false;
    return start == host || start[-1] == '.';
}

static bool NEINIsBlockedHost(const char *host) {
    for (size_t i = 0; i < sizeof(NEINBlockedDomains) / sizeof(NEINBlockedDomains[0]); i++) {
        if (NEINHostMatches(host, NEINBlockedDomains[i])) return true;
    }
    return false;
}

#ifdef NEIN_ENABLE_DNS_BLOCK
// Intentionally opt-in only.  Global DNS blocking interferes with LINE's
// login-time network environment discovery and is not part of this build.
static int NEINGetAddrInfo(const char *node, const char *service,
                           const struct addrinfo *hints,
                           struct addrinfo **result) {
    if (NEINIsBlockedHost(node)) {
        if (result) *result = NULL;
        return EAI_NONAME;
    }
    typedef int (*GetAddrInfoIMP)(const char *, const char *,
                                  const struct addrinfo *, struct addrinfo **);
    static GetAddrInfoIMP original;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        original = (GetAddrInfoIMP)dlsym(RTLD_NEXT, "getaddrinfo");
    });
    return original ? original(node, service, hints, result) : EAI_SYSTEM;
}

__attribute__((used))
static struct {
    const void *replacement;
    const void *replacee;
} NEINDnsInterposes[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)NEINGetAddrInfo, (const void *)getaddrinfo},
};
#endif

static bool NEINIsBlockedURL(NSURL *URL) {
    return URL && NEINIsBlockedHost(URL.host.UTF8String);
}

static id (*NEINOriginalLoadRequest)(id, SEL, NSURLRequest *);

static id NEINBlockedLoadRequest(id self, SEL selector, NSURLRequest *request) {
    if (NEINIsBlockedURL(request.URL)) {
        NSURLRequest *empty = [NSURLRequest requestWithURL:
            [NSURL URLWithString:@"about:blank"]];
        return NEINOriginalLoadRequest(self, selector, empty);
    }
    return NEINOriginalLoadRequest(self, selector, request);
}

static void NEINInstallWebKitHook(void) {
    Class webView = objc_getClass("WKWebView");
    SEL selector = @selector(loadRequest:);
    Method method = webView ? class_getInstanceMethod(webView, selector) : NULL;
    if (!method) return;
    NEINOriginalLoadRequest = (id (*)(id, SEL, NSURLRequest *))
        method_getImplementation(method);
    method_setImplementation(method, (IMP)NEINBlockedLoadRequest);
}

#ifdef NEIN_ENABLE_QT_AD_HIDING
static bool NEINClassNameMatchesAd(const char *className) {
    if (!className || !*className) return false;
    // These are the native QML component names found in LINE 26.4.2.  Keep
    // the match limited to ad panels/spaces so ordinary LINE QML stays intact.
    static const char * const componentNames[] = {
        "AdvertisementPanel",
        "ImageAdvertisementPanel",
        "VideoAdvertisementPanel",
        "AdvertisementSpace",
    };
    for (size_t i = 0; i < sizeof(componentNames) / sizeof(componentNames[0]); i++) {
        if (strcasestr(className, componentNames[i])) return true;
    }
    return false;
}

static bool NEINIsAdItem(QObject *object) {
    if (!object) return false;
    const QMetaObject *meta = object->metaObject();
    return meta && NEINClassNameMatchesAd(meta->className());
}

static void NEINLogHiddenItem(QObject *object) {
    static bool logged = false;
    if (logged) return;
    logged = true;
    const QMetaObject *meta = object ? object->metaObject() : nullptr;
    const char *className = meta ? meta->className() : "unknown";
    NSLog(@"[NEINMacHooks] Qt/QML ad item hidden: class=%s", className);
}

using QQuickItemSetVisibleIMP = void (*)(QQuickItem *, bool);
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
using QWidgetSetVisibleIMP = void (*)(QWidget *, bool);
#endif

static QQuickItemSetVisibleIMP NEINOriginalQQuickItemSetVisible;
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
static QWidgetSetVisibleIMP NEINOriginalQWidgetSetVisible;
#endif
static thread_local bool NEINInQQuickItemSetVisible;
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
static thread_local bool NEINInQWidgetSetVisible;
#endif

// Ordinary function aliases are used only as the replacee addresses in the
// dyld table.  A C++ pointer-to-member cannot be converted to a void pointer.
extern "C" void NEINQQuickItemSetVisibleSymbol(QQuickItem *, bool)
    __asm("__ZN10QQuickItem10setVisibleEb");
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
extern "C" void NEINQWidgetSetVisibleSymbol(QWidget *, bool)
    __asm("__ZN7QWidget10setVisibleEb");
#endif

static void NEINQQuickItemSetVisible(QQuickItem *item, bool visible) {
    // A QML item can synchronously update another item while Qt is already
    // inside setVisible.  Skipping that nested call can leave ordinary LINE
    // UI state stale (including the read-state transition).  Forward nested
    // calls directly to Qt's original implementation instead of dropping
    // them; this keeps the ad decision limited to the outer call.
    if (NEINInQQuickItemSetVisible) {
        if (NEINOriginalQQuickItemSetVisible) {
            NEINOriginalQQuickItemSetVisible(item, visible);
        }
        return;
    }
    NEINInQQuickItemSetVisible = true;
    if (visible && NEINIsAdItem(item)) {
        NEINLogHiddenItem(item);
        visible = false;
    }
    if (NEINOriginalQQuickItemSetVisible) {
        NEINOriginalQQuickItemSetVisible(item, visible);
    }
    NEINInQQuickItemSetVisible = false;
}

#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
static void NEINQWidgetSetVisible(QWidget *widget, bool visible) {
    if (NEINInQWidgetSetVisible) return;
    NEINInQWidgetSetVisible = true;
    if (visible && NEINIsAdItem(widget)) {
        NEINLogHiddenItem(widget);
        visible = false;
    }
    if (NEINOriginalQWidgetSetVisible) {
        NEINOriginalQWidgetSetVisible(widget, visible);
    }
    NEINInQWidgetSetVisible = false;
}
#endif

// C++ symbols are exported by the bundled Qt frameworks.  Resolve against
// each framework image directly; RTLD_NEXT can resolve back to the interposed
// entry point when Qt itself calls the method.
static void *NEINLookupQtSymbol(const char *framework, const char *symbol) {
    Dl_info info = {};
    if (!dladdr((const void *)NEINQQuickItemSetVisible, &info) || !info.dli_fname) {
        return dlsym(RTLD_NEXT, symbol);
    }
    NSString *hookPath = [NSString stringWithUTF8String:info.dli_fname];
    NSString *frameworkPath = [[hookPath stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:[NSString stringWithFormat:
            @"%s.framework/Versions/A/%s", framework, framework]];
    void *handle = dlopen(frameworkPath.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    return handle ? dlsym(handle, symbol) : dlsym(RTLD_NEXT, symbol);
}

static void NEINResolveQtOriginals(void) {
    NEINOriginalQQuickItemSetVisible =
        (QQuickItemSetVisibleIMP)NEINLookupQtSymbol(
            "QtQuick", "_ZN10QQuickItem10setVisibleEb");
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
    NEINOriginalQWidgetSetVisible =
        (QWidgetSetVisibleIMP)NEINLookupQtSymbol(
            "QtWidgets", "_ZN7QWidget10setVisibleEb");
#endif
}

__attribute__((used))
static struct {
    const void *replacement;
    const void *replacee;
} NEINQtInterposes[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)NEINQQuickItemSetVisible,
     (const void *)NEINQQuickItemSetVisibleSymbol},
#ifdef NEIN_ENABLE_QT_WIDGET_AD_HIDING
    {(const void *)NEINQWidgetSetVisible,
     (const void *)NEINQWidgetSetVisibleSymbol},
#endif
};
#endif

__attribute__((constructor))
static void NEINHooksLoad(void) {
    @autoreleasepool {
#ifdef NEIN_ENABLE_QT_AD_HIDING
        NEINResolveQtOriginals();
#endif
        NEINInstallWebKitHook();
#ifdef NEIN_ENABLE_QT_AD_HIDING
        NSLog(@"[NEINMacHooks] login-safe Qt/QML ad hiding loaded");
#else
        NSLog(@"[NEINMacHooks] login-safe WebKit-only mode loaded; Qt visibility hooks disabled");
#endif
    }
}
