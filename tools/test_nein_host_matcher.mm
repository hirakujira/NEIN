// Small regression test for the exact host matcher used by NEINMacHooks.mm.
// This deliberately includes the production helper so the test cannot drift.
#define NEINHooksLoad NEINHooksLoadForHostMatcherTest
#include "../hooks/NEINMacHooks.mm"
#undef NEINHooksLoad

#include <assert.h>

static NSURL *capturedURL;

static id CaptureLoadRequest(id, SEL, NSURLRequest *request) {
    capturedURL = request.URL;
    return request;
}

int main() {
    assert(NEINIsBlockedHost("doubleclick.net"));
    assert(NEINIsBlockedHost("sub.doubleclick.net"));
    assert(NEINIsBlockedHost("ad.line-scdn.net"));
    assert(NEINIsBlockedHost("TABOOLA.COM"));

    // Similar-looking domains must not be over-blocked.
    assert(!NEINIsBlockedHost("notdoubleclick.net"));
    assert(!NEINIsBlockedHost("doubleclick.net.example"));
    assert(!NEINIsBlockedHost("example.com"));

    // Exercise the actual WebKit replacement decision, without opening a
    // network connection or requiring an interactive LINE session.
    NEINOriginalLoadRequest = CaptureLoadRequest;
    NEINBlockedLoadRequest(nil, @selector(loadRequest:),
        [NSURLRequest requestWithURL:[NSURL URLWithString:
            @"https://ads.doubleclick.net/banner"]]);
    assert([capturedURL.absoluteString isEqualToString:@"about:blank"]);

    NEINBlockedLoadRequest(nil, @selector(loadRequest:),
        [NSURLRequest requestWithURL:[NSURL URLWithString:
            @"https://example.com/normal"]]);
    assert([capturedURL.absoluteString isEqualToString:
        @"https://example.com/normal"]);

    return 0;
}
