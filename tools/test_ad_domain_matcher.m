#import <Foundation/Foundation.h>
#include <assert.h>

#include "../hooks/NEINAdDomainMatcher.h"

int main(void) {
    @autoreleasepool {
        NSString * const domains[] = {@"doubleclick.net", @"taboola.com"};
        assert(NEINNormalizedAdHostMatchesDomain(@"ads.doubleclick.net", @"DOUBLECLICK.NET"));
        assert(NEINAdHostIsBlocked(@"DOUBLECLICK.NET", domains, 2));
        assert(NEINAdHostIsBlocked(@"googleads.g.doubleclick.net", domains, 2));
        assert(NEINAdHostIsBlocked(@"TRC.TABOOLA.COM", domains, 2));
        assert(!NEINAdHostIsBlocked(@"doubleclick.net.example", domains, 2));
        assert(!NEINAdHostIsBlocked(@"notdoubleclick.net", domains, 2));
        assert(!NEINAdHostIsBlocked(nil, domains, 2));
        assert(!NEINAdHostIsBlocked(@"google.com", domains, 2));
    }
    return 0;
}
