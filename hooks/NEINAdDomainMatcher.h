#import <Foundation/Foundation.h>

static BOOL NEINNormalizedAdHostMatchesDomain(NSString *normalizedHost, NSString *domain) {
    if (!normalizedHost.length || !domain.length) return NO;
    NSString *normalizedDomain = domain.lowercaseString;
    return [normalizedHost isEqualToString:normalizedDomain] ||
           [normalizedHost hasSuffix:[@"." stringByAppendingString:normalizedDomain]];
}

static BOOL NEINAdHostIsBlocked(NSString *host, NSString * const domains[], NSUInteger count) {
    if (!host.length) return NO;
    NSString *normalizedHost = host.lowercaseString;
    for (NSUInteger index = 0; index < count; index++) {
        if (NEINNormalizedAdHostMatchesDomain(normalizedHost, domains[index])) return YES;
    }
    return NO;
}
