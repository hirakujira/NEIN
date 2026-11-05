#pragma once

static inline BOOL NEINExactPromotionalTitle(NSString *text) {
    NSString *title = [[text stringByTrimmingCharactersInSet:
                        NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
    // 逛逛/Discover is the LINE 26.17.0 TW commerce tab ("tw.commerce.gnb").
    return [@[@"VOOM", @"LINE VOOM", @"NEWS", @"LINE NEWS",
              @"SHOPPING", @"LINE SHOPPING", @"逛逛", @"DISCOVER"]
            containsObject:title ?: @""];
}

static inline BOOL NEINIsPromotionalTabItem(UITabBarItem *item) {
    // LINE 26.14.0 includes this specific item class. Do not match generic
    // TabBar/TabItem names or infer item identity from view positions.
    return NEINExactPromotionalTitle(item.title) ||
           [NSStringFromClass(item.class) hasSuffix:@"VOOMSkinnedTabBarItem"];
}
