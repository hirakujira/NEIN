#pragma once

static inline BOOL NEINExactPromotionalTitle(NSString *text) {
    NSString *title = [[text stringByTrimmingCharactersInSet:
                        NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
    return [@[@"VOOM", @"LINE VOOM", @"NEWS", @"LINE NEWS",
              @"SHOPPING", @"LINE SHOPPING"] containsObject:title ?: @""];
}

static inline BOOL NEINIsPromotionalTabItem(UITabBarItem *item) {
    // LINE 26.14.0 includes this specific item class. Do not match generic
    // TabBar/TabItem names or infer item identity from view positions.
    return NEINExactPromotionalTitle(item.title) ||
           [NSStringFromClass(item.class) hasSuffix:@"VOOMSkinnedTabBarItem"];
}
