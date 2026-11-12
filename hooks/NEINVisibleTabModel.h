// Keep model indices intact. Only the separate presentation bar is filtered.
static BOOL NEINTabTitleIsOneOf(NSString *title, NSArray<NSString *> *knownTitles) {
    NSString *normalized = [[title stringByTrimmingCharactersInSet:
                             NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
    return [knownTitles containsObject:normalized ?: @""];
}

static BOOL NEINIsPromotionalTabItem(UITabBarItem *item) {
    // 逛逛/Discover is the LINE 26.17.0 TW commerce tab ("tw.commerce.gnb").
    // LINE 26.14.0 includes this specific item class. Do not match generic
    // TabBar/TabItem names or infer item identity from view positions.
    return NEINTabTitleIsOneOf(item.title, @[@"VOOM", @"LINE VOOM", @"NEWS", @"LINE NEWS",
                                             @"SHOPPING", @"LINE SHOPPING", @"逛逛", @"DISCOVER"]) ||
           [NSStringFromClass(item.class) hasSuffix:@"VOOMSkinnedTabBarItem"];
}

static BOOL NEINIsHomeTabTitle(NSString *title) {
    return NEINTabTitleIsOneOf(title,
        @[@"HOME", @"首頁", @"主頁", @"主页", @"ホーム", @"홈"]);
}

static BOOL NEINIsMainLineTabBar(NSArray<UITabBarItem *> *items) {
    BOOL hasHome = NO, hasChat = NO, hasCalls = NO;
    for (UITabBarItem *item in items) {
        NSString *title = item.title;
        hasHome |= NEINIsHomeTabTitle(title);
        hasChat |= NEINTabTitleIsOneOf(title,
            @[@"CHAT", @"CHATS", @"聊天", @"トーク", @"채팅"]);
        hasCalls |= NEINTabTitleIsOneOf(title,
            @[@"CALL", @"CALLS", @"通話", @"통화"]);
    }
    return hasHome && hasChat && hasCalls;
}

static NSArray<NSNumber *> *NEINVisibleTabIndices(NSArray<UITabBarItem *> *items) {
    NSMutableArray *indices = [NSMutableArray new];
    for (NSUInteger i = 0; i < items.count; i++) {
        if (!NEINIsPromotionalTabItem(items[i])) [indices addObject:@(i)];
    }
    return indices;
}

static NSUInteger NEINVisibleTabDestination(NSArray<UITabBarItem *> *items,
                                          NSUInteger current, NSUInteger requested) {
    if (requested >= items.count) return NSNotFound;
    if (!NEINIsPromotionalTabItem(items[requested]) && items[requested].enabled) return requested;
    NSInteger direction = current < items.count && requested < current ? -1 : 1;
    for (NSInteger i = (NSInteger)requested + direction;
         i >= 0 && (NSUInteger)i < items.count; i += direction) {
        if (!NEINIsPromotionalTabItem(items[i]) && items[i].enabled) return (NSUInteger)i;
    }
    if (current < items.count && !NEINIsPromotionalTabItem(items[current]) &&
        items[current].enabled) return current;
    for (NSUInteger i = 0; i < items.count; i++) {
        if (!NEINIsPromotionalTabItem(items[i]) && items[i].enabled) return i;
    }
    return NSNotFound;
}
