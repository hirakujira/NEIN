// Keep model indices intact. Only the separate presentation bar is filtered.
#include "NEINPromotionalTabIdentity.h"

static BOOL NEINVisibleTabIsPromotional(UITabBarItem *item) {
    return NEINIsPromotionalTabItem(item);
}

static BOOL NEINTabTitleIsOneOf(NSString *title, NSArray<NSString *> *knownTitles) {
    NSString *normalized = [[title stringByTrimmingCharactersInSet:
                             NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
    return [knownTitles containsObject:normalized ?: @""];
}

static BOOL NEINIsMainLineTabBar(NSArray<UITabBarItem *> *items) {
    BOOL hasHome = NO, hasChat = NO, hasCalls = NO;
    for (UITabBarItem *item in items) {
        NSString *title = item.title;
        hasHome |= NEINTabTitleIsOneOf(title,
            @[@"HOME", @"首頁", @"主頁", @"主页", @"ホーム", @"홈"]);
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
        if (!NEINVisibleTabIsPromotional(items[i])) [indices addObject:@(i)];
    }
    return indices;
}

static NSUInteger NEINVisibleTabDestination(NSArray<UITabBarItem *> *items,
                                          NSUInteger current, NSUInteger requested) {
    if (requested >= items.count) return NSNotFound;
    if (!NEINVisibleTabIsPromotional(items[requested]) && items[requested].enabled) return requested;
    NSInteger direction = current < items.count && requested < current ? -1 : 1;
    for (NSInteger i = (NSInteger)requested + direction;
         i >= 0 && (NSUInteger)i < items.count; i += direction) {
        if (!NEINVisibleTabIsPromotional(items[i]) && items[i].enabled) return (NSUInteger)i;
    }
    if (current < items.count && !NEINVisibleTabIsPromotional(items[current]) &&
        items[current].enabled) return current;
    for (NSUInteger i = 0; i < items.count; i++) {
        if (!NEINVisibleTabIsPromotional(items[i]) && items[i].enabled) return i;
    }
    return NSNotFound;
}
