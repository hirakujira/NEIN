#import <Foundation/Foundation.h>
#include <assert.h>

// Minimal item doubles exercise the production selection code on macOS.
@interface UITabBarItem : NSObject
@property BOOL enabled;
@property(copy) NSString *title;
@end
@implementation UITabBarItem
- (instancetype)init {
    if ((self = [super init])) _enabled = YES;
    return self;
}
@end
@interface VOOMSkinnedTabBarItem : UITabBarItem @end
@implementation VOOMSkinnedTabBarItem @end

#include "../hooks/NEINVisibleTabModel.h"

int main(void) {
    @autoreleasepool {
        NSMutableArray<UITabBarItem *> *nativeItems = [NSMutableArray new];
        for (NSString *title in @[@"首頁", @"聊天", @"VOOM", @"通話"]) {
            UITabBarItem *item = [UITabBarItem new];
            item.title = title;
            [nativeItems addObject:item];
        }
        assert(NEINIsMainLineTabBar(nativeItems));
        assert(!NEINIsMainLineTabBar(@[nativeItems[0], nativeItems[1]]));
        NSArray *nativeSnapshot = [nativeItems copy];
        assert(([NEINVisibleTabIndices(nativeItems) isEqualToArray:@[@0, @1, @3]]));
        assert(NEINVisibleTabDestination(nativeItems, 1, 2) == 3);
        assert(NEINVisibleTabDestination(nativeItems, 3, 2) == 1);
        assert(NEINVisibleTabDestination(nativeItems, 1, 1) == 1);
        assert(NEINVisibleTabDestination(nativeItems, NSNotFound, 2) == 3);
        assert(NEINVisibleTabDestination(nativeItems, 1, NSNotFound) == NSNotFound);
        assert(NEINVisibleTabDestination(@[], 0, 0) == NSNotFound);
        nativeItems[3].enabled = NO;
        assert(NEINVisibleTabDestination(nativeItems, 1, 2) == 1);
        nativeItems[1].title = @"NEWS";
        assert(([NEINVisibleTabIndices(nativeItems) isEqualToArray:@[@0, @3]]));
        assert(NEINVisibleTabDestination(nativeItems, 3, 2) == 0);
        nativeItems[0].title = @"SHOPPING";
        assert(NEINVisibleTabDestination(nativeItems, 1, 2) == NSNotFound);
        assert([nativeItems isEqualToArray:nativeSnapshot]); // Same model objects/order.
        NSMutableArray<UITabBarItem *> *discoverItems = [NSMutableArray new];
        for (NSString *title in @[@"主頁", @"聊天", @"逛逛", @"VOOM", @"通話"]) {
            UITabBarItem *item = [UITabBarItem new];
            item.title = title;
            [discoverItems addObject:item];
        }
        assert(NEINIsMainLineTabBar(discoverItems));
        assert(([NEINVisibleTabIndices(discoverItems) isEqualToArray:@[@0, @1, @4]]));
        assert(NEINVisibleTabDestination(discoverItems, 1, 2) == 4);
        assert(NEINVisibleTabDestination(discoverItems, 4, 3) == 1);
        discoverItems[2].title = @" Discover ";
        assert(NEINIsPromotionalTabItem(discoverItems[2]));
        discoverItems[2].title = @"我的逛逛";
        assert(!NEINIsPromotionalTabItem(discoverItems[2]));
        UITabBarItem *partial = [UITabBarItem new];
        partial.title = @"VOOM settings";
        assert(!NEINIsPromotionalTabItem(partial));
        assert(NEINIsPromotionalTabItem([VOOMSkinnedTabBarItem new]));
        assert(!NEINIsPromotionalTabItem([UITabBarItem new]));
        puts("Promotional tab selection regression tests passed (item doubles).");
    }
    return 0;
}
