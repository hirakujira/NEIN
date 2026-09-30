#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>

// Minimal view doubles exercise the production selection code on macOS.
@interface UIView : NSObject
@property BOOL hidden;
@property CGRect frame;
@property CGRect bounds;
@property CGAffineTransform transform;
@property(readonly) CGPoint center;
@property CGFloat alpha;
@property BOOL userInteractionEnabled;
@property(copy) NSArray *gestureRecognizers;
@property(copy) NSString *accessibilityLabel;
@property(copy) NSArray *subviews;
@end
@implementation UIView
- (instancetype)init {
    if ((self = [super init])) {
        _subviews = @[];
        _transform = CGAffineTransformIdentity;
    }
    return self;
}
- (CGPoint)center {
    return CGPointMake(_frame.origin.x + _frame.size.width / 2,
                       _frame.origin.y + _frame.size.height / 2);
}
@end
@interface UIControl : UIView
@property BOOL enabled;
@end
@implementation UIControl @end
@interface UIButton : UIControl
@property(copy) NSString *currentTitle;
@property(copy) NSAttributedString *currentAttributedTitle;
@end
@implementation UIButton @end
@interface UILabel : UIView
@property(copy) NSString *text;
@property(copy) NSAttributedString *attributedText;
@end
@implementation UILabel @end

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

enum { UIUserInterfaceLayoutDirectionLeftToRight = 0 };
@interface UITabBar : UIView
@property(copy) NSArray<UITabBarItem *> *items;
@property(strong) UITabBarItem *selectedItem;
@property NSInteger effectiveUserInterfaceLayoutDirection;
@end
@implementation UITabBar @end

#include "../hooks/NEINPromotionalTabs.h"
#include "../hooks/NEINVisibleTabModel.h"
#include "../hooks/NEINCompactTabs.h"
#define NEIN_TAB_DIAGNOSTICS_SNAPSHOT_ONLY 1
#include "../hooks/NEINTabDiagnostics.h"

static UIView *TestView(NSString *name, BOOL control, CGRect frame) {
    Class cls = NSClassFromString(name);
    if (!cls) {
        cls = objc_allocateClassPair(control ? UIControl.class : UIView.class,
                                     name.UTF8String, 0);
        objc_registerClassPair(cls);
    }
    UIView *view = [cls new];
    view.frame = frame;
    view.bounds = CGRectMake(0, 0, frame.size.width, frame.size.height);
    return view;
}

static void TestCompactLayout(NSUInteger count, CGFloat width) {
    UITabBar *bar = [UITabBar new];
    UIView *platter = TestView(@"UIKit._UITabBarItemPlatterView", NO, CGRectMake(21, 0, width, 62));
    UIView *normal = TestView(@"_TtCC5UIKit20_UITabBarPlatterViewP33_022AA364308030F4627162921FD6D31A11ContentView", NO, CGRectMake(0, 0, width, 62));
    UIView *selected = TestView(@"_TtCC5UIKit32_UITabBarVisualProvider_FloatingP33_3C6E5A7AE2316B749C88F887559DAAB619SelectedContentView", NO, normal.frame);
    UIView *badges = TestView(@"_TtCC5UIKit20_UITabBarPlatterViewP33_022AA364308030F4627162921FD6D31A18BadgeContainerView", NO, normal.frame);
    CGFloat buttonWidth = count == 4 ? 98 : 77;
    CGFloat step = (width - 8 - buttonWidth) / (count - 1);
    NSMutableArray *buttons = [NSMutableArray new], *copies = [NSMutableArray new];
    NSMutableArray *items = [NSMutableArray new];
    for (NSUInteger i = 0; i < count; i++) {
        UITabBarItem *item = [UITabBarItem new];
        item.enabled = i != 2;
        [items addObject:item];
        CGRect frame = CGRectMake(4 + i * step, 4, buttonWidth, 54);
        for (NSMutableArray *row in @[buttons, copies]) {
            UIControl *button = (UIControl *)TestView(@"_UITabButton", YES, frame);
            button.enabled = i != 2;
            button.hidden = i == 2;
            if (i == 2) objc_setAssociatedObject(button, &NEINTabOriginalHiddenKey, @NO,
                                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [row addObject:button];
        }
    }
    normal.subviews = buttons;
    selected.subviews = [[copies reverseObjectEnumerator] allObjects];
    UIView *lens = TestView(@"_UILiquidLensView", NO, ((UIView *)buttons[1]).frame);
    UIView *mask = TestView(@"_TtCE5UIKitCSo17_UILiquidLensViewP33_4C400BD973F5E4E0B779D1A21A7AEB2711DestOutView", NO, CGRectMake(0, 0, buttonWidth, 54));
    UIView *badge = TestView(@"_UIBarBadgeView", NO, CGRectMake(((UIView *)buttons[1]).center.x + 4, 10, 16, 16));
    badges.subviews = @[badge];
    platter.subviews = @[selected, lens, normal, mask, badges];
    bar.subviews = @[platter];
    bar.items = items;
    bar.selectedItem = items[1];
    CGFloat expected = step * (count - 1) / (count - 2) - step;
    NEINCompactTabs(bar);
    assert(fabs(((UIView *)buttons[1]).transform.tx - expected) < 0.001);
    assert(fabs(((UIView *)copies[1]).transform.tx - expected) < 0.001);
    assert(fabs(lens.transform.tx - expected) < 0.001);
    assert(fabs(badge.transform.tx - expected) < 0.001);
    assert(CGAffineTransformIsIdentity(mask.transform));
    assert(CGAffineTransformIsIdentity(platter.transform));
    UIView *portal = TestView(@"_UIPortalView", NO, CGRectZero);
    bar.subviews = @[portal, platter]; // Report 2: zero-sized portal is a sibling.
    NEINCompactTabs(bar);
    assert(fabs(lens.transform.tx - expected) < 0.001);
    assert(CGAffineTransformIsIdentity(portal.transform));
    portal.frame = CGRectMake(0, 0, 1, 1);
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform)); // Nonzero portal is unknown.
    portal.frame = CGRectZero;
    bar.subviews = @[platter, [UIView new]];
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    bar.subviews = @[platter, platter];
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    bar.subviews = @[platter, portal];
    NEINCompactTabs(bar);
    assert(fabs(lens.transform.tx - expected) < 0.001); // No accumulation.
    CGRect original = lens.frame;
    // Report 3: UIKit updates the base position after we applied a translation.
    lens.frame = CGRectOffset(original, expected, 0);
    NEINCompactAlignLens(lens, items[1]);
    assert(fabs(lens.transform.tx) < 0.001);
    assert(fabs(lens.center.x + lens.transform.tx -
                (((UIView *)buttons[1]).center.x + expected)) < 0.001);
    NEINCompactAlignLens(lens, items[1]);
    assert(fabs(lens.transform.tx) < 0.001);
    lens.frame = original;
    NEINCompactAlignLens(lens, items[1]);
    assert(fabs(lens.transform.tx - expected) < 0.001);
    lens.frame = CGRectOffset(original, 1, 0);
    NEINCompactAlignLens(lens, items.lastObject); // Stale target after selection changes.
    assert(fabs(lens.transform.tx - expected) < 0.001);
    lens.frame = original;
    NEINCompactRestore(bar);
    NEINCompactAlignLens(lens, items[1]); // No target survives restore.
    assert(CGAffineTransformIsIdentity(lens.transform));
    NEINCompactTabs(bar);
    lens.frame = CGRectOffset(original, 1, 0);
    NEINCompactTabs(bar);
    assert(fabs(lens.transform.tx - (expected - 1)) < 0.001);
    assert(fabs(badge.transform.tx - expected) < 0.001);
    // Reproduce the reported stale hidden-slot lens with floating-point noise.
    lens.frame = CGRectOffset(((UIView *)buttons[2]).frame, 0.00000000000003, 0);
    lens.bounds = CGRectMake(0, 0, buttonWidth + 0.00000000000003, 54);
    NEINCompactTabs(bar);
    assert(fabs(lens.center.x + lens.transform.tx -
                (((UIView *)buttons[1]).center.x + expected)) < 0.001);
    assert(fabs(((UIView *)buttons[1]).transform.tx - expected) < 0.001);
    NEINCompactTabs(bar);
    assert(fabs(lens.center.x + lens.transform.tx -
                (((UIView *)buttons[1]).center.x + expected)) < 0.001);
    lens.frame = original;
    NEINCompactTabs(bar);
    CGRect badgeFrame = badge.frame;
    badge.frame = CGRectMake(((UIView *)buttons[1]).center.x + step / 2 - 8,
                              10, 16, 16);
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform)); // Ambiguous badge.
    badge.frame = badgeFrame;
    lens.frame = ((UIView *)buttons.lastObject).frame;
    bar.selectedItem = items.lastObject;
    NEINCompactTabs(bar);
    assert(fabs(lens.transform.tx) < 0.001); // Last tab stays at the right edge.
    assert(fabs(((UIView *)buttons[1]).transform.tx - expected) < 0.001);
    lens.frame = original;
    bar.selectedItem = items[1];
    NEINCompactTabs(bar);
    ((UIView *)buttons[1]).transform = CGAffineTransformMakeScale(0.9, 0.9);
    NEINCompactTabs(bar);
    assert(((UIView *)buttons[1]).transform.a == 0.9); // Preserve external transforms.
    assert(CGAffineTransformIsIdentity(lens.transform));
    ((UIView *)buttons[1]).transform = CGAffineTransformIdentity;
    bar.selectedItem = items[2]; // Never force a hidden selected item elsewhere.
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    assert(lens.hidden);
    assert(fabs(((UIView *)buttons[1]).transform.tx - expected) < 0.001);
    assert(fabs(badge.transform.tx - expected) < 0.001);
    assert(bar.selectedItem == items[2]);
    NEINCompactTabs(bar);
    assert(lens.hidden);
    NEINCompactTabsForSelection(bar, items[1]); // Controller and bar disagree.
    assert(!lens.hidden);
    assert(fabs(lens.transform.tx - expected) < 0.001);
    assert(bar.selectedItem == items[2]); // No selection setters invoked.
    NEINCompactTabs(bar);
    lens.hidden = YES;
    NEINCompactRestore(bar);
    lens.hidden = YES; // Preserve a pre-existing hidden selection background.
    NEINCompactTabs(bar);
    NEINCompactTabsForSelection(bar, items[1]);
    assert(lens.hidden);
    NEINCompactRestore(bar);
    lens.hidden = NO;
    bar.selectedItem = [UITabBarItem new];
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    assert(!lens.hidden);
    bar.selectedItem = nil;
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    bar.selectedItem = items[1];
    bar.effectiveUserInterfaceLayoutDirection = 1;
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    bar.effectiveUserInterfaceLayoutDirection = 0;
    bar.items = @[items[0], items[1]];
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    bar.items = items;
    NEINCompactTabs(bar);
    ((UIControl *)buttons[2]).hidden = NO;
    ((UIControl *)copies[2]).hidden = NO;
    NEINCompactTabs(bar);
    assert(CGAffineTransformIsIdentity(lens.transform));
    assert(normal.subviews.count == count && selected.subviews.count == count);
}

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
        UITabBarItem *partial = [UITabBarItem new];
        partial.title = @"VOOM settings";
        assert(!NEINVisibleTabIsPromotional(partial));
        assert(NEINVisibleTabIsPromotional([VOOMSkinnedTabBarItem new]));
        assert(NEINCompactRectNear(CGRectMake(0, 0, 98, 54),
                                CGRectMake(0.1, 0, 98.00000000000003, 54)));
        assert(!NEINCompactRectNear(CGRectMake(0, 0, 98, 54),
                                 CGRectMake(0.6, 0, 98, 54)));
        assert(!NEINCompactNear(NAN, 0));
        TestCompactLayout(4, 360);
        TestCompactLayout(5, 360);
        TestCompactLayout(4, 600);
        NSMutableArray<UITabBarItem *> *items = [NSMutableArray new];
        for (NSString *title in @[@"首頁", @"聊天", @"設定", @"VOOM", @"NEWS", @"SHOPPING"]) {
            UITabBarItem *item = [UITabBarItem new];
            item.title = title;
            [items addObject:item];
        }
        NSArray *originalItems = [items copy];
        NEINUpdatePromotionalItems(items);
        NEINUpdatePromotionalItems(items); // Repeated layouts preserve original state.
        assert([items isEqualToArray:originalItems]);
        for (NSUInteger i = 0; i < items.count; i++) {
            assert(items[i].enabled == (i < 3));
        }
        assert([items[3].title isEqualToString:@"VOOM"]);
        items[3].title = @"設定";
        NEINUpdatePromotionalItems(items);
        assert(items[3].enabled);
        items[3].enabled = NO;
        items[3].title = @"VOOM";
        NEINUpdatePromotionalItems(items);
        items[3].title = @"設定";
        NEINUpdatePromotionalItems(items);
        assert(!items[3].enabled); // Do not enable an originally disabled item.
        VOOMSkinnedTabBarItem *voomItem = [VOOMSkinnedTabBarItem new];
        UITabBarItem *unknownItem = [UITabBarItem new];
        UITabBarItem *partialTitleItem = [UITabBarItem new];
        partialTitleItem.title = @"VOOM settings";
        NEINUpdatePromotionalItems(@[voomItem, unknownItem, partialTitleItem]);
        assert(!voomItem.enabled && unknownItem.enabled && partialTitleItem.enabled);
        UIView *bar = [UIView new];
        UIControl *shared = [UIControl new];
        NSMutableArray *buttons = [NSMutableArray new];
        for (NSString *title in @[@"首頁", @"聊天", @"設定", @"VOOM", @"NEWS", @"SHOPPING"]) {
            UIButton *button = [UIButton new];
            button.currentTitle = title;
            [buttons addObject:button];
        }
        shared.subviews = buttons;
        bar.subviews = @[shared];
        NEINUpdatePromotionalButtons(bar);
        assert(!bar.hidden && !shared.hidden);
        for (NSUInteger i = 0; i < buttons.count; i++) {
            assert(((UIButton *)buttons[i]).hidden == (i >= 3));
        }
        UIButton *reused = buttons[3];
        reused.currentTitle = @"聊天";
        NEINUpdatePromotionalButtons(bar);
        assert(!reused.hidden);
        reused.currentTitle = nil;
        UILabel *label = [UILabel new];
        label.text = @" VOOM ";
        reused.subviews = @[label];
        NEINUpdatePromotionalButtons(bar);
        assert(reused.hidden && !label.hidden && !shared.hidden);
        label.text = @"VOOM settings";
        NEINUpdatePromotionalButtons(bar);
        assert(!reused.hidden);
        label.text = nil;
        label.attributedText = [[NSAttributedString alloc] initWithString:@"LINE VOOM"];
        NEINUpdatePromotionalButtons(bar);
        assert(reused.hidden);
        label.attributedText = nil;
        reused.currentAttributedTitle = [[NSAttributedString alloc] initWithString:@"NEWS"];
        NEINUpdatePromotionalButtons(bar);
        assert(reused.hidden);
        reused.currentAttributedTitle = nil;
        NEINUpdatePromotionalButtons(bar);
        assert(!reused.hidden);
        reused.hidden = YES;
        reused.accessibilityLabel = @"VOOM";
        NEINUpdatePromotionalButtons(bar);
        reused.accessibilityLabel = nil;
        NEINUpdatePromotionalButtons(bar);
        assert(reused.hidden); // Preserve LINE's pre-existing hidden state.
        reused.hidden = NO;
        label.text = @"VOOM";
        UILabel *home = [UILabel new];
        home.text = @"首頁";
        reused.subviews = @[label, home];
        NEINUpdatePromotionalButtons(bar);
        assert(!reused.hidden); // A container with mixed tab labels is ambiguous.
        assert(!NEINExactPromotionalTitle(nil));
        assert(bar.subviews.count == 1 && shared.subviews.count == 6);
        label.text = @"PRIVATE_TEST_TEXT";
        label.accessibilityLabel = @"PRIVATE_TEST_ACCESSIBILITY";
        NSUInteger budget = 512;
        NSDictionary *snapshot = NEINTDView(bar, 0, &budget);
        NSData *json = [NSJSONSerialization dataWithJSONObject:snapshot options:0 error:NULL];
        assert(json != nil);
        NSString *serialized = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
        assert(![serialized containsString:@"PRIVATE_TEST"]);
        assert([snapshot[@"child_count"] unsignedIntegerValue] == 1);
        assert([snapshot[@"children"] count] == 1);
        budget = 1;
        snapshot = NEINTDView(bar, 0, &budget);
        assert(budget == 0 && [snapshot[@"children"] count] == 0);
        budget = 512;
        snapshot = NEINTDView(bar, 21, &budget);
        assert([snapshot[@"truncated"] boolValue]);
        puts("Promotional tab selection regression tests passed (view doubles).");
    }
    return 0;
}
