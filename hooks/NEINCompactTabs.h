#include <math.h>

// Translation keeps UIKit's original centers/sizes and control identity intact.
// Only the floating hierarchy observed on the test device is supported.
static char NEINCompactMovedKey;
static char NEINCompactDeltaKey;
static char NEINCompactHiddenLensKey;
static char NEINCompactLensHiddenStateKey;
static char NEINCompactLensTargetKey;

@interface NEINCompactLensTarget : NSObject
@property(nonatomic, weak) UITabBar *bar;
@property(nonatomic, weak) UIControl *button;
@property(nonatomic, weak) UITabBarItem *item;
@property(nonatomic) BOOL updating;
@end
@implementation NEINCompactLensTarget @end

static BOOL NEINCompactClass(UIView *view, NSString *name) {
    return [NSStringFromClass(view.class) isEqualToString:name];
}

static BOOL NEINCompactNear(CGFloat a, CGFloat b) {
    return isfinite(a) && isfinite(b) && fabs(a - b) <= 0.5;
}

static BOOL NEINCompactRectNear(CGRect a, CGRect b) {
    return NEINCompactNear(a.origin.x, b.origin.x) &&
           NEINCompactNear(a.origin.y, b.origin.y) &&
           NEINCompactNear(a.size.width, b.size.width) &&
           NEINCompactNear(a.size.height, b.size.height);
}

static void NEINCompactAlignLens(UIView *lens, UITabBarItem *selection) {
    NEINCompactLensTarget *target = objc_getAssociatedObject(lens, &NEINCompactLensTargetKey);
    UIControl *button = target.button;
    NSNumber *previous = objc_getAssociatedObject(lens, &NEINCompactDeltaKey);
    if (!target || target.updating || !target.bar || !button ||
        !selection || selection != target.item || !selection.enabled ||
        ![target.bar.items containsObject:selection] || lens.hidden || button.hidden ||
        button.transform.a != 1 || button.transform.b != 0 ||
        button.transform.c != 0 || button.transform.d != 1 ||
        !previous || !CGAffineTransformEqualToTransform(lens.transform,
            CGAffineTransformMakeTranslation(previous.doubleValue, 0)) ||
        !NEINCompactNear(lens.bounds.size.width, button.bounds.size.width) ||
        !NEINCompactNear(lens.bounds.size.height, button.bounds.size.height)) return;
    CGFloat dx = button.center.x + button.transform.tx - lens.center.x;
    if (!isfinite(dx)) return;
    CGAffineTransform translation = CGAffineTransformMakeTranslation(dx, 0);
    if (CGAffineTransformEqualToTransform(lens.transform, translation)) return;
    target.updating = YES;
    lens.transform = translation;
    objc_setAssociatedObject(lens, &NEINCompactDeltaKey, @(dx), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    target.updating = NO;
}

static void NEINCompactRestore(UIView *bar) {
    UIView *lens = objc_getAssociatedObject(bar, &NEINCompactHiddenLensKey);
    if (lens) {
        NSNumber *hidden = objc_getAssociatedObject(lens, &NEINCompactLensHiddenStateKey);
        if (hidden) lens.hidden = hidden.boolValue;
        objc_setAssociatedObject(lens, &NEINCompactLensHiddenStateKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(bar, &NEINCompactHiddenLensKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    for (UIView *view in objc_getAssociatedObject(bar, &NEINCompactMovedKey)) {
        objc_setAssociatedObject(view, &NEINCompactLensTargetKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSNumber *delta = objc_getAssociatedObject(view, &NEINCompactDeltaKey);
        if (delta && CGAffineTransformEqualToTransform(view.transform,
                CGAffineTransformMakeTranslation(delta.doubleValue, 0))) {
            view.transform = CGAffineTransformIdentity;
        }
        objc_setAssociatedObject(view, &NEINCompactDeltaKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    objc_setAssociatedObject(bar, &NEINCompactMovedKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static NSArray<UIControl *> *NEINCompactButtons(UIView *row) {
    if (row.subviews.count < 2 || row.subviews.count > 6) return nil;
    for (UIView *view in row.subviews) {
        if (!NEINCompactClass(view, @"_UITabButton") ||
            ![view isKindOfClass:UIControl.class] ||
            !CGAffineTransformIsIdentity(view.transform)) return nil;
    }
    return [row.subviews sortedArrayUsingComparator:^NSComparisonResult(UIView *a, UIView *b) {
        return a.center.x < b.center.x ? NSOrderedAscending :
               a.center.x > b.center.x ? NSOrderedDescending : NSOrderedSame;
    }];
}

static void NEINCompactTabsForSelection(UITabBar *bar, UITabBarItem *selection) {
    NEINCompactRestore(bar);
    // The captured hierarchy is LTR; do not infer item order for other layouts.
    if (bar.effectiveUserInterfaceLayoutDirection != UIUserInterfaceLayoutDirectionLeftToRight) return;
    NSArray<UITabBarItem *> *items = bar.items;
    NSUInteger selectedIndex = selection
        ? [items indexOfObjectIdenticalTo:selection] : NSNotFound;
    if (selectedIndex == NSNotFound || selectedIndex >= items.count) return;
    UIView *platter = nil;
    for (UIView *view in bar.subviews) {
        if (NEINCompactClass(view, @"UIKit._UITabBarItemPlatterView")) {
            if (platter) return;
            platter = view;
        } else if (!NEINCompactClass(view, @"_UIPortalView") ||
                   view.frame.size.width != 0 || view.frame.size.height != 0 ||
                   view.bounds.size.width != 0 || view.bounds.size.height != 0) {
            return;
        }
    }
    if (!platter || platter.subviews.count != 5) return;
    UIView *normal = nil, *selected = nil, *lens = nil, *badges = nil;
    for (UIView *view in platter.subviews) {
        NSString *name = NSStringFromClass(view.class);
        if ([name isEqualToString:@"_TtCC5UIKit20_UITabBarPlatterViewP33_022AA364308030F4627162921FD6D31A11ContentView"]) normal = view;
        else if ([name isEqualToString:@"_TtCC5UIKit32_UITabBarVisualProvider_FloatingP33_3C6E5A7AE2316B749C88F887559DAAB619SelectedContentView"]) selected = view;
        else if ([name isEqualToString:@"_UILiquidLensView"]) lens = view;
        else if ([name isEqualToString:@"_TtCC5UIKit20_UITabBarPlatterViewP33_022AA364308030F4627162921FD6D31A18BadgeContainerView"]) badges = view;
        else if (![name isEqualToString:@"_TtCE5UIKitCSo17_UILiquidLensViewP33_4C400BD973F5E4E0B779D1A21A7AEB2711DestOutView"]) return;
    }
    if (!normal || !selected || !lens || !badges ||
        !CGAffineTransformIsIdentity(lens.transform) ||
        !NEINCompactRectNear(normal.frame, selected.frame) ||
        !NEINCompactRectNear(normal.frame, badges.frame) ||
        !NEINCompactNear(normal.frame.origin.x, 0) || !NEINCompactNear(normal.frame.origin.y, 0) ||
        !NEINCompactNear(normal.bounds.origin.x, 0) || !NEINCompactNear(normal.bounds.origin.y, 0)) return;
    NSArray<UIControl *> *buttons = NEINCompactButtons(normal);
    NSArray<UIControl *> *copies = NEINCompactButtons(selected);
    if (!buttons || buttons.count != copies.count || buttons.count != items.count) return;
    NSMutableArray<UIView *> *targets = [NSMutableArray new];
    NSMutableArray<NSNumber *> *deltas = [NSMutableArray new];
    NSMutableArray<NSNumber *> *visible = [NSMutableArray new];
    CGFloat previous = -INFINITY;
    CGFloat spacing = INFINITY;
    for (NSUInteger i = 0; i < buttons.count; i++) {
        UIControl *button = buttons[i], *copy = copies[i];
        if (!NEINCompactRectNear(button.frame, copy.frame) ||
            button.hidden != copy.hidden || button.enabled != copy.enabled ||
            button.enabled != items[i].enabled ||
            !isfinite(button.center.x) || button.center.x <= previous ||
            button.bounds.size.width <= 0) return;
        spacing = fmin(spacing, button.center.x - previous);
        previous = button.center.x;
        if (button.hidden) {
            if (button.enabled ||
                !objc_getAssociatedObject(button, &NEINTabOriginalHiddenKey) ||
                !objc_getAssociatedObject(copy, &NEINTabOriginalHiddenKey)) return;
        } else {
            [visible addObject:@(i)];
        }
    }
    if (visible.count < 2 || visible.count == buttons.count) return;
    CGFloat left = buttons.firstObject.center.x;
    CGFloat right = buttons.lastObject.center.x;
    CGFloat step = (right - left) / (visible.count - 1);
    if (!isfinite(step) || step <= 0 || left < 0 || right > normal.bounds.size.width) return;
    NSUInteger selectedRank = [visible indexOfObject:@(selectedIndex)];
    UIControl *selectedButton = buttons[selectedIndex];
    if (!isfinite(lens.center.x) ||
        !NEINCompactNear(lens.frame.origin.y, selectedButton.frame.origin.y) ||
        !NEINCompactNear(lens.bounds.size.width, selectedButton.bounds.size.width) ||
        !NEINCompactNear(lens.bounds.size.height, selectedButton.bounds.size.height)) return;
    for (NSUInteger rank = 0; rank < visible.count; rank++) {
        NSUInteger i = visible[rank].unsignedIntegerValue;
        UIControl *button = buttons[i];
        if (button.bounds.size.width > step) return;
        CGFloat dx = left + rank * step - button.center.x;
        [targets addObject:button]; [deltas addObject:@(dx)];
        [targets addObject:copies[i]];
        [deltas addObject:@(left + rank * step - copies[i].center.x)];
    }
    // UIKit can leave the lens over a hidden slot. Use actual item selection,
    // not that stale position, without changing UIKit's selection or arrays.
    if (selectedRank != NSNotFound) {
        [targets addObject:lens];
        [deltas addObject:@(left + selectedRank * step - lens.center.x)];
    }
    for (UIView *badge in badges.subviews) {
        if (!NEINCompactClass(badge, @"_UIBarBadgeView") ||
            !CGAffineTransformIsIdentity(badge.transform)) return;
        NSInteger nearest = -1;
        CGFloat distance = INFINITY;
        for (NSUInteger i = 0; i < buttons.count; i++) {
            CGFloat d = fabs(badge.center.x - buttons[i].center.x);
            if (d < distance) { distance = d; nearest = (NSInteger)i; }
        }
        if (nearest < 0 || distance >= spacing / 2) return;
        NSUInteger rank = [visible indexOfObject:@(nearest)];
        if (rank == NSNotFound) return;
        [targets addObject:badge]; [deltas addObject:deltas[rank * 2]];
    }
    if (selectedRank == NSNotFound) {
        // Keep the actual page selected, but do not highlight a hidden tab.
        objc_setAssociatedObject(lens, &NEINCompactLensHiddenStateKey, @(lens.hidden),
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(bar, &NEINCompactHiddenLensKey, lens,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        lens.hidden = YES;
    }
    for (NSUInteger i = 0; i < targets.count; i++) {
        targets[i].transform = CGAffineTransformMakeTranslation(deltas[i].doubleValue, 0);
        objc_setAssociatedObject(targets[i], &NEINCompactDeltaKey, deltas[i],
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    objc_setAssociatedObject(bar, &NEINCompactMovedKey, targets, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    if (selectedRank != NSNotFound) {
        NEINCompactLensTarget *target = [NEINCompactLensTarget new];
        target.bar = bar;
        target.button = selectedButton;
        target.item = selection;
        objc_setAssociatedObject(lens, &NEINCompactLensTargetKey, target,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
}

static inline void NEINCompactTabs(UITabBar *bar) {
    NEINCompactTabsForSelection(bar, bar.selectedItem);
}
