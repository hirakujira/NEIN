#include "NEINVisibleTabModel.h"
#include "NEINHomeTapSequence.h"

static BOOL NEINIsSettingsTabItem(UITabBarItem *item) {
    return NEINTabTitleIsOneOf(item.title,
        @[@"SETTINGS", @"設定", @"设置", @"設置", @"설정"]);
}

static char NEINVisibleTabBarKey;
static char NEINVisibleTabSourceOwnerKey;

@class NEINVisibleTabBar;
@interface NEINVisibleTabSourceOwner : NSObject
@property(nonatomic, weak) NEINVisibleTabBar *presentation;
@end
@implementation NEINVisibleTabSourceOwner @end

@interface NEINVisibleTabBar : NSObject <UITabBarDelegate>
@property(nonatomic, weak) UITabBarController *controller;
@property(nonatomic, strong) UITabBar *bar;
@property(nonatomic, strong) UITabBarItem *settingsItem;
@property(nonatomic, copy) NSArray<UITabBarItem *> *sourceItems;
@property(nonatomic, copy) NSArray<UIViewController *> *sourceControllers;
@property(nonatomic, copy) NSArray<NSNumber *> *indices;
@property(nonatomic) CGFloat originalAlpha;
@property(nonatomic) BOOL originalInteraction;
@property(nonatomic) BOOL originalAccessibilityHidden;
@property(nonatomic) BOOL active;
@property(nonatomic) BOOL updating;
@property(nonatomic) BOOL suppressingSourceAppearance;
@property(nonatomic) NSUInteger lastVisibleIndex;
@property(nonatomic, strong) NSMutableArray<NSNumber *> *homeTapTimes;
- (void)update;
- (void)deactivate;
- (BOOL)matchesCurrentModel;
- (void)syncVisibility;
@end

@implementation NEINVisibleTabBar
- (instancetype)init {
    if ((self = [super init])) {
        _lastVisibleIndex = NSNotFound;
        _homeTapTimes = [NSMutableArray new];
        _bar = [[UITabBar alloc] initWithFrame:CGRectZero];
        _bar.delegate = self;
        _bar.itemPositioning = UITabBarItemPositioningFill;
    }
    return self;
}

- (NSString *)settingsTabPresentationTitle {
    NSString *language = NSBundle.mainBundle.preferredLocalizations.firstObject.lowercaseString;
    if ([language hasPrefix:@"en"]) return @"Settings";
    if ([language hasPrefix:@"zh-hans"]) return @"设置";
    if ([language hasPrefix:@"ko"]) return @"설정";
    return @"設定";
}

- (UITabBarItem *)newSettingsItem {
    NSString *title = [self settingsTabPresentationTitle];
    UITabBarItem *item = [[UITabBarItem alloc] initWithTitle:title
        image:[UIImage systemImageNamed:@"gearshape"]
        selectedImage:[UIImage systemImageNamed:@"gearshape.fill"]];
    item.accessibilityLabel = title;
    return item;
}

- (BOOL)matchesCurrentModel {
    UITabBarController *controller = self.controller;
    if (!controller || controller.viewControllers.count != self.sourceControllers.count ||
        controller.tabBar.items.count != self.sourceItems.count) return NO;
    for (NSUInteger i = 0; i < self.sourceItems.count; i++) {
        if (controller.viewControllers[i] != self.sourceControllers[i] ||
            controller.tabBar.items[i] != self.sourceItems[i] ||
            controller.viewControllers[i].tabBarItem != self.sourceItems[i]) return NO;
    }
    return YES;
}

- (void)deactivate {
    if (self.active) {
        UITabBar *source = self.controller.tabBar;
        objc_setAssociatedObject(source, &NEINVisibleTabSourceOwnerKey, nil,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        source.alpha = self.originalAlpha;
        source.userInteractionEnabled = self.originalInteraction;
        source.accessibilityElementsHidden = self.originalAccessibilityHidden;
    }
    self.active = NO;
    self.lastVisibleIndex = NSNotFound;
    [self.homeTapTimes removeAllObjects];
    [self.bar removeFromSuperview];
}

- (void)syncVisibility {
    if (!self.active) return;
    UITabBarController *controller = self.controller;
    UITabBar *source = controller.tabBar;
    if (!source.superview) {
        self.bar.hidden = YES;
        return;
    }
    if (self.bar.superview != source.superview) [source.superview addSubview:self.bar];
    if (!CGRectEqualToRect(self.bar.frame, source.frame)) self.bar.frame = source.frame;
    if (self.bar.alpha != self.originalAlpha) self.bar.alpha = self.originalAlpha;
    BOOL hidden = source.hidden || self.originalAlpha == 0;
    UIViewController *selected = controller.selectedViewController;
    if ([selected isKindOfClass:UINavigationController.class]) {
        NSArray<UIViewController *> *stack = ((UINavigationController *)selected).viewControllers;
        // A pushed controller's request persists until it leaves the stack.
        for (NSUInteger i = 1; i < stack.count; i++) {
            if (stack[i].hidesBottomBarWhenPushed) { hidden = YES; break; }
        }
    }
    if (self.bar.hidden != hidden) self.bar.hidden = hidden;
    if (hidden) [self.homeTapTimes removeAllObjects];
}

- (void)update {
    if (self.updating) return;
    self.updating = YES;
    @try {
        UITabBarController *controller = self.controller;
        UITabBar *source = controller.tabBar;
        NSArray<UITabBarItem *> *items = source.items;
        NSArray<UIViewController *> *controllers = controller.viewControllers;
        NSArray<NSNumber *> *indices = NEINVisibleTabIndices(items);
        BOOL valid = items.count == controllers.count && indices.count >= 2 &&
                     NEINIsMainLineTabBar(items) && source.superview != nil;
        for (NSUInteger i = 0; valid && i < items.count; i++) {
            valid = ((UIViewController *)controllers[i]).tabBarItem == items[i];
        }
        if (!valid) { [self deactivate]; return; }
        if (!self.settingsItem) self.settingsItem = [self newSettingsItem];
        BOOL hasNativeSettings = NO;
        for (NSNumber *index in indices) {
            if (NEINIsSettingsTabItem(items[index.unsignedIntegerValue])) {
                hasNativeSettings = YES;
                break;
            }
        }
        BOOL rebuild = ![self matchesCurrentModel] || ![indices isEqualToArray:self.indices] ||
                       self.bar.items.count != indices.count + !hasNativeSettings ||
                       (self.bar.items.lastObject == self.settingsItem) != !hasNativeSettings;
        self.sourceItems = items;
        self.sourceControllers = controllers;
        self.indices = indices;
        if (rebuild) {
            self.lastVisibleIndex = NSNotFound;
            [self.homeTapTimes removeAllObjects];
            NSMutableArray *copies = [NSMutableArray new];
            for (NSNumber *index in indices) {
                UITabBarItem *item = items[index.unsignedIntegerValue];
                [copies addObject:[[UITabBarItem alloc] initWithTitle:item.title
                    image:item.image selectedImage:item.selectedImage]];
            }
            if (!hasNativeSettings) [copies addObject:self.settingsItem];
            [self.bar setItems:copies animated:NO];
        }
        for (NSUInteger i = 0; i < indices.count; i++) {
            UITabBarItem *item = items[indices[i].unsignedIntegerValue];
            UITabBarItem *copy = self.bar.items[i];
            if (copy.title != item.title && ![copy.title isEqualToString:item.title]) copy.title = item.title;
            if (copy.image != item.image) copy.image = item.image;
            if (copy.selectedImage != item.selectedImage) copy.selectedImage = item.selectedImage;
            if (copy.badgeValue != item.badgeValue && ![copy.badgeValue isEqualToString:item.badgeValue]) copy.badgeValue = item.badgeValue;
            if (copy.badgeColor != item.badgeColor) copy.badgeColor = item.badgeColor;
            if (copy.enabled != item.enabled) copy.enabled = item.enabled;
        }
        if (!self.active) {
            self.originalAlpha = source.alpha;
            self.originalInteraction = source.userInteractionEnabled;
            self.originalAccessibilityHidden = source.accessibilityElementsHidden;
            self.bar.standardAppearance = [source.standardAppearance copy];
            self.bar.scrollEdgeAppearance = [source.scrollEdgeAppearance copy];
            self.active = YES;
            NEINVisibleTabSourceOwner *owner = [NEINVisibleTabSourceOwner new];
            owner.presentation = self;
            objc_setAssociatedObject(source, &NEINVisibleTabSourceOwnerKey, owner,
                                     OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        if (self.bar.tintColor != source.tintColor) self.bar.tintColor = source.tintColor;
        if (self.bar.unselectedItemTintColor != source.unselectedItemTintColor) self.bar.unselectedItemTintColor = source.unselectedItemTintColor;
        if (self.bar.semanticContentAttribute != source.semanticContentAttribute) self.bar.semanticContentAttribute = source.semanticContentAttribute;
        [self syncVisibility];
        // Retain the source bar's frame and safe-area reservation, but disable
        // its rendering, accessibility and gestures together.
        if (source.alpha != 0) {
            self.suppressingSourceAppearance = YES;
            @try { source.alpha = 0; }
            @finally { self.suppressingSourceAppearance = NO; }
        }
        if (source.userInteractionEnabled) source.userInteractionEnabled = NO;
        if (!source.accessibilityElementsHidden) source.accessibilityElementsHidden = YES;

        NSUInteger selected = [controllers indexOfObjectIdenticalTo:controller.selectedViewController];
        NSUInteger destination = NEINVisibleTabDestination(items, self.lastVisibleIndex, selected);
        if (destination != NSNotFound && destination != selected) {
            controller.selectedViewController = controllers[destination];
            selected = [controllers indexOfObjectIdenticalTo:controller.selectedViewController];
        }
        NSUInteger presentationIndex = [indices indexOfObject:@(selected)];
        UITabBarItem *selectedItem = presentationIndex == NSNotFound ? nil : self.bar.items[presentationIndex];
        if (self.bar.selectedItem != selectedItem) self.bar.selectedItem = selectedItem;
        if (presentationIndex != NSNotFound) self.lastVisibleIndex = selected;
    } @finally {
        self.updating = NO;
    }
}

- (void)tabBar:(UITabBar *)tabBar didSelectItem:(UITabBarItem *)item {
    if (!self.active || self.updating || ![self matchesCurrentModel]) { [self update]; return; }
    if (item == self.settingsItem) {
        [self.homeTapTimes removeAllObjects];
        NEINOpenLineSettings(self.controller);
        [self update];
        return;
    }
    NSUInteger index = [tabBar.items indexOfObjectIdenticalTo:item];
    if (index >= self.indices.count) return;
    NSUInteger original = self.indices[index].unsignedIntegerValue;
    UITabBarItem *source = self.sourceItems[original];
    BOOL homeItem = NEINIsHomeTabTitle(source.title);
    if (!homeItem) [self.homeTapTimes removeAllObjects];
    if (NEINVisibleTabIsPromotional(source) || !source.enabled) { [self update]; return; }
    UITabBarController *controller = self.controller;
    UIViewController *destination = self.sourceControllers[original];
    id<UITabBarControllerDelegate> delegate = controller.delegate;
    if ([delegate respondsToSelector:@selector(tabBarController:shouldSelectViewController:)] &&
        ![delegate tabBarController:controller shouldSelectViewController:destination]) {
        BOOL openSettings = NEINRecordHomeTap(self.homeTapTimes,
            NSProcessInfo.processInfo.systemUptime,
            homeItem && controller.selectedViewController == destination);
        [self update];
        if (openSettings) NEINOpenLineSettings(controller);
        return;
    }
    if (![self matchesCurrentModel]) { [self update]; return; }
    controller.selectedViewController = destination;
    if (controller.selectedViewController == destination &&
        [delegate respondsToSelector:@selector(tabBarController:didSelectViewController:)]) {
        [delegate tabBarController:controller didSelectViewController:destination];
    }
    [self update];
    BOOL home = controller.selectedViewController == destination && homeItem;
    if (NEINRecordHomeTap(self.homeTapTimes, NSProcessInfo.processInfo.systemUptime, home)) {
        NEINOpenLineSettings(controller);
    }
}
@end

static void NEINSyncSourceTabVisibility(UITabBar *source) {
    NEINVisibleTabSourceOwner *owner = objc_getAssociatedObject(source, &NEINVisibleTabSourceOwnerKey);
    [owner.presentation syncVisibility];
}

static CGFloat NEINVisibleSourceAlpha(UITabBar *source, CGFloat requested) {
    NEINVisibleTabSourceOwner *owner = objc_getAssociatedObject(source, &NEINVisibleTabSourceOwnerKey);
    NEINVisibleTabBar *presentation = owner.presentation;
    if (!presentation.active) return requested;
    if (!presentation.suppressingSourceAppearance) presentation.originalAlpha = requested;
    return 0;
}

static void NEINUpdateVisibleTabBar(UITabBarController *controller) {
    NEINVisibleTabBar *presentation = objc_getAssociatedObject(controller, &NEINVisibleTabBarKey);
    if (!presentation) {
        if (!NEINIsMainLineTabBar(controller.tabBar.items)) return;
        presentation = [NEINVisibleTabBar new];
        presentation.controller = controller;
        objc_setAssociatedObject(controller, &NEINVisibleTabBarKey, presentation,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    [presentation update];
}

static NSUInteger NEINGuardVisibleTabSelection(UITabBarController *controller, NSUInteger requested) {
    NEINVisibleTabBar *presentation = objc_getAssociatedObject(controller, &NEINVisibleTabBarKey);
    if (!presentation.active || ![presentation matchesCurrentModel] ||
        requested >= presentation.sourceItems.count) return requested;
    NSUInteger current = [presentation.sourceControllers
                           indexOfObjectIdenticalTo:controller.selectedViewController];
    return NEINVisibleTabDestination(presentation.sourceItems, current, requested);
}
