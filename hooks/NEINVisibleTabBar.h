#include "NEINVisibleTabModel.h"
#include "NEINHomeTapSequence.h"

static BOOL NEINIsSettingsTabItem(UITabBarItem *item) {
    return NEINTabTitleIsOneOf(item.title,
        @[@"SETTINGS", @"設定", @"设置", @"設置", @"설정"]);
}

#ifdef NEIN_MULTI_SKIN_THEME
#import "NEINThemeConfig.h"

static CGImageRef NEINCreateTrimmedTabImage(CGImageRef source) {
    if (!source) return NULL;
    size_t width = CGImageGetWidth(source), height = CGImageGetHeight(source);
    CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
    if (!space) return NULL;
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, 0, space,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(space);
    if (!context) return NULL;
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), source);
    const uint8_t *pixels = CGBitmapContextGetData(context);
    size_t stride = CGBitmapContextGetBytesPerRow(context);
    size_t left = width, top = height, right = 0, bottom = 0;
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            if (!pixels[y * stride + x * 4 + 3]) continue;
            left = MIN(left, x); top = MIN(top, y);
            right = MAX(right, x + 1); bottom = MAX(bottom, y + 1);
        }
    }
    CGImageRef trimmed = NULL;
    if (right > left && bottom > top) {
        CGImageRef normalized = CGBitmapContextCreateImage(context);
        if (normalized) {
            trimmed = CGImageCreateWithImageInRect(normalized,
                CGRectMake(left, top, right - left, bottom - top));
            CGImageRelease(normalized);
        }
    }
    CGContextRelease(context);
    return trimmed;
}

static UIImage *NEINSkinTabImage(UITabBarItem *item, BOOL selected, UITraitCollection *traits, CGSize slot) {
    id manager = NSClassFromString(@"_TtC17LineSharedUITheme17StylesheetManager");
    if (![manager respondsToSelector:@selector(sharedManager)]) return nil;
    manager = [manager performSelector:@selector(sharedManager)];
    if (![manager respondsToSelector:@selector(currentStylesheet)]) return nil;
    id sheet = [manager performSelector:@selector(currentStylesheet)];
    if (![sheet respondsToSelector:@selector(productID)] ||
        ![sheet respondsToSelector:@selector(isDefaultStylesheet)]) return nil;
    NSString *productID = [sheet performSelector:@selector(productID)];
    if (![[sheet valueForKey:@"isDefaultStylesheet"] boolValue] &&
        ![productID isEqualToString:[NSString stringWithUTF8String:NEINSkinThemeTarget]]) return nil;

    NSString *role = nil;
    if (NEINIsHomeTabTitle(item.title)) role = @"home";
    else if (NEINTabTitleIsOneOf(item.title, @[@"CHAT", @"CHATS", @"聊天", @"トーク", @"채팅"])) role = @"chat";
    else if (NEINTabTitleIsOneOf(item.title, @[@"CALL", @"CALLS", @"通話", @"통화"])) role = @"call";
    else if (NEINIsSettingsTabItem(item)) role = @"setting";
    if (!role) return nil;

    // The default stylesheet is reskinned, but LINE's default-tab generator bypasses its artwork.
    static NSDictionary *rules;
    static NSCache *images;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *data = [NSData dataWithContentsOfURL:[NSBundle.mainBundle URLForResource:@"default" withExtension:@"json"]];
        id json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
        if ([json isKindOfClass:NSDictionary.class]) rules = json;
        images = [NSCache new];
    });
    NSArray<NSString *> *styles = [role isEqualToString:@"setting"]
        ? @[@"liquid.tabBar.today", @"line.tabBar.today",
            @"liquid.tabBar.voom", @"line.tabBar.voom",
            @"liquid.tabBar.wallet", @"line.tabBar.wallet"]
        : @[[@"liquid.tabBar." stringByAppendingString:role],
            [@"line.tabBar." stringByAppendingString:role]];
    for (NSString *style in styles) {
        id rule = rules[style];
        if (![rule isKindOfClass:NSDictionary.class]) continue;
        id states = rule[@"icon.image"];
        if (![states isKindOfClass:NSDictionary.class]) continue;
        id name = states[selected ? @"selected" : @"normal"];
        if ([name isKindOfClass:NSDictionary.class]) {
            name = name[traits.userInterfaceStyle == UIUserInterfaceStyleDark ? @"dark" : @"light"];
        }
        if (![name isKindOfClass:NSString.class]) continue;
        NSString *cacheKey = [NSString stringWithFormat:@"%@:%g:%g:%ld", name,
            slot.width, slot.height, (long)traits.userInterfaceStyle];
        UIImage *cached = [images objectForKey:cacheKey];
        if (cached) return cached;
        UIImage *image = [UIImage imageNamed:name inBundle:NSBundle.mainBundle compatibleWithTraitCollection:traits];
        if (!image) continue;
        if ([style hasPrefix:@"line.tabBar."]) {
            // Legacy artwork includes the old bar's transparent title area.
            CGImageRef trimmed = NEINCreateTrimmedTabImage(image.CGImage);
            if (trimmed) {
                image = [UIImage imageWithCGImage:trimmed scale:image.scale orientation:image.imageOrientation];
                CGImageRelease(trimmed);
            }
        }
        if (slot.width > 0 && slot.height > 0 &&
            (image.size.width > slot.width || image.size.height > slot.height)) {
            // Legacy tab art is taller than the Liquid Glass icon slot.
            CGFloat scale = MIN(slot.width / image.size.width, slot.height / image.size.height);
            CGSize size = CGSizeMake(image.size.width * scale, image.size.height * scale);
            image = [[[UIGraphicsImageRenderer alloc] initWithSize:size] imageWithActions:^(UIGraphicsImageRendererContext *context) {
                (void)context;
                [image drawInRect:(CGRect){CGPointZero, size}];
            }];
        }
        image = [image imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
        [images setObject:image forKey:cacheKey];
        return image;
    }
    return nil;
}
#endif

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

// LINE adds its own settings tab once settings has been opened, but leaves
// that item without artwork. Show the gear there instead of a blank slot.
- (UIImage *)imageForSourceItem:(UITabBarItem *)item selected:(BOOL)selected {
#ifdef NEIN_MULTI_SKIN_THEME
    CGSize slot = NEINIsSettingsTabItem(item)
        ? self.controller.tabBar.items.firstObject.image.size : item.image.size;
    UIImage *skin = NEINSkinTabImage(item, selected, self.bar.traitCollection, slot);
    if (skin) return skin;
    if (item == self.settingsItem) return [UIImage systemImageNamed:selected ? @"gearshape.fill" : @"gearshape"];
#endif
    if (item.image || !NEINIsSettingsTabItem(item)) return selected ? item.selectedImage : item.image;
    return selected ? self.settingsItem.selectedImage : self.settingsItem.image;
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
#ifdef NEIN_MULTI_SKIN_THEME
        UIImage *settingsImage = [self imageForSourceItem:self.settingsItem selected:NO];
        UIImage *settingsSelectedImage = [self imageForSourceItem:self.settingsItem selected:YES];
        if (self.settingsItem.image != settingsImage) self.settingsItem.image = settingsImage;
        if (self.settingsItem.selectedImage != settingsSelectedImage) self.settingsItem.selectedImage = settingsSelectedImage;
#endif
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
                    image:[self imageForSourceItem:item selected:NO]
                    selectedImage:[self imageForSourceItem:item selected:YES]]];
            }
            if (!hasNativeSettings) [copies addObject:self.settingsItem];
            [self.bar setItems:copies animated:NO];
        }
        for (NSUInteger i = 0; i < indices.count; i++) {
            UITabBarItem *item = items[indices[i].unsignedIntegerValue];
            UITabBarItem *copy = self.bar.items[i];
            if (copy.title != item.title && ![copy.title isEqualToString:item.title]) copy.title = item.title;
            UIImage *image = [self imageForSourceItem:item selected:NO];
            UIImage *selectedImage = [self imageForSourceItem:item selected:YES];
            if (copy.image != image) copy.image = image;
            if (copy.selectedImage != selectedImage) copy.selectedImage = selectedImage;
            if (copy.badgeValue != item.badgeValue && ![copy.badgeValue isEqualToString:item.badgeValue]) copy.badgeValue = item.badgeValue;
            if (copy.badgeColor != item.badgeColor) copy.badgeColor = item.badgeColor;
            if (copy.enabled != item.enabled) copy.enabled = item.enabled;
        }
        if (!self.active) {
            self.originalAlpha = source.alpha;
            self.originalInteraction = source.userInteractionEnabled;
            self.originalAccessibilityHidden = source.accessibilityElementsHidden;
            self.bar.standardAppearance = NEINPresentationTabAppearance(source.standardAppearance);
            self.bar.scrollEdgeAppearance = NEINPresentationTabAppearance(source.scrollEdgeAppearance);
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
    if (NEINIsPromotionalTabItem(source) || !source.enabled) { [self update]; return; }
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
