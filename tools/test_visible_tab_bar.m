#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>
#include <assert.h>

// View doubles validate lifecycle/delegation, not UIKit rendering or gestures.
@interface UIView : NSObject
@property CGRect frame;
@property BOOL hidden;
@property CGFloat alpha;
@property BOOL userInteractionEnabled;
@property BOOL accessibilityElementsHidden;
@property(nonatomic, weak) UIView *superview;
@property(nonatomic, strong) NSMutableArray *children;
- (instancetype)initWithFrame:(CGRect)frame;
- (void)addSubview:(UIView *)view;
- (void)removeFromSuperview;
@end
@implementation UIView
- (instancetype)init { return [self initWithFrame:CGRectZero]; }
- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super init])) {
        _frame = frame; _alpha = 1; _userInteractionEnabled = YES;
        _children = [NSMutableArray new];
    }
    return self;
}
- (void)addSubview:(UIView *)view {
    [view removeFromSuperview];
    [self.children addObject:view]; view.superview = self;
}
- (void)removeFromSuperview {
    [self.superview.children removeObjectIdenticalTo:self]; self.superview = nil;
}
@end

enum { UIUserInterfaceStyleLight = 1, UIUserInterfaceStyleDark = 2 };
enum { UIImageRenderingModeAlwaysOriginal = 1 };
@interface UITraitCollection : NSObject
@property NSInteger userInterfaceStyle;
@end
@implementation UITraitCollection @end

@interface UIImage : NSObject
@property(copy) NSString *name;
@property CGSize size;
@property(readonly) CGImageRef CGImage;
@property(readonly) CGFloat scale;
@property(readonly) NSInteger imageOrientation;
+ (instancetype)systemImageNamed:(NSString *)name;
+ (instancetype)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traits;
+ (instancetype)imageWithCGImage:(CGImageRef)image scale:(CGFloat)scale orientation:(NSInteger)orientation;
- (instancetype)imageWithRenderingMode:(NSInteger)mode;
- (void)drawInRect:(CGRect)rect;
@end
static UIImage *drawnImage;
@implementation UIImage
- (instancetype)init {
    if ((self = [super init])) _size = CGSizeMake(40, 28);
    return self;
}
+ (instancetype)systemImageNamed:(NSString *)name {
    UIImage *image = [self new]; image.name = name;
    return image;
}
+ (instancetype)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traits {
    (void)bundle; (void)traits;
    if (![name hasPrefix:@"skin-"]) return nil;
    static NSMutableDictionary *images;
    if (!images) images = [NSMutableDictionary new];
    if (!images[name]) {
        UIImage *image = [self new]; image.name = name; images[name] = image;
        if ([name hasPrefix:@"skin-call"]) image.size = CGSizeMake(64, 75);
    }
    return images[name];
}
- (instancetype)imageWithRenderingMode:(NSInteger)mode { (void)mode; return self; }
- (CGImageRef)CGImage { return NULL; }
- (CGFloat)scale { return 2; }
- (NSInteger)imageOrientation { return 0; }
+ (instancetype)imageWithCGImage:(CGImageRef)cgImage scale:(CGFloat)scale orientation:(NSInteger)orientation {
    (void)orientation;
    UIImage *image = [self new];
    image.size = CGSizeMake(CGImageGetWidth(cgImage) / scale, CGImageGetHeight(cgImage) / scale);
    return image;
}
- (void)drawInRect:(CGRect)rect { (void)rect; drawnImage = self; }
@end
@interface UIGraphicsImageRendererContext : NSObject @end
@implementation UIGraphicsImageRendererContext @end
@interface UIGraphicsImageRenderer : NSObject
@property CGSize size;
- (instancetype)initWithSize:(CGSize)size;
- (UIImage *)imageWithActions:(void (^)(UIGraphicsImageRendererContext *))actions;
@end
@implementation UIGraphicsImageRenderer
- (instancetype)initWithSize:(CGSize)size {
    if ((self = [super init])) _size = size;
    return self;
}
- (UIImage *)imageWithActions:(void (^)(UIGraphicsImageRendererContext *))actions {
    drawnImage = nil; actions(nil);
    UIImage *image = [UIImage new]; image.name = drawnImage.name; image.size = self.size;
    return image;
}
@end

#ifdef NEIN_MULTI_SKIN_THEME
@interface TestStylesheet : NSObject
@property(copy) NSString *productID;
@property BOOL isDefaultStylesheet;
@end
@implementation TestStylesheet @end
@interface _TtC17LineSharedUITheme17StylesheetManager : NSObject
@property(strong) TestStylesheet *currentStylesheet;
+ (instancetype)sharedManager;
@end
@implementation _TtC17LineSharedUITheme17StylesheetManager
+ (instancetype)sharedManager {
    static id manager;
    if (!manager) manager = [self new];
    return manager;
}
@end
#endif

@interface UITabBarItem : NSObject
@property(copy) NSString *title;
@property(copy) NSString *accessibilityLabel;
@property(strong) UIImage *image;
@property(strong) UIImage *selectedImage;
@property(copy) NSString *badgeValue;
@property(strong) id badgeColor;
@property BOOL enabled;
- (instancetype)initWithTitle:(NSString *)title image:(id)image selectedImage:(id)selectedImage;
@end
@implementation UITabBarItem
- (instancetype)initWithTitle:(NSString *)title image:(id)image selectedImage:(id)selectedImage {
    if ((self = [super init])) {
        _title = [title copy]; _image = image; _selectedImage = selectedImage; _enabled = YES;
    }
    return self;
}
@end
@class UITabBar;
@protocol UITabBarDelegate <NSObject>
- (void)tabBar:(UITabBar *)tabBar didSelectItem:(UITabBarItem *)item;
@end
enum { UITabBarItemPositioningFill = 1 };
@interface UITabBar : UIView
@property(strong) UITraitCollection *traitCollection;
@property(nonatomic, weak) id<UITabBarDelegate> delegate;
@property NSInteger itemPositioning;
@property(copy) NSArray<UITabBarItem *> *items;
@property(strong) UITabBarItem *selectedItem;
@property(strong) id standardAppearance;
@property(strong) id scrollEdgeAppearance;
@property(strong) id tintColor;
@property(strong) id unselectedItemTintColor;
@property NSInteger semanticContentAttribute;
- (void)setItems:(NSArray *)items animated:(BOOL)animated;
@end
@implementation UITabBar
- (void)setItems:(NSArray *)items animated:(BOOL)animated {
    (void)animated; self.items = items;
}
@end
@interface UIViewController : NSObject
@property(strong) UITabBarItem *tabBarItem;
@property BOOL hidesBottomBarWhenPushed;
@end
@implementation UIViewController @end
@interface UINavigationController : UIViewController
@property(copy) NSArray<UIViewController *> *viewControllers;
@end
@implementation UINavigationController @end
@class UITabBarController;
@protocol UITabBarControllerDelegate <NSObject>
@optional
- (BOOL)tabBarController:(UITabBarController *)bar shouldSelectViewController:(UIViewController *)vc;
- (void)tabBarController:(UITabBarController *)bar didSelectViewController:(UIViewController *)vc;
@end
@interface UITabBarController : UIViewController
@property(strong) UITabBar *tabBar;
@property(copy) NSArray<UIViewController *> *viewControllers;
@property(strong) UIViewController *selectedViewController;
@property(nonatomic, weak) id<UITabBarControllerDelegate> delegate;
@end
@implementation UITabBarController @end

static NSUInteger settingsOpened;
static void NEINOpenLineSettings(UITabBarController *controller) {
    (void)controller; settingsOpened++;
}

static id NEINPresentationTabAppearance(id appearance) { return [appearance copy]; }

#include "../hooks/NEINVisibleTabBar.h"

@interface TestDelegate : NSObject <UITabBarControllerDelegate>
@property BOOL deny;
@property NSUInteger notifications;
@end
@implementation TestDelegate
- (BOOL)tabBarController:(UITabBarController *)bar shouldSelectViewController:(UIViewController *)vc {
    (void)bar; (void)vc; return !self.deny;
}
- (void)tabBarController:(UITabBarController *)bar didSelectViewController:(UIViewController *)vc {
    (void)bar; (void)vc; self.notifications++;
}
@end

int main(void) {
    @autoreleasepool {
        NSMutableArray<NSNumber *> *tapTimes = [NSMutableArray new];
        for (NSUInteger i = 0; i < 9; i++) assert(!NEINRecordHomeTap(tapTimes, i * 0.5, YES));
        assert(NEINRecordHomeTap(tapTimes, 5, YES));
        assert(tapTimes.count == 0);
        for (NSUInteger i = 0; i < 9; i++) assert(!NEINRecordHomeTap(tapTimes, 10 + i * 0.5, YES));
        assert(!NEINRecordHomeTap(tapTimes, 15.01, YES));
        assert(!NEINRecordHomeTap(tapTimes, 15.02, NO) && tapTimes.count == 0);
        assert(!NEINRecordHomeTap(tapTimes, NAN, YES));
        assert(NEINIsHomeTabTitle(@"首頁") && !NEINIsHomeTabTitle(@"聊天"));
        UIView *root = [UIView new];
        UITabBarController *controller = [UITabBarController new];
        controller.tabBar = [[UITabBar alloc] initWithFrame:CGRectMake(0, 790, 402, 83)];
        [root addSubview:controller.tabBar];
        NSMutableArray *items = [NSMutableArray new], *controllers = [NSMutableArray new];
        for (NSString *title in @[@"首頁", @"聊天", @"VOOM", @"通話"]) {
            UITabBarItem *item = [[UITabBarItem alloc] initWithTitle:title image:[UIImage new] selectedImage:nil];
            UIViewController *vc = [title isEqualToString:@"聊天"]
                ? [UINavigationController new] : [UIViewController new];
            vc.tabBarItem = item;
            [items addObject:item]; [controllers addObject:vc];
        }
        controller.viewControllers = controllers; controller.tabBar.items = items;
        controller.selectedViewController = controllers[1];
        TestDelegate *delegate = [TestDelegate new]; controller.delegate = delegate;
        NEINUpdateVisibleTabBar(controller);
        NEINVisibleTabBar *presentation = objc_getAssociatedObject(controller, &NEINVisibleTabBarKey);
        assert(presentation.active && presentation.bar.items.count == 4);
        assert(presentation.bar.items.lastObject == presentation.settingsItem);
        assert(presentation.settingsItem.title.length > 0);
        assert(presentation.settingsItem.accessibilityLabel == presentation.settingsItem.title ||
               [presentation.settingsItem.accessibilityLabel isEqualToString:presentation.settingsItem.title]);
        assert(presentation.bar.items[1] != items[1]);
        assert(presentation.bar.selectedItem == presentation.bar.items[1]);
        assert(controller.tabBar.alpha == 0 && !controller.tabBar.userInteractionEnabled);
        assert(controller.tabBar.accessibilityElementsHidden);
        assert(controller.tabBar.items.count == 4 && controller.viewControllers.count == 4);
        UIViewController *selectedBeforeSettings = controller.selectedViewController;
        [presentation tabBar:presentation.bar didSelectItem:presentation.settingsItem];
        assert(settingsOpened == 1);
        assert(controller.selectedViewController == selectedBeforeSettings);
        assert(delegate.notifications == 0);
        assert(presentation.bar.selectedItem == presentation.bar.items[1]);
        for (NSUInteger i = 0; i < 9; i++) {
            [presentation.homeTapTimes addObject:@(NSProcessInfo.processInfo.systemUptime)];
        }
        [presentation tabBar:presentation.bar didSelectItem:presentation.bar.items[0]];
        assert(settingsOpened == 2 && presentation.homeTapTimes.count == 0);
        controller.selectedViewController = controllers[1];
        delegate.notifications = 0;
        NEINUpdateVisibleTabBar(controller);
        assert(((UITabBarItem *)items[2]).enabled);
        assert(NEINVisibleSourceAlpha(controller.tabBar, 0) == 0);
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.hidden);
        assert(NEINVisibleSourceAlpha(controller.tabBar, 0.5) == 0);
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(!presentation.bar.hidden && presentation.bar.alpha == 0.5);
        assert(controller.tabBar.alpha == 0);
        assert(NEINVisibleSourceAlpha(controller.tabBar, 1) == 0);
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.alpha == 1);
        presentation.suppressingSourceAppearance = YES;
        assert(NEINVisibleSourceAlpha(controller.tabBar, 0) == 0);
        presentation.suppressingSourceAppearance = NO;
        assert(presentation.originalAlpha == 1);
        assert(NEINVisibleSourceAlpha(presentation.bar, 0.5) == 0.5);
        UINavigationController *navigation = controllers[1];
        UIViewController *list = [UIViewController new], *chat = [UIViewController new];
        UIViewController *detail = [UIViewController new];
        chat.hidesBottomBarWhenPushed = YES;
        navigation.viewControllers = @[list, chat];
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.hidden); // No tap or full presentation update.
        navigation.viewControllers = @[list, chat, detail];
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.hidden);
        navigation.viewControllers = @[list];
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(!presentation.bar.hidden);
        navigation.viewControllers = @[list, chat]; // Cancelled interactive pop.
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.hidden);
        navigation.viewControllers = @[list, detail];
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(!presentation.bar.hidden); // Do not hide every pushed page.
        controller.tabBar.hidden = YES;
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(presentation.bar.hidden);
        controller.tabBar.hidden = NO;
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(!presentation.bar.hidden);
        CGRect oldFrame = controller.tabBar.frame;
        controller.tabBar.frame = CGRectOffset(oldFrame, 0, 90);
        NEINSyncSourceTabVisibility(controller.tabBar);
        assert(CGRectEqualToRect(presentation.bar.frame, controller.tabBar.frame));
        controller.tabBar.frame = oldFrame;
        NEINSyncSourceTabVisibility(controller.tabBar);
        navigation.viewControllers = @[list];
        NSArray *copies = presentation.bar.items;
        ((UITabBarItem *)items[1]).badgeValue = @"7";
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.bar.items == copies);
        assert([presentation.bar.items[1].badgeValue isEqualToString:@"7"]);
        assert(NEINGuardVisibleTabSelection(controller, 2) == 3);
        [presentation tabBar:presentation.bar didSelectItem:presentation.bar.items[2]];
        assert(controller.selectedViewController == controllers[3] && delegate.notifications == 1);
        assert(NEINGuardVisibleTabSelection(controller, 2) == 1);
        delegate.deny = YES;
        [presentation tabBar:presentation.bar didSelectItem:presentation.bar.items[0]];
        assert(controller.selectedViewController == controllers[3] && delegate.notifications == 1);
        controller.selectedViewController = controllers[2]; // Simulate bypassing setter hooks.
        NEINUpdateVisibleTabBar(controller);
        assert(controller.selectedViewController == controllers[1]);
        controller.selectedViewController = controllers[0];
        NEINUpdateVisibleTabBar(controller);
        delegate.deny = YES;
        NSUInteger routesBeforeDeniedHomeRetaps = settingsOpened;
        for (NSUInteger i = 0; i < 10; i++) {
            [presentation tabBar:presentation.bar didSelectItem:presentation.bar.items[0]];
        }
        assert(controller.selectedViewController == controllers[0]);
        assert(settingsOpened == routesBeforeDeniedHomeRetaps + 1);
        delegate.deny = NO;
        controller.selectedViewController = controllers[1];
        NEINUpdateVisibleTabBar(controller);
        controller.tabBar.frame = CGRectMake(0, 400, 700, 83);
        NEINUpdateVisibleTabBar(controller);
        assert(CGRectEqualToRect(controller.tabBar.frame, presentation.bar.frame));
        controller.tabBar.hidden = YES;
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.bar.hidden);
        controller.tabBar.hidden = NO;
        ((UITabBarItem *)items[2]).title = @"MISC";
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.active && presentation.bar.items.count == 5);
        assert(controller.tabBar.alpha == 0 && !controller.tabBar.userInteractionEnabled);
        assert(controller.tabBar.accessibilityElementsHidden);
        ((UITabBarItem *)items[2]).title = @"VOOM";
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.active && presentation.bar.items.count == 4);
        controller.viewControllers = @[controllers[0]]; // Invalid model restores original UI.
        NEINUpdateVisibleTabBar(controller);
        assert(!presentation.active && controller.tabBar.alpha == 1);

        UITabBarController *threeTabController = [UITabBarController new];
        threeTabController.tabBar = [[UITabBar alloc] initWithFrame:CGRectMake(0, 790, 402, 83)];
        [root addSubview:threeTabController.tabBar];
        NSMutableArray *threeTabItems = [NSMutableArray new];
        NSMutableArray *threeTabControllers = [NSMutableArray new];
        for (NSString *title in @[@"主頁", @"聊天", @"通話"]) {
            UITabBarItem *item = [[UITabBarItem alloc] initWithTitle:title
                image:[UIImage new] selectedImage:nil];
            UIViewController *viewController = [UIViewController new];
            viewController.tabBarItem = item;
            [threeTabItems addObject:item];
            [threeTabControllers addObject:viewController];
        }
        threeTabController.tabBar.items = threeTabItems;
        threeTabController.viewControllers = threeTabControllers;
        threeTabController.selectedViewController = threeTabControllers[1];
        assert(NEINIsMainLineTabBar(threeTabItems));
        NEINUpdateVisibleTabBar(threeTabController);
        NEINVisibleTabBar *threeTabPresentation =
            objc_getAssociatedObject(threeTabController, &NEINVisibleTabBarKey);
        assert(threeTabPresentation.active);
        assert(threeTabPresentation.bar.items.count == 4);
        assert(threeTabPresentation.bar.items.lastObject == threeTabPresentation.settingsItem);
        assert(threeTabController.tabBar.items.count == 3);
        NSUInteger routesBeforeThreeTabSettings = settingsOpened;
        [threeTabPresentation tabBar:threeTabPresentation.bar
                         didSelectItem:threeTabPresentation.settingsItem];
        assert(settingsOpened == routesBeforeThreeTabSettings + 1);
        assert(threeTabController.selectedViewController == threeTabControllers[1]);
        NSUInteger routesBeforeHomeShortcut = settingsOpened;
        for (NSUInteger i = 0; i < 9; i++) {
            [threeTabPresentation.homeTapTimes addObject:
                @(NSProcessInfo.processInfo.systemUptime)];
        }
        [threeTabPresentation tabBar:threeTabPresentation.bar
                         didSelectItem:threeTabPresentation.bar.items[0]];
        assert(settingsOpened == routesBeforeHomeShortcut + 1);
        assert(threeTabPresentation.homeTapTimes.count == 0);
        assert(!NEINIsMainLineTabBar(@[threeTabItems[0], threeTabItems[1]]));

        UITabBarController *nativeSettingsController = [UITabBarController new];
        nativeSettingsController.tabBar = [[UITabBar alloc] initWithFrame:CGRectMake(0, 790, 402, 83)];
        [root addSubview:nativeSettingsController.tabBar];
        NSMutableArray *nativeItems = [NSMutableArray new];
        NSMutableArray *nativeControllers = [NSMutableArray new];
        for (NSString *title in @[@"主頁", @"聊天", @"VOOM", @"通話", @"設定"]) {
            UITabBarItem *item = [[UITabBarItem alloc] initWithTitle:title
                image:[UIImage new] selectedImage:nil];
            UIViewController *viewController = [UIViewController new];
            viewController.tabBarItem = item;
            [nativeItems addObject:item];
            [nativeControllers addObject:viewController];
        }
        nativeSettingsController.tabBar.items = nativeItems;
        nativeSettingsController.viewControllers = nativeControllers;
        nativeSettingsController.selectedViewController = nativeControllers[4];
        NEINUpdateVisibleTabBar(nativeSettingsController);
        NEINVisibleTabBar *nativePresentation =
            objc_getAssociatedObject(nativeSettingsController, &NEINVisibleTabBarKey);
        assert(nativePresentation.active && nativePresentation.bar.items.count == 4);
        assert(nativePresentation.bar.items.lastObject != nativePresentation.settingsItem);
        assert(nativePresentation.bar.selectedItem == nativePresentation.bar.items[3]);
        assert(NEINGuardVisibleTabSelection(nativeSettingsController, 4) == 4);
        nativeSettingsController.selectedViewController = nativeControllers[0];
        NEINUpdateVisibleTabBar(nativeSettingsController);
        NSUInteger routesBeforeNativeSettings = settingsOpened;
        [nativePresentation tabBar:nativePresentation.bar
                    didSelectItem:nativePresentation.bar.items[3]];
        assert(nativeSettingsController.selectedViewController == nativeControllers[4]);
        assert(settingsOpened == routesBeforeNativeSettings);
        // LINE's own settings tab can lack artwork; the gear fills the slot.
        UITabBarItem *nativeSettings = nativeItems[4];
        id nativeArtwork = nativeSettings.image;
        nativeSettings.image = nil;
        NEINUpdateVisibleTabBar(nativeSettingsController);
        assert(nativePresentation.bar.items.count == 4);
        assert(nativePresentation.settingsItem.image && nativePresentation.settingsItem.selectedImage);
        assert(nativePresentation.bar.items[3].image == nativePresentation.settingsItem.image);
        assert(nativePresentation.bar.items[3].selectedImage == nativePresentation.settingsItem.selectedImage);
        nativeSettings.image = nativeArtwork;
        NEINUpdateVisibleTabBar(nativeSettingsController);
        assert(nativePresentation.bar.items[3].image == nativeArtwork);
        assert(nativePresentation.bar.items[3].selectedImage == nil);
        ((UITabBarItem *)nativeItems[4]).title = @"MISC";
        NEINUpdateVisibleTabBar(nativeSettingsController);
        assert(nativePresentation.bar.items.count == 5);
        assert(nativePresentation.bar.items.lastObject == nativePresentation.settingsItem);
        ((UITabBarItem *)nativeItems[4]).title = @"設定";
        NEINUpdateVisibleTabBar(nativeSettingsController);
        assert(nativePresentation.bar.items.count == 4);
        assert(nativePresentation.bar.items.lastObject != nativePresentation.settingsItem);

        UITabBarController *discoverController = [UITabBarController new];
        discoverController.tabBar = [[UITabBar alloc] initWithFrame:CGRectMake(0, 790, 402, 83)];
        [root addSubview:discoverController.tabBar];
        NSMutableArray *discoverItems = [NSMutableArray new];
        NSMutableArray *discoverControllers = [NSMutableArray new];
        for (NSString *title in @[@"主頁", @"聊天", @"逛逛", @"VOOM", @"通話"]) {
            UITabBarItem *item = [[UITabBarItem alloc] initWithTitle:title
                image:[UIImage new] selectedImage:nil];
            UIViewController *viewController = [UIViewController new];
            viewController.tabBarItem = item;
            [discoverItems addObject:item];
            [discoverControllers addObject:viewController];
        }
        discoverController.tabBar.items = discoverItems;
        discoverController.viewControllers = discoverControllers;
        discoverController.selectedViewController = discoverControllers[2];
        NEINUpdateVisibleTabBar(discoverController);
        NEINVisibleTabBar *discoverPresentation =
            objc_getAssociatedObject(discoverController, &NEINVisibleTabBarKey);
        assert(discoverPresentation.active && discoverPresentation.bar.items.count == 4);
        assert(([discoverPresentation.indices isEqualToArray:@[@0, @1, @4]]));
        for (UITabBarItem *item in discoverPresentation.bar.items) {
            assert(![item.title isEqualToString:@"逛逛"]);
        }
        // A launch-time selection of the hidden tab moves to a visible tab.
        assert(discoverController.selectedViewController == discoverControllers[4]);
        assert(NEINGuardVisibleTabSelection(discoverController, 2) == 1);
        assert(discoverController.tabBar.items.count == 5);
#ifdef NEIN_MULTI_SKIN_THEME
        CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
        CGContextRef bitmap = CGBitmapContextCreate(NULL, 128, 150, 8, 0, space,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
        CGColorSpaceRelease(space);
        CGContextSetRGBFillColor(bitmap, 1, 0, 0, 1);
        CGContextFillRect(bitmap, CGRectMake(32, 56, 64, 60));
        CGImageRef padded = CGBitmapContextCreateImage(bitmap);
        CGImageRef trimmed = NEINCreateTrimmedTabImage(padded);
        assert(trimmed && CGImageGetWidth(trimmed) == 64 && CGImageGetHeight(trimmed) == 60);
        CFDataRef trimmedData = CGDataProviderCopyData(CGImageGetDataProvider(trimmed));
        assert(CFDataGetBytePtr(trimmedData)[3] == 255);
        CFRelease(trimmedData); CGImageRelease(trimmed); CGImageRelease(padded);
        CGContextClearRect(bitmap, CGRectMake(0, 0, 128, 150));
        padded = CGBitmapContextCreateImage(bitmap);
        assert(!NEINCreateTrimmedTabImage(padded) && !NEINCreateTrimmedTabImage(NULL));
        CGImageRelease(padded); CGContextRelease(bitmap);
        TestStylesheet *sheet = [TestStylesheet new];
        sheet.productID = @"default-theme"; sheet.isDefaultStylesheet = YES;
        [_TtC17LineSharedUITheme17StylesheetManager sharedManager].currentStylesheet = sheet;
        UITraitCollection *traits = [UITraitCollection new];
        traits.userInterfaceStyle = UIUserInterfaceStyleLight;
        presentation.bar.traitCollection = traits;
        controller.viewControllers = controllers;
        NEINUpdateVisibleTabBar(controller);
        assert([((UIImage *)presentation.bar.items[0].image).name isEqualToString:@"skin-home-light.png"]);
        assert([((UIImage *)presentation.bar.items[0].selectedImage).name isEqualToString:@"skin-home-on.png"]);
        assert([((UIImage *)presentation.bar.items[1].image).name isEqualToString:@"skin-chat.png"]);
        assert([((UIImage *)presentation.bar.items[2].image).name isEqualToString:@"skin-call.png"]);
        assert([((UIImage *)presentation.bar.items[2].selectedImage).name isEqualToString:@"skin-call-on.png"]);
        CGSize callSize = ((UIImage *)presentation.bar.items[2].image).size;
        assert(callSize.width <= 40 && callSize.height <= 28);
        assert(fabs(callSize.width / callSize.height - 64.0 / 75.0) < 0.0001);
        assert(presentation.bar.items[3] == presentation.settingsItem);
        NSString *fallback = NSProcessInfo.processInfo.arguments[1];
        NSString *role = [fallback isEqualToString:@"legacy-today"] ? @"today" : fallback;
        NSString *normalName = [role isEqualToString:@"none"]
            ? @"gearshape" : [NSString stringWithFormat:@"skin-%@.png", role];
        NSString *selectedName = [role isEqualToString:@"none"]
            ? @"gearshape.fill" : [NSString stringWithFormat:@"skin-%@-on.png", role];
        assert([presentation.settingsItem.image.name isEqualToString:normalName]);
        assert([presentation.settingsItem.selectedImage.name isEqualToString:selectedName]);
        UIImage *settingsBefore = presentation.settingsItem.image;
        NEINUpdateVisibleTabBar(controller);
        assert([presentation.settingsItem.image.name isEqualToString:normalName]);
        assert(CGSizeEqualToSize(settingsBefore.size, presentation.settingsItem.image.size));
        nativePresentation.bar.traitCollection = traits;
        NEINUpdateVisibleTabBar(nativeSettingsController);
        if ([role isEqualToString:@"none"]) {
            assert(nativePresentation.bar.items[3].image == nativeSettings.image);
            nativeSettings.image = nil;
            NEINUpdateVisibleTabBar(nativeSettingsController);
        }
        assert([nativePresentation.bar.items[3].image.name isEqualToString:normalName]);
        assert([nativePresentation.bar.items[3].selectedImage.name isEqualToString:selectedName]);
        NSUInteger beforeSkinSettings = settingsOpened;
        [presentation tabBar:presentation.bar didSelectItem:presentation.settingsItem];
        assert(settingsOpened == beforeSkinSettings + 1);
        traits.userInterfaceStyle = UIUserInterfaceStyleDark;
        NEINUpdateVisibleTabBar(controller);
        assert([((UIImage *)presentation.bar.items[0].image).name isEqualToString:@"skin-home-dark.png"]);
        assert([((UIImage *)presentation.bar.items[0].selectedImage).name isEqualToString:@"skin-home-on-dark.png"]);
        sheet.productID = @"owned-theme"; sheet.isDefaultStylesheet = NO;
        NEINUpdateVisibleTabBar(controller);
        assert([((UIImage *)presentation.bar.items[0].image).name isEqualToString:@"skin-home-dark.png"]);
        sheet.productID = @"another-theme";
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.bar.items[0].image == ((UITabBarItem *)items[0]).image);
        assert([presentation.settingsItem.image.name isEqualToString:@"gearshape"]);
        assert([presentation.settingsItem.selectedImage.name isEqualToString:@"gearshape.fill"]);
        [_TtC17LineSharedUITheme17StylesheetManager sharedManager].currentStylesheet = nil;
        NEINUpdateVisibleTabBar(controller);
        assert(presentation.bar.items[1].image == ((UITabBarItem *)items[1]).image);
#endif
        puts("Native tab presentation lifecycle and selection tests passed (view doubles).");
    }
    return 0;
}
