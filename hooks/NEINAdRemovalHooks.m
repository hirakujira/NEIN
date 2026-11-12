// Disable known advertising loaders and remove their views without touching
// chat content or ordinary LINE network requests.
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include "NEINObjCRuntime.h"

typedef void (*NEINVoidNoArgIMP)(id, SEL);
typedef void (*NEINVoidBoolIMP)(id, SEL, BOOL);

#ifdef NEIN_MULTI_REMOVE_ADS
static void NEINNoopObject(id self, SEL selector, id object) {
    (void)self;
    (void)selector;
    (void)object;
}

static void NEINNoopObjectObject(id self, SEL selector, id object, id handler) {
    (void)self;
    (void)selector;
    (void)object;
    (void)handler;
}

static void NEINNoopNoArg(id self, SEL selector) {
    (void)self;
    (void)selector;
}

static NSError *NEINAdLoadBlockedError(void) {
    return [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCancelled
                           userInfo:@{NSLocalizedDescriptionKey: @"Advertising disabled"}];
}

static void NEINFailAdLoad(id self, SEL selector, id unitID, id request, id completion) {
    (void)self;
    (void)selector;
    (void)unitID;
    (void)request;
    if (!completion) return;
    void (^handler)(id, NSError *) = [completion copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        handler(nil, NEINAdLoadBlockedError());
    });
}

static BOOL NEINNameContains(NSString *name, NSArray<NSString *> *tokens) {
    for (NSString *token in tokens) {
        if ([name rangeOfString:token options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static NSArray<NSString *> *NEINAdvertisingClassTokens(void) {
    static NSArray<NSString *> *tokens;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        tokens = @[
            @"GAD", @"LAD", @"LineAdvertise", @"Advertise",
            @"AdView", @"AdCell", @"BannerAd", @"GoogleAd",
            @"SquareAd", @"SmartChAd", @"HomeTabAd", @"WalletAd",
            @"ChatAd", @"NewsAd", @"RCAd", @"AdHeader", @"AdSkeleton",
        ];
    });
    return tokens;
}

static BOOL NEINIsAdvertisingView(UIView *view) {
    static NSMapTable *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cache = [NSMapTable strongToStrongObjectsMapTable];
    });
    Class viewClass = view.class;
    NSNumber *cached = [cache objectForKey:viewClass];
    if (cached) return cached.boolValue;
    BOOL result = NEINNameContains(NSStringFromClass(viewClass),
                                 NEINAdvertisingClassTokens());
    [cache setObject:@(result) forKey:viewClass];
    return result;
}

static void NEINHideAdvertisingView(UIView *view) {
    // Keep the hierarchy intact. LINE's ad view models may still deliver
    // callbacks after a request is cancelled.
    if (!view.hidden) view.hidden = YES;
    if (view.alpha != 0.0) view.alpha = 0.0;
    if (view.userInteractionEnabled) view.userInteractionEnabled = NO;
    if (!view.accessibilityElementsHidden) view.accessibilityElementsHidden = YES;
    if (view.isAccessibilityElement) view.isAccessibilityElement = NO;
}

static void NEINHideAdvertisingSubviews(UIView *root) {
    for (UIView *view in [root.subviews copy]) {
        if (NEINIsAdvertisingView(view)) {
            NEINHideAdvertisingView(view);
        } else {
            NEINHideAdvertisingSubviews(view);
        }
    }
}

static NEINVoidNoArgIMP NEINOriginalViewDidMoveToSuperview;

static void NEINViewDidMoveToSuperview(id self, SEL selector) {
    if (NEINOriginalViewDidMoveToSuperview) {
        NEINOriginalViewDidMoveToSuperview(self, selector);
    }
    UIView *view = (UIView *)self;
    if (NEINIsAdvertisingView(view)) NEINHideAdvertisingView(view);
}

static NEINVoidBoolIMP NEINOriginalViewDidAppear;

static void NEINViewControllerDidAppear(id self, SEL selector, BOOL animated) {
    if (NEINOriginalViewDidAppear) NEINOriginalViewDidAppear(self, selector, animated);
    UIView *view = [(UIViewController *)self viewIfLoaded];
    if (view) NEINHideAdvertisingSubviews(view);
}

static void NEINInstallAdvertisingLoaderHooks(void) {
    Class interstitial = NSClassFromString(@"GADInterstitialAd");
    if (interstitial) {
        NEINHook(interstitial, @selector(presentFromRootViewController:), "v", 3, "@", NULL,
               (IMP)NEINNoopObject, NULL);
        NEINHookClassMethod(interstitial,
               @selector(loadWithAdUnitID:request:completionHandler:), "v", 5, "@", "@",
               (IMP)NEINFailAdLoad, NULL);
    }
    Class rewarded = NSClassFromString(@"GADRewardedAd");
    if (rewarded) {
        NEINHook(rewarded, @selector(presentFromRootViewController:userDidEarnRewardHandler:),
               "v", 4, "@", "@?", (IMP)NEINNoopObjectObject, NULL);
        NEINHookClassMethod(rewarded,
               @selector(loadWithAdUnitID:request:completionHandler:), "v", 5, "@", "@",
               (IMP)NEINFailAdLoad, NULL);
    }
    Class appOpen = NSClassFromString(@"GADAppOpenAd");
    if (appOpen) {
        NEINHook(appOpen, @selector(presentFromRootViewController:), "v", 3, "@", NULL,
               (IMP)NEINNoopObject, NULL);
        NEINHookClassMethod(appOpen,
               @selector(loadWithAdUnitID:request:completionHandler:), "v", 5, "@", "@",
               (IMP)NEINFailAdLoad, NULL);
    }
    Class rewardedInterstitial = NSClassFromString(@"GADRewardedInterstitialAd");
    if (rewardedInterstitial) {
        NEINHookClassMethod(rewardedInterstitial,
               @selector(loadWithAdUnitID:request:completionHandler:), "v", 5, "@", "@",
               (IMP)NEINFailAdLoad, NULL);
    }
    Class gamInterstitial = NSClassFromString(@"GAMInterstitialAd");
    if (gamInterstitial) {
        NEINHookClassMethod(gamInterstitial,
               @selector(loadWithAdManagerAdUnitID:request:completionHandler:), "v", 5,
               "@", "@", (IMP)NEINFailAdLoad, NULL);
    }
    Class imaManager = NSClassFromString(@"IMAAdsManager");
    if (imaManager) {
        NEINHook(imaManager, @selector(start), "v", 2, NULL, NULL,
               (IMP)NEINNoopNoArg, NULL);
    }
}

static void NEINInstallAdvertisingCleanupHook(void) {
    Class view = UIView.class;
    NEINHook(view, @selector(didMoveToSuperview), "v", 2, NULL, NULL,
           (IMP)NEINViewDidMoveToSuperview,
           (IMP *)&NEINOriginalViewDidMoveToSuperview);
    Class controller = UIViewController.class;
    NEINHook(controller, @selector(viewDidAppear:), "v", 3, "B", NULL,
           (IMP)NEINViewControllerDidAppear, (IMP *)&NEINOriginalViewDidAppear);
}
#endif

#ifdef NEIN_MULTI_HIDE_PROMOTIONAL_TABS
static void NEINOpenLineSettings(UITabBarController *controller) {
    // Route inside this app. UIApplication.openURL could launch the original LINE.
    if (!controller.viewIfLoaded.window || controller.presentedViewController) return;
    id<UIApplicationDelegate> delegate = UIApplication.sharedApplication.delegate;
    SEL selector = @selector(application:openURL:options:);
    NSURL *url = [NSURL URLWithString:@"line://nv/settings"];
    if ([delegate respondsToSelector:selector] &&
        [delegate application:UIApplication.sharedApplication openURL:url options:@{}]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"NEIN"
        message:@"目前無法透過內部路由開啟設定，請稍後再試。"
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

// LINE's tab icons are pre-colored bitmaps, so its appearance leaves template
// icons such as the gear on the default blue tint. Match the selected title.
static UITabBarAppearance *NEINPresentationTabAppearance(UITabBarAppearance *source) {
    UITabBarAppearance *appearance = [source copy];
    if (!appearance) return nil;
    for (UITabBarItemAppearance *layout in @[appearance.stackedLayoutAppearance,
                                             appearance.inlineLayoutAppearance,
                                             appearance.compactInlineLayoutAppearance]) {
        UIColor *color = layout.selected.titleTextAttributes[NSForegroundColorAttributeName];
        layout.selected.iconColor = [color isKindOfClass:UIColor.class] ? color : UIColor.labelColor;
    }
    return appearance;
}

#include "NEINVisibleTabBar.h"

static NEINVoidNoArgIMP NEINOriginalTabBarLayout;
static NEINVoidNoArgIMP NEINOriginalSourceTabBarLayout;
static void (*NEINOriginalSelectedIndex)(id, SEL, NSUInteger);
static void (*NEINOriginalSelectedController)(id, SEL, UIViewController *);
static void (*NEINOriginalTabHidden)(id, SEL, BOOL);
static void (*NEINOriginalTabAlpha)(id, SEL, CGFloat);
static void (*NEINOriginalTabFrame)(id, SEL, CGRect);
static void (*NEINOriginalTabCenter)(id, SEL, CGPoint);
static void (*NEINOriginalTabBounds)(id, SEL, CGRect);
static void (*NEINOriginalTabTransform)(id, SEL, CGAffineTransform);
static NEINVoidNoArgIMP NEINOriginalNavigationWillLayout;

static void NEINSourceTabSetHidden(id self, SEL selector, BOOL hidden) {
    NEINOriginalTabHidden(self, selector, hidden);
    NEINSyncSourceTabVisibility(self);
}

static void NEINSourceTabSetAlpha(id self, SEL selector, CGFloat alpha) {
    NEINOriginalTabAlpha(self, selector, NEINVisibleSourceAlpha(self, alpha));
    NEINSyncSourceTabVisibility(self);
}

static void NEINSourceTabSetFrame(id self, SEL selector, CGRect frame) {
    NEINOriginalTabFrame(self, selector, frame);
    NEINSyncSourceTabVisibility(self);
}

static void NEINSourceTabSetCenter(id self, SEL selector, CGPoint center) {
    NEINOriginalTabCenter(self, selector, center);
    NEINSyncSourceTabVisibility(self);
}

static void NEINSourceTabSetBounds(id self, SEL selector, CGRect bounds) {
    NEINOriginalTabBounds(self, selector, bounds);
    NEINSyncSourceTabVisibility(self);
}

static void NEINSourceTabSetTransform(id self, SEL selector, CGAffineTransform transform) {
    NEINOriginalTabTransform(self, selector, transform);
    NEINSyncSourceTabVisibility(self);
}

static void NEINNavigationWillLayout(id self, SEL selector) {
    if (NEINOriginalNavigationWillLayout) NEINOriginalNavigationWillLayout(self, selector);
    UITabBarController *controller = [(UINavigationController *)self tabBarController];
    NEINVisibleTabBar *presentation = objc_getAssociatedObject(controller, &NEINVisibleTabBarKey);
    [presentation syncVisibility];
}

static void NEINTabBarControllerDidLayoutSubviews(id self, SEL selector) {
    if (NEINOriginalTabBarLayout) NEINOriginalTabBarLayout(self, selector);
    if (![self isKindOfClass:UITabBarController.class]) return;
    NEINUpdateVisibleTabBar(self);
}

static void NEINSourceTabBarLayout(id self, SEL selector) {
    if (NEINOriginalSourceTabBarLayout) NEINOriginalSourceTabBarLayout(self, selector);
    for (UIResponder *responder = [(UITabBar *)self nextResponder]; responder;
         responder = responder.nextResponder) {
        if ([responder isKindOfClass:UITabBarController.class] &&
            ((UITabBarController *)responder).tabBar == self) {
            NEINUpdateVisibleTabBar((UITabBarController *)responder);
            return;
        }
    }
}

static void NEINSetVisibleSelectedIndex(id self, SEL selector, NSUInteger requested) {
    NSUInteger destination = NEINGuardVisibleTabSelection(self, requested);
    if (destination == NSNotFound && requested != NSNotFound) return;
    NEINOriginalSelectedIndex(self, selector, destination);
}

static void NEINSetVisibleSelectedController(id self, SEL selector, UIViewController *requested) {
    UITabBarController *controller = self;
    NSArray<UIViewController *> *controllers = controller.viewControllers;
    NSUInteger index = requested ? [controllers indexOfObjectIdenticalTo:requested] : NSNotFound;
    if (index != NSNotFound) {
        NSUInteger destination = NEINGuardVisibleTabSelection(controller, index);
        if (destination == NSNotFound) return;
        if (destination < controllers.count) requested = controllers[destination];
    }
    NEINOriginalSelectedController(self, selector, requested);
}

static void NEINInstallPromotionalTabHooks(void) {
    NEINHookOwnMethod(UITabBar.class, @selector(setAlpha:), "v", 3, @encode(CGFloat), NULL,
                    (IMP)NEINSourceTabSetAlpha, (IMP *)&NEINOriginalTabAlpha);
    NEINHookOwnMethod(UITabBar.class, @selector(setHidden:), "v", 3, @encode(BOOL), NULL,
                    (IMP)NEINSourceTabSetHidden, (IMP *)&NEINOriginalTabHidden);
    NEINHookOwnMethod(UITabBar.class, @selector(setFrame:), "v", 3, @encode(CGRect), NULL,
                    (IMP)NEINSourceTabSetFrame, (IMP *)&NEINOriginalTabFrame);
    NEINHookOwnMethod(UITabBar.class, @selector(setCenter:), "v", 3, @encode(CGPoint), NULL,
                    (IMP)NEINSourceTabSetCenter, (IMP *)&NEINOriginalTabCenter);
    NEINHookOwnMethod(UITabBar.class, @selector(setBounds:), "v", 3, @encode(CGRect), NULL,
                    (IMP)NEINSourceTabSetBounds, (IMP *)&NEINOriginalTabBounds);
    NEINHookOwnMethod(UITabBar.class, @selector(setTransform:), "v", 3, @encode(CGAffineTransform), NULL,
                    (IMP)NEINSourceTabSetTransform, (IMP *)&NEINOriginalTabTransform);
    NEINHookOwnMethod(UINavigationController.class, @selector(viewWillLayoutSubviews),
                    "v", 2, NULL, NULL, (IMP)NEINNavigationWillLayout,
                    (IMP *)&NEINOriginalNavigationWillLayout);
    Class controller = UITabBarController.class;
    NEINHookOwnMethod(controller, @selector(setSelectedIndex:),
                    "v", 3, @encode(NSUInteger), NULL,
                    (IMP)NEINSetVisibleSelectedIndex, (IMP *)&NEINOriginalSelectedIndex);
    NEINHookOwnMethod(controller, @selector(setSelectedViewController:),
                    "v", 3, "@", NULL,
                    (IMP)NEINSetVisibleSelectedController, (IMP *)&NEINOriginalSelectedController);
    NEINHookOwnMethod(controller, @selector(viewDidLayoutSubviews),
                    "v", 2, NULL, NULL, (IMP)NEINTabBarControllerDidLayoutSubviews,
                    (IMP *)&NEINOriginalTabBarLayout);
    NEINHookOwnMethod(UITabBar.class, @selector(layoutSubviews),
                    "v", 2, NULL, NULL, (IMP)NEINSourceTabBarLayout,
                    (IMP *)&NEINOriginalSourceTabBarLayout);
}
#endif

static void NEINInstallAdRemovalCompat(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#ifdef NEIN_MULTI_REMOVE_ADS
        NEINInstallAdvertisingLoaderHooks();
        NEINInstallAdvertisingCleanupHook();
#endif
#ifdef NEIN_MULTI_HIDE_PROMOTIONAL_TABS
        NEINInstallPromotionalTabHooks();
#endif
    });
}
