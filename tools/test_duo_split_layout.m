#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>
#include <assert.h>

// UIKit doubles cover trait bookkeeping, not UISplitViewController's real
// collapse/expand behavior.
typedef NS_ENUM(NSInteger, UIUserInterfaceSizeClass) {
    UIUserInterfaceSizeClassUnspecified = 0,
    UIUserInterfaceSizeClassCompact = 1,
    UIUserInterfaceSizeClassRegular = 2,
};

@interface UITraitHorizontalSizeClass : NSObject
@end
@implementation UITraitHorizontalSizeClass
@end

@protocol UITraitOverrides <NSObject>
@property(nonatomic) UIUserInterfaceSizeClass horizontalSizeClass;
- (BOOL)containsTrait:(Class)trait;
- (void)removeTrait:(Class)trait;
@end

@interface NEINTestTraitOverrides : NSObject <UITraitOverrides>
@property(nonatomic) BOOL hasHorizontalSizeClass;
@property(nonatomic) NSUInteger writes;
@property(nonatomic) NSUInteger removals;
@end
@implementation NEINTestTraitOverrides
@synthesize horizontalSizeClass = _horizontalSizeClass;
- (void)setHorizontalSizeClass:(UIUserInterfaceSizeClass)sizeClass {
    _horizontalSizeClass = sizeClass;
    self.hasHorizontalSizeClass = YES;
    self.writes++;
}
- (BOOL)containsTrait:(Class)trait {
    return trait == UITraitHorizontalSizeClass.class && self.hasHorizontalSizeClass;
}
- (void)removeTrait:(Class)trait {
    if (trait != UITraitHorizontalSizeClass.class) return;
    _horizontalSizeClass = UIUserInterfaceSizeClassUnspecified;
    self.hasHorizontalSizeClass = NO;
    self.removals++;
}
@end

@class UIWindow;

@interface UIView : NSObject
@property(nonatomic) CGRect bounds;
@property(nonatomic, strong) UIWindow *window;
@end
@implementation UIView
@end

@interface UIWindow : UIView
@end
@implementation UIWindow
@end

@interface UIViewController : NSObject
@property(nonatomic, strong) UIView *viewIfLoaded;
@property(nonatomic, readonly) NEINTestTraitOverrides *traitOverrides;
- (void)viewDidLayoutSubviews;
@end
@implementation UIViewController
- (instancetype)init {
    if ((self = [super init])) _traitOverrides = [NEINTestTraitOverrides new];
    return self;
}
- (void)viewDidLayoutSubviews {}
@end

@interface UISplitViewController : UIViewController
@end
@implementation UISplitViewController
@end

__attribute__((objc_runtime_name("_TtC4LINE21NLSplitViewController")))
@interface NEINFakeSplitViewController : UISplitViewController
@property(nonatomic) NSUInteger layoutCount;
@end
@implementation NEINFakeSplitViewController
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.layoutCount++;
}
@end

__attribute__((objc_runtime_name("_TtC4LINE18FakeFallbackTarget")))
@interface NEINFakeFallbackTarget : NSObject
@end
@implementation NEINFakeFallbackTarget
@end

@interface OtherFakeFallbackTarget : NSObject
@end
@implementation OtherFakeFallbackTarget
@end

__attribute__((objc_runtime_name("_TtC4LINE15FirstTwinTarget")))
@interface NEINFirstTwinTarget : NSObject
@end
@implementation NEINFirstTwinTarget
@end

__attribute__((objc_runtime_name("_TtC4LINE16SecondTwinTarget")))
@interface NEINSecondTwinTarget : NSObject
@end
@implementation NEINSecondTwinTarget
@end

#include "../hooks/NEINDuoSplitLayout.h"

static UIView *NEINTestView(CGSize window, CGSize view) {
    UIView *result = [UIView new];
    result.bounds = CGRectMake(0, 0, view.width, view.height);
    if (window.width > 0) {
        result.window = [UIWindow new];
        result.window.bounds = CGRectMake(0, 0, window.width, window.height);
    }
    return result;
}

int main(void) {
    @autoreleasepool {
        const CGSize unfolded = CGSizeMake(951, 669);
        const CGSize folded = CGSizeMake(466, 678);
        const CGSize maxLandscape = CGSizeMake(956, 440);

        assert(NEINDuoModelSupportsSplitLayout(@"iPhone19,4"));
        assert(!NEINDuoModelSupportsSplitLayout(@"iPhone19,5"));
        assert(!NEINDuoModelSupportsSplitLayout(@"iPhone18,1"));
        assert(!NEINDuoModelSupportsSplitLayout(@"arm64"));
        assert(!NEINDuoModelSupportsSplitLayout(nil));
        // A Mac reports its architecture here, never an iPhone model.
        assert(NEINDuoMachineModel().length > 0);
        assert(!NEINDuoModelSupportsSplitLayout(NEINDuoMachineModel()));

        assert(NEINDuoCanvasFitsSplitLayout(unfolded));
        assert(NEINDuoCanvasFitsSplitLayout(CGSizeMake(669, 951)));
        assert(NEINDuoCanvasFitsSplitLayout(CGSizeMake(600, 600)));
        assert(!NEINDuoCanvasFitsSplitLayout(folded));
        assert(!NEINDuoCanvasFitsSplitLayout(CGSizeMake(599.5, 900)));
        assert(!NEINDuoCanvasFitsSplitLayout(maxLandscape));
        assert(!NEINDuoCanvasFitsSplitLayout(CGSizeZero));

        assert(NEINDuoLineClass(@"_TtC4LINE21NLSplitViewController", @"Unused") ==
               NEINFakeSplitViewController.class);
        assert(NEINDuoLineClass(@"_TtC4LINE99Missing", @"FakeFallbackTarget") ==
               NEINFakeFallbackTarget.class);
        assert(NEINDuoLineClass(@"_TtC4LINE99Missing", @"TwinTarget") == Nil);
        assert(NEINDuoLineClass(@"_TtC4LINE99Missing", @"NoSuchTarget") == Nil);

        SEL layoutSelector = @selector(viewDidLayoutSubviews);
        assert(NEINDuoOwnMethod(UISplitViewController.class, layoutSelector) == NULL);
        assert(NEINDuoOwnMethod(NEINFakeSplitViewController.class, layoutSelector) != NULL);

        NEINFakeSplitViewController *split = [NEINFakeSplitViewController new];
        NEINTestTraitOverrides *overrides = split.traitOverrides;
        split.viewIfLoaded = NEINTestView(unfolded, unfolded);

        // Other iPhones never install the hook.
        assert(!NEINInstallDuoSplitLayout(@"iPhone18,1"));
        assert(!NEINInstallDuoSplitLayout(nil));
        [split viewDidLayoutSubviews];
        assert(split.layoutCount == 1);
        assert(overrides.writes == 0);

        assert(NEINInstallDuoSplitLayout(@"iPhone19,4"));

        // UIKit's shared implementation stays untouched.
        UISplitViewController *plainSplit = [UISplitViewController new];
        plainSplit.viewIfLoaded = NEINTestView(unfolded, unfolded);
        [plainSplit viewDidLayoutSubviews];
        assert(plainSplit.traitOverrides.writes == 0);

        [split viewDidLayoutSubviews];
        assert(split.layoutCount == 2);
        assert([overrides containsTrait:UITraitHorizontalSizeClass.class]);
        assert(overrides.horizontalSizeClass == UIUserInterfaceSizeClassRegular);
        assert(overrides.writes == 1);
        [split viewDidLayoutSubviews];
        assert(overrides.writes == 1);

        split.viewIfLoaded = NEINTestView(folded, folded);
        [split viewDidLayoutSubviews];
        assert(![overrides containsTrait:UITraitHorizontalSizeClass.class]);
        assert(overrides.removals == 1);
        [split viewDidLayoutSubviews];
        assert(overrides.removals == 1);
        assert(overrides.writes == 1);

        split.viewIfLoaded = NEINTestView(unfolded, unfolded);
        [split viewDidLayoutSubviews];
        assert(overrides.horizontalSizeClass == UIUserInterfaceSizeClassRegular);
        assert(overrides.writes == 2);

        // The window wins over a split view that has not resized yet.
        split.viewIfLoaded = NEINTestView(folded, unfolded);
        [split viewDidLayoutSubviews];
        assert(overrides.removals == 2);
        split.viewIfLoaded = NEINTestView(unfolded, folded);
        [split viewDidLayoutSubviews];
        assert(overrides.writes == 3);
        split.viewIfLoaded = NEINTestView(maxLandscape, maxLandscape);
        [split viewDidLayoutSubviews];
        assert(overrides.removals == 3);
        split.viewIfLoaded = NEINTestView(CGSizeZero, unfolded);
        [split viewDidLayoutSubviews];
        assert(overrides.writes == 4);
        split.viewIfLoaded = nil;
        [split viewDidLayoutSubviews];
        assert(overrides.removals == 4);
        assert(split.layoutCount == 11);

        // Narrow layouts leave overrides that NEIN did not set alone.
        NEINFakeSplitViewController *other = [NEINFakeSplitViewController new];
        other.traitOverrides.horizontalSizeClass = UIUserInterfaceSizeClassCompact;
        other.viewIfLoaded = NEINTestView(folded, folded);
        [other viewDidLayoutSubviews];
        assert([other.traitOverrides containsTrait:UITraitHorizontalSizeClass.class]);
        assert(other.traitOverrides.horizontalSizeClass == UIUserInterfaceSizeClassCompact);
        assert(other.traitOverrides.removals == 0);
        puts("iPhone Duo split layout tests passed (view doubles).");
    }
    return 0;
}
