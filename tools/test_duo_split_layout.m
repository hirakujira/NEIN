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

@interface NEINTestTraitOverrides : NSObject
@property(nonatomic) UIUserInterfaceSizeClass horizontalSizeClass;
@property(nonatomic) NSUInteger writes;
@property(nonatomic) NSUInteger removals;
- (void)removeTrait:(Class)trait;
@end
@implementation NEINTestTraitOverrides
- (void)setHorizontalSizeClass:(UIUserInterfaceSizeClass)sizeClass {
    _horizontalSizeClass = sizeClass;
    self.writes++;
}
- (void)removeTrait:(Class)trait {
    assert(trait == UITraitHorizontalSizeClass.class);
    _horizontalSizeClass = UIUserInterfaceSizeClassUnspecified;
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

static BOOL NEINTestWide(CGSize canvas) {
    NEINFakeSplitViewController *split = [NEINFakeSplitViewController new];
    NEINDuoUpdateSplitTraits(split, canvas);
    return split.traitOverrides.horizontalSizeClass == UIUserInterfaceSizeClassRegular;
}

int main(void) {
    @autoreleasepool {
        const CGSize unfolded = CGSizeMake(951, 669);
        const CGSize folded = CGSizeMake(466, 678);
        const CGSize maxLandscape = CGSizeMake(956, 440);

        assert(NEINTestWide(unfolded));
        assert(NEINTestWide(CGSizeMake(669, 951)));
        assert(NEINTestWide(CGSizeMake(600, 600)));
        assert(!NEINTestWide(folded));
        assert(!NEINTestWide(CGSizeMake(599.5, 900)));
        assert(!NEINTestWide(maxLandscape));
        assert(!NEINTestWide(CGSizeZero));

        NEINFakeSplitViewController *split = [NEINFakeSplitViewController new];
        NEINTestTraitOverrides *overrides = split.traitOverrides;
        split.viewIfLoaded = NEINTestView(unfolded, unfolded);

        // Other iPhones never install the hook; a Mac reports its architecture.
        assert(NEINDuoMachineModel().length > 0);
        for (NSString *model in @[@"iPhone19,5", @"iPhone18,1", NEINDuoMachineModel()]) {
            assert(!NEINInstallDuoSplitLayout(model));
        }
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
        assert(overrides.horizontalSizeClass == UIUserInterfaceSizeClassRegular);
        assert(overrides.writes == 1);
        [split viewDidLayoutSubviews];
        assert(overrides.writes == 1);

        split.viewIfLoaded = NEINTestView(folded, folded);
        [split viewDidLayoutSubviews];
        assert(overrides.horizontalSizeClass == UIUserInterfaceSizeClassUnspecified);
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
        assert(other.traitOverrides.horizontalSizeClass == UIUserInterfaceSizeClassCompact);
        assert(other.traitOverrides.removals == 0);
        puts("iPhone Duo split layout tests passed (view doubles).");
    }
    return 0;
}
