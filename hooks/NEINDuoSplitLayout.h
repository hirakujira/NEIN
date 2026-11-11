// LINE builds its iPad split layout on every device, but MainRootViewController
// forces the split controller to a compact width whenever the idiom is phone.
// iPhone Duo is still a phone, so give the split controller a regular width
// while the unfolded inner display hosts the window. LINE's split controller
// already pins both columns (oneBesideSecondary, 320pt primary column).
#pragma once

#include <sys/utsname.h>
#include <TargetConditionals.h>
#include "NEINObjCRuntime.h"

static NSString * const NEINDuoModelIdentifier = @"iPhone19,4";

// iPhone Duo windows measure 466x678pt folded and 951x669pt unfolded.
static const CGFloat NEINDuoSplitMinimumCanvasSide = 600;

static char NEINDuoSplitOverrideKey;

typedef void (*NEINDuoLayoutIMP)(id, SEL);
static NEINDuoLayoutIMP NEINDuoOriginalSplitLayout;

static NSString *NEINDuoMachineModel(void) {
#if TARGET_OS_SIMULATOR
    return NSProcessInfo.processInfo.environment[@"SIMULATOR_MODEL_IDENTIFIER"];
#else
    struct utsname info;
    return uname(&info) == 0 ? @(info.machine) : nil;
#endif
}

static CGSize NEINDuoCanvasSize(UIViewController *controller) {
    UIView *view = controller.viewIfLoaded;
    // The window resizes before its subviews during fold transitions.
    return (view.window ?: view).bounds.size;
}

static void NEINDuoUpdateSplitTraits(UISplitViewController *controller, CGSize canvas) {
    BOOL wide = MIN(canvas.width, canvas.height) >= NEINDuoSplitMinimumCanvasSide;
    BOOL applied = objc_getAssociatedObject(controller, &NEINDuoSplitOverrideKey) != nil;
    if (wide == applied) return;
    // The child's own override wins over LINE's compact parent override.
    // UIKit does not re-query that parent override on fold because the
    // window's size class never changes, so update the child directly.
    if (wide) {
        controller.traitOverrides.horizontalSizeClass = UIUserInterfaceSizeClassRegular;
    } else {
        [controller.traitOverrides removeTrait:UITraitHorizontalSizeClass.class];
    }
    objc_setAssociatedObject(controller, &NEINDuoSplitOverrideKey, wide ? @YES : nil,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static void NEINDuoSplitDidLayoutSubviews(id self, SEL selector) {
    NEINDuoOriginalSplitLayout(self, selector);
    NEINDuoUpdateSplitTraits(self, NEINDuoCanvasSize(self));
}

static BOOL NEINInstallDuoSplitLayout(NSString *model) {
    if (![model isEqualToString:NEINDuoModelIdentifier]) return NO;
    Class split = NSClassFromString(@"_TtC4LINE21NLSplitViewController");
    if (![split isSubclassOfClass:UISplitViewController.class]) {
        NSLog(@"[NEINIPhoneDuo] LINE split controller not found; keeping one column.");
        return NO;
    }
    // UISplitViewController's implementation is shared by every split view, so
    // only replace the override that LINE's class defines itself.
    SEL selector = @selector(viewDidLayoutSubviews);
    Method layout = class_getInstanceMethod(split, selector);
    if (layout == class_getInstanceMethod(class_getSuperclass(split), selector) ||
            !NEINMethodHasType(layout, "v", 2, NULL, NULL)) {
        NSLog(@"[NEINIPhoneDuo] Unexpected LINE split controller layout; keeping one column.");
        return NO;
    }
    NEINDuoOriginalSplitLayout = (NEINDuoLayoutIMP)method_getImplementation(layout);
    method_setImplementation(layout, (IMP)NEINDuoSplitDidLayoutSubviews);
    return YES;
}
