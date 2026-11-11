// LINE builds its iPad split layout on every device, but MainRootViewController
// forces the split controller to a compact width whenever the idiom is phone.
// iPhone Duo is still a phone, so give the split controller a regular width
// while the unfolded inner display hosts the window. LINE's split controller
// already pins both columns (oneBesideSecondary, 320pt primary column).
#pragma once

#include <stdlib.h>
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

static BOOL NEINDuoModelSupportsSplitLayout(NSString *model) {
    return [model isEqualToString:NEINDuoModelIdentifier];
}

static BOOL NEINDuoCanvasFitsSplitLayout(CGSize size) {
    return MIN(size.width, size.height) >= NEINDuoSplitMinimumCanvasSide;
}

static CGSize NEINDuoCanvasSize(UIViewController *controller) {
    UIView *view = controller.viewIfLoaded;
    // The window resizes before its subviews during fold transitions.
    CGSize window = view.window.bounds.size;
    if (window.width > 0 && window.height > 0) return window;
    return view ? view.bounds.size : CGSizeZero;
}

static void NEINDuoUpdateSplitTraits(UISplitViewController *controller, CGSize canvas) {
    id<UITraitOverrides> overrides = controller.traitOverrides;
    BOOL applied = [objc_getAssociatedObject(controller, &NEINDuoSplitOverrideKey) boolValue];
    if (NEINDuoCanvasFitsSplitLayout(canvas)) {
        if (applied && overrides.horizontalSizeClass == UIUserInterfaceSizeClassRegular) return;
        // The child's own override wins over LINE's compact parent override.
        // UIKit does not re-query that parent override on fold because the
        // window's size class never changes, so update the child directly.
        overrides.horizontalSizeClass = UIUserInterfaceSizeClassRegular;
        objc_setAssociatedObject(controller, &NEINDuoSplitOverrideKey, @YES,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    } else if (applied) {
        [overrides removeTrait:UITraitHorizontalSizeClass.class];
        objc_setAssociatedObject(controller, &NEINDuoSplitOverrideKey, nil,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
}

static void NEINDuoSplitDidLayoutSubviews(id self, SEL selector) {
    NEINDuoOriginalSplitLayout(self, selector);
    NEINDuoUpdateSplitTraits(self, NEINDuoCanvasSize(self));
}

static Class NEINDuoLineClass(NSString *mangledName, NSString *suffix) {
    Class exact = NSClassFromString(mangledName);
    if (exact) return exact;
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    Class match = Nil;
    for (unsigned int index = 0; index < count; index++) {
        NSString *name = NSStringFromClass(classes[index]);
        if (![name hasPrefix:@"_TtC4LINE"] || ![name hasSuffix:suffix]) continue;
        if (match) {
            match = Nil;
            break;
        }
        match = classes[index];
    }
    free(classes);
    return match;
}

static Method NEINDuoOwnMethod(Class cls, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method match = NULL;
    for (unsigned int index = 0; index < count; index++) {
        if (method_getName(methods[index]) == selector) {
            match = methods[index];
            break;
        }
    }
    free(methods);
    return match;
}

static BOOL NEINInstallDuoSplitLayout(NSString *model) {
    if (!NEINDuoModelSupportsSplitLayout(model)) return NO;
    Class split = NEINDuoLineClass(@"_TtC4LINE21NLSplitViewController",
                                   @"NLSplitViewController");
    if (![split isSubclassOfClass:UISplitViewController.class]) {
        NSLog(@"[NEINIPhoneDuo] LINE split controller not found; keeping one column.");
        return NO;
    }
    // UISplitViewController's implementation is shared by every split view, so
    // only replace the override that LINE's class defines itself.
    Method layout = NEINDuoOwnMethod(split, @selector(viewDidLayoutSubviews));
    if (!NEINMethodHasType(layout, "v", 2, NULL, NULL)) {
        NSLog(@"[NEINIPhoneDuo] Unexpected LINE split controller layout; keeping one column.");
        return NO;
    }
    NEINDuoOriginalSplitLayout = (NEINDuoLayoutIMP)method_getImplementation(layout);
    method_setImplementation(layout, (IMP)NEINDuoSplitDidLayoutSubviews);
    return YES;
}
