// iOS 27.1 SDK builds get vertical bars on wide iPhone Duo layouts. NEIN's
// visible tab bar mirrors the original horizontal bar, so keep bars horizontal.
// The unfolded inner display also gets LINE's iPad-style split layout, and
// the camera preview is kept inside the short Duo windows.
#import <UIKit/UIKit.h>
#include "NEINDuoSplitLayout.h"
#include "NEINDuoCameraLayout.h"

// UIVerticalBarBehaviorDisabled; the enum is absent from pre-27.1 SDK headers.
static const NSInteger NEINVerticalBarBehaviorDisabled = 1;

static NSInteger NEINDisabledVerticalBarBehavior(id self, SEL selector) {
    (void)self;
    (void)selector;
    return NEINVerticalBarBehaviorDisabled;
}

static void NEINInstallIPhoneDuoCompat(void) {
    NEINInstallDuoSplitLayout(NEINDuoMachineModel());
    NEINInstallDuoCameraLayout();
    if (@available(iOS 27.1, *)) {
        Method method = class_getInstanceMethod(
            UIViewController.class, NSSelectorFromString(@"preferredVerticalBarBehavior"));
        if (!NEINMethodHasType(method, "q", 2, NULL, NULL)) return;
        method_setImplementation(method, (IMP)NEINDisabledVerticalBarBehavior);
    }
}
