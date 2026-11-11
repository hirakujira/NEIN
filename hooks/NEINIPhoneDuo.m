// iOS 27.1 SDK builds get vertical bars on wide iPhone Duo layouts. NEIN's
// visible tab bar mirrors the original horizontal bar, so keep bars horizontal.
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <string.h>

// UIVerticalBarBehaviorDisabled; the enum is absent from pre-27.1 SDK headers.
static const NSInteger NEINVerticalBarBehaviorDisabled = 1;

static NSInteger NEINDisabledVerticalBarBehavior(id self, SEL selector) {
    (void)self;
    (void)selector;
    return NEINVerticalBarBehaviorDisabled;
}

static void NEINInstallIPhoneDuoCompat(void) {
    if (@available(iOS 27.1, *)) {
        Method method = class_getInstanceMethod(
            UIViewController.class, NSSelectorFromString(@"preferredVerticalBarBehavior"));
        const char *types = method ? method_getTypeEncoding(method) : NULL;
        if (!types || strcmp(types, "q16@0:8") != 0) return;
        method_setImplementation(method, (IMP)NEINDisabledVerticalBarBehavior);
    }
}
