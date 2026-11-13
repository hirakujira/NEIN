// LINE's camera gives its preview a 16:9 height from the view width (priority
// 750) with nothing below it, assuming a tall phone. iPhone Duo windows are too
// short, so the preview, the shutter (preview bottom - 64) and the mode bar run
// off screen and the visible part is not what gets captured. A required cap
// lets LINE's own 9:16 inner view shrink and center inside the visible area.
#pragma once

#include "NEINObjCRuntime.h"

// LINE hangs its photo/video mode bar 34pt below the preview's bottom edge.
static const CGFloat NEINDuoCameraModeBarBelowPreview = 34;

static char NEINDuoCameraCappedPreviewKey;

typedef void (*NEINDuoCameraLayoutIMP)(id, SEL);
static NEINDuoCameraLayoutIMP NEINDuoOriginalCameraLayout;

static UIView *NEINDuoCameraPreview(UIView *camera) {
    Class preview = NSClassFromString(@"_TtC19LineCameraSubsystem15CameraLayerView");
    for (NSLayoutConstraint *constraint in camera.constraints) {
        if (constraint.firstAttribute == NSLayoutAttributeHeight &&
                constraint.secondItem == camera &&
                constraint.secondAttribute == NSLayoutAttributeWidth &&
                fabs(constraint.multiplier - 16.0 / 9.0) < 0.01 &&
                [constraint.firstItem isKindOfClass:preview]) {
            return constraint.firstItem;
        }
    }
    return nil;
}

static void NEINDuoCameraLayoutSubviews(UIView *self, SEL selector) {
    UIView *preview = NEINDuoCameraPreview(self);
    // LINE can rebuild its preview view, so cap each new one once.
    if (preview && objc_getAssociatedObject(self, &NEINDuoCameraCappedPreviewKey) != preview) {
        [preview.bottomAnchor constraintLessThanOrEqualToAnchor:self.safeAreaLayoutGuide.bottomAnchor
                                                       constant:-NEINDuoCameraModeBarBelowPreview].active = YES;
        objc_setAssociatedObject(self, &NEINDuoCameraCappedPreviewKey, preview,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    NEINDuoOriginalCameraLayout(self, selector);
}

// YukiCameraView resizes its bounds to the window on fold and rotation but
// sizes its Metal layer only once, so after unfolding or rotating the picture
// fills just the top-left part of the preview.
static NEINDuoCameraLayoutIMP NEINDuoOriginalYukiLayout;

static void NEINDuoYukiLayoutSubviews(UIView *self, SEL selector) {
    NEINDuoOriginalYukiLayout(self, selector);
    Ivar ivar = class_getInstanceVariable(self.class, "_metalLayer");
    id metal = ivar ? object_getIvar(self, ivar) : nil;
    if ([metal isKindOfClass:CALayer.class] && ((CALayer *)metal).superlayer == self.layer &&
            !CGRectEqualToRect(((CALayer *)metal).frame, self.layer.bounds)) {
        ((CALayer *)metal).frame = self.layer.bounds;
    }
}

static void NEINInstallDuoYukiLayout(void) {
    Class yuki = NSClassFromString(@"YukiCameraView");
    if (![yuki isSubclassOfClass:UIView.class] ||
            !NEINHookOwnMethod(yuki, @selector(layoutSubviews), "v", 2, NULL, NULL,
                               (IMP)NEINDuoYukiLayoutSubviews,
                               (IMP *)&NEINDuoOriginalYukiLayout)) {
        NSLog(@"[NEINIPhoneDuo] YukiCameraView not found; its Metal layer keeps its first size.");
    }
}

static BOOL NEINInstallDuoCameraLayout(void) {
    Class camera = NSClassFromString(@"_TtC19LineCameraSubsystem10CameraView");
    if (![camera isSubclassOfClass:UIView.class] ||
            !NEINHookOwnMethod(camera, @selector(layoutSubviews), "v", 2, NULL, NULL,
                               (IMP)NEINDuoCameraLayoutSubviews,
                               (IMP *)&NEINDuoOriginalCameraLayout)) {
        NSLog(@"[NEINIPhoneDuo] LINE camera view not found; keeping its 16:9 preview.");
        return NO;
    }
    NEINInstallDuoYukiLayout();
    return YES;
}
