#import <UIKit/UIKit.h>
#include <assert.h>

// Real UIKit Auto Layout (Mac Catalyst) on LINE's camera constraints as dumped
// on an iPhone Duo; the safe area is zero because the views have no window.
__attribute__((objc_runtime_name("_TtC19LineCameraSubsystem15CameraLayerView")))
@interface NEINFakeCameraLayerView : UIView
@end
@implementation NEINFakeCameraLayerView
@end

__attribute__((objc_runtime_name("_TtC19LineCameraSubsystem10CameraView")))
@interface NEINFakeCameraView : UIView
@property(nonatomic, strong) NEINFakeCameraLayerView *preview;
@property(nonatomic, strong) UIView *frameView;
@property(nonatomic, strong) UIView *shutter;
@end
@implementation NEINFakeCameraView
- (void)rebuildPreview {
    [self.preview removeFromSuperview];
    self.preview = [NEINFakeCameraLayerView new];
    self.frameView = [UIView new];
    self.shutter = [UIView new];
    for (UIView *view in @[self.preview, self.frameView, self.shutter]) {
        view.translatesAutoresizingMaskIntoConstraints = NO;
    }
    [self addSubview:self.preview];
    [self.preview addSubview:self.frameView];
    [self addSubview:self.shutter];
    UILayoutGuide *safe = self.safeAreaLayoutGuide;
    NSLayoutConstraint *height = [self.preview.heightAnchor constraintEqualToAnchor:self.widthAnchor
                                                                         multiplier:16.0 / 9.0];
    height.priority = 750;
    NSLayoutConstraint *aspect = [self.frameView.widthAnchor constraintEqualToAnchor:self.frameView.heightAnchor
                                                                          multiplier:0.5625];
    aspect.priority = 500;
    NSArray *weak = @[
        [self.frameView.widthAnchor constraintLessThanOrEqualToAnchor:self.preview.widthAnchor],
        [self.frameView.heightAnchor constraintLessThanOrEqualToAnchor:self.preview.heightAnchor],
        [self.frameView.topAnchor constraintEqualToAnchor:self.preview.topAnchor],
    ];
    NSArray *weakest = @[
        [self.frameView.centerXAnchor constraintEqualToAnchor:self.preview.centerXAnchor],
        [self.frameView.bottomAnchor constraintEqualToAnchor:self.preview.bottomAnchor],
    ];
    for (NSLayoutConstraint *c in weak) c.priority = 750;
    for (NSLayoutConstraint *c in weakest) c.priority = 250;
    [NSLayoutConstraint activateConstraints:[@[
        [self.preview.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [self.preview.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [self.preview.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        height, aspect,
        [self.shutter.centerYAnchor constraintEqualToAnchor:self.preview.bottomAnchor constant:-64],
        [self.shutter.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
        [self.shutter.widthAnchor constraintEqualToConstant:74],
        [self.shutter.heightAnchor constraintEqualToConstant:74],
    ] arrayByAddingObjectsFromArray:[weak arrayByAddingObjectsFromArray:weakest]]];
}
@end

__attribute__((objc_runtime_name("YukiCameraView")))
@interface NEINFakeYukiCameraView : UIView
@end
@implementation NEINFakeYukiCameraView {
    CALayer *_metalLayer;
}
- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        _metalLayer = [CALayer new];
        _metalLayer.frame = self.layer.bounds;
        [self.layer addSublayer:_metalLayer];
    }
    return self;
}
- (CALayer *)metal {
    return _metalLayer;
}
@end

#import "../hooks/NEINDuoCameraLayout.h"

static NEINFakeCameraView *NEINTestCamera(CGSize size) {
    NEINFakeCameraView *camera = [[NEINFakeCameraView alloc] initWithFrame:(CGRect){CGPointZero, size}];
    [camera rebuildPreview];
    [camera layoutIfNeeded];
    return camera;
}

static void NEINAssertFits(NEINFakeCameraView *camera) {
    CGRect bounds = camera.bounds;
    CGFloat maxBottom = CGRectGetMaxY(bounds) - NEINDuoCameraModeBarBelowPreview;
    assert(CGRectGetMaxY(camera.preview.frame) <= maxBottom + 0.5);
    assert(CGRectContainsRect(bounds, camera.shutter.frame));
    CGRect frame = [camera convertRect:camera.frameView.bounds fromView:camera.frameView];
    assert(CGRectContainsRect(CGRectInset(camera.preview.frame, -0.5, -0.5), frame));
    assert(fabs(frame.size.width / frame.size.height - 0.5625) < 0.002);
    assert(fabs(CGRectGetMidX(frame) - CGRectGetMidX(bounds)) < 0.5);
}

int main(void) {
    @autoreleasepool {
        const CGSize folded = CGSizeMake(466, 678);
        const CGSize unfolded = CGSizeMake(951, 669);
        const CGSize tall = CGSizeMake(402, 874);

        // Unpatched LINE layout: the shutter leaves the folded window.
        NEINFakeCameraView *before = NEINTestCamera(folded);
        assert(CGRectGetMaxY(before.preview.frame) > folded.height);
        assert(!CGRectContainsRect(before.bounds, before.shutter.frame));

        assert(NEINInstallDuoCameraLayout());
        for (NSValue *size in @[[NSValue valueWithCGSize:folded], [NSValue valueWithCGSize:unfolded]]) {
            NEINAssertFits(NEINTestCamera(size.CGSizeValue));
        }

        // A tall phone already fits, so LINE's full-width 16:9 preview stays.
        NEINFakeCameraView *phone = NEINTestCamera(tall);
        assert(fabs(phone.preview.frame.size.height - tall.width * 16 / 9) < 0.5);
        assert(fabs(phone.frameView.bounds.size.width - tall.width) < 0.5);

        // Fold and unfold resize the same view; a rebuilt preview is capped too.
        NEINFakeCameraView *camera = NEINTestCamera(folded);
        camera.frame = (CGRect){CGPointZero, unfolded};
        [camera layoutIfNeeded];
        NEINAssertFits(camera);
        NSUInteger constraints = camera.constraints.count;
        [camera setNeedsLayout];
        [camera layoutIfNeeded];
        assert(camera.constraints.count == constraints);
        [camera rebuildPreview];
        camera.frame = (CGRect){CGPointZero, folded};
        [camera layoutIfNeeded];
        NEINAssertFits(camera);

        // Yuki's bounds follow the window; its Metal layer must follow too.
        NEINFakeYukiCameraView *yuki = [[NEINFakeYukiCameraView alloc]
            initWithFrame:CGRectMake(0, 0, 466, 828)];
        yuki.bounds = CGRectMake(0, 0, 670, 1191);
        [yuki layoutIfNeeded];
        assert(CGRectEqualToRect(yuki.metal.frame, yuki.layer.bounds));
        puts("iPhone Duo camera layout tests passed (UIKit).");
    }
    return 0;
}
