// Diagnostic-only export. Never serialize view descriptions, labels, images,
// identifiers, badge values, constraints or any views outside the tab bar.
static NSArray *NEINTDRect(CGRect rect) {
    return @[@(rect.origin.x), @(rect.origin.y),
             @(rect.size.width), @(rect.size.height)];
}

static NSDictionary *NEINTDView(UIView *view, NSUInteger depth, NSUInteger *remaining) {
    if (!*remaining || depth > 20) return @{@"truncated": @YES};
    --*remaining;
    NSMutableArray *children = [NSMutableArray new];
    for (UIView *child in view.subviews) {
        if (!*remaining) break;
        [children addObject:NEINTDView(child, depth + 1, remaining)];
    }
    NSMutableDictionary *node = [@{
        @"class": NSStringFromClass(view.class),
        @"frame_in_parent": NEINTDRect(view.frame),
        @"bounds": NEINTDRect(view.bounds),
        @"hidden": @(view.hidden),
        @"alpha": @(view.alpha),
        @"interactive": @(view.userInteractionEnabled),
        @"translation": @[@(view.transform.tx), @(view.transform.ty)],
        @"gesture_count": @(view.gestureRecognizers.count),
        @"children": children,
        @"child_count": @(view.subviews.count),
    } mutableCopy];
    if ([view isKindOfClass:UIControl.class]) {
        node[@"enabled"] = @(((UIControl *)view).enabled);
    }
    return node;
}

#ifndef NEIN_TAB_DIAGNOSTICS_SNAPSHOT_ONLY
@interface NEINTabDiagnosticExporter : NSObject
@property(nonatomic, weak) UITabBarController *controller;
@property(nonatomic, strong) UIButton *button;
- (void)exportSnapshot;
@end

@implementation NEINTabDiagnosticExporter
- (void)exportSnapshot {
    UITabBarController *controller = self.controller;
    if (!controller.viewIfLoaded.window || controller.presentedViewController) return;
    NSUInteger remaining = 512;
    NEINVisibleTabBar *presentation = objc_getAssociatedObject(controller, &NEINVisibleTabBarKey);
    NSMutableArray *items = [NSMutableArray new];
    for (UITabBarItem *item in controller.tabBar.items) {
        [items addObject:@{@"class": NSStringFromClass(item.class),
                           @"enabled": @(item.enabled)}];
    }
    NSDictionary *report = @{
        @"schema": @1,
        @"build": @"v17-home-settings",
        @"phase": @"native_presentation",
        @"tab_bar": NEINTDView(controller.tabBar, 0, &remaining),
        @"items": items,
        @"presentation_active": @(presentation.active),
        @"presentation_indices": presentation.indices ?: @[],
        @"presentation_tab_bar": presentation.active
            ? NEINTDView(presentation.bar, 0, &remaining) : @{},
        @"selected_item_index": controller.tabBar.selectedItem
            ? @([controller.tabBar.items indexOfObjectIdenticalTo:controller.tabBar.selectedItem])
            : @(-1),
        @"layout_direction": @(controller.tabBar.effectiveUserInterfaceLayoutDirection),
        @"controller_selected_item_index": controller.selectedViewController.tabBarItem
            ? @([controller.tabBar.items indexOfObjectIdenticalTo:controller.selectedViewController.tabBarItem])
            : @(-1),
        @"node_limit_reached": @(remaining == 0),
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                    options:NSJSONWritingPrettyPrinted error:NULL];
    // Unique temporary directory, never expose the app's Documents folder.
    NSURL *directory = [[NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES]
                        URLByAppendingPathComponent:NSUUID.UUID.UUIDString isDirectory:YES];
    NSURL *file = [directory URLByAppendingPathComponent:@"NEIN-tab-diagnostics.json"];
    BOOL written = data &&
        [NSFileManager.defaultManager createDirectoryAtURL:directory
          withIntermediateDirectories:NO attributes:nil error:NULL] &&
        [data writeToURL:file options:NSDataWritingAtomic error:NULL];
    if (!written) {
        [NSFileManager.defaultManager removeItemAtURL:directory error:NULL];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Tab 診斷"
            message:@"無法建立診斷檔，請稍後再試。" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [controller presentViewController:alert animated:YES completion:nil];
        return;
    }
    UIActivityViewController *share = [[UIActivityViewController alloc]
        initWithActivityItems:@[file] applicationActivities:nil];
    share.popoverPresentationController.sourceView = self.button;
    share.popoverPresentationController.sourceRect = self.button.bounds;
    share.completionWithItemsHandler = ^(UIActivityType activity, BOOL completed,
                                        NSArray *returned, NSError *error) {
        (void)activity; (void)completed; (void)returned; (void)error;
        [NSFileManager.defaultManager removeItemAtURL:directory error:NULL];
    };
    [controller presentViewController:share animated:YES completion:nil];
}
@end

static char NEINTDExporterKey;

static void NEINInstallTabDiagnosticButton(UITabBarController *controller) {
    if (objc_getAssociatedObject(controller, &NEINTDExporterKey)) return;
    NEINTabDiagnosticExporter *exporter = [NEINTabDiagnosticExporter new];
    exporter.controller = controller;
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    UIButtonConfiguration *configuration = UIButtonConfiguration.filledButtonConfiguration;
    configuration.title = @"Tab 診斷";
    button.configuration = configuration;
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button addTarget:exporter action:@selector(exportSnapshot)
        forControlEvents:UIControlEventTouchUpInside];
    exporter.button = button;
    objc_setAssociatedObject(controller, &NEINTDExporterKey, exporter,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    UIView *view = controller.view;
    [view addSubview:button];
    [NSLayoutConstraint activateConstraints:@[
        [button.trailingAnchor constraintEqualToAnchor:view.safeAreaLayoutGuide.trailingAnchor constant:-16],
        [button.bottomAnchor constraintEqualToAnchor:view.safeAreaLayoutGuide.bottomAnchor constant:-100],
    ]];
}
#endif
