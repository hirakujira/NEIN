#include <math.h>

static BOOL NEINRecordHomeTap(NSMutableArray<NSNumber *> *times, NSTimeInterval now,
                            BOOL isHome) {
    if (!isHome || !isfinite(now)) { [times removeAllObjects]; return NO; }
    if (times.count && now < times.lastObject.doubleValue) [times removeAllObjects];
    while (times.count && now - times.firstObject.doubleValue > 5.0) {
        [times removeObjectAtIndex:0];
    }
    [times addObject:@(now)];
    if (times.count < 10) return NO;
    [times removeAllObjects];
    return YES;
}

static BOOL NEINIsHomeTabTitle(NSString *title) {
    return NEINTabTitleIsOneOf(title,
        @[@"HOME", @"首頁", @"主頁", @"主页", @"ホーム", @"홈"]);
}
