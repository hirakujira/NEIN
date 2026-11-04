#pragma once

static inline BOOL NEINIsLINEAppGroup(NSString *identifier) {
    return [identifier isEqualToString:@"group.com.linecorp.line"] ||
           [identifier isEqualToString:@"group.share.com.linecorp.line"];
}
