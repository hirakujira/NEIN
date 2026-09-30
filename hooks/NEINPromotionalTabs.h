#include "NEINPromotionalTabIdentity.h"

static char NEINTabOriginalEnabledKey;

static void NEINUpdatePromotionalItems(NSArray<UITabBarItem *> *items) {
    for (UITabBarItem *item in items) {
        BOOL promotional = NEINIsPromotionalTabItem(item);
        NSNumber *original = objc_getAssociatedObject(item, &NEINTabOriginalEnabledKey);
        if (promotional) {
            if (!original) {
                objc_setAssociatedObject(item, &NEINTabOriginalEnabledKey,
                    @(item.enabled), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
            item.enabled = NO;
        } else if (original) {
            item.enabled = original.boolValue;
            objc_setAssociatedObject(item, &NEINTabOriginalEnabledKey,
                nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    }
}

static BOOL NEINContainsControl(UIView *root) {
    for (UIView *child in root.subviews) {
        if ([child isKindOfClass:UIControl.class] || NEINContainsControl(child)) return YES;
    }
    return NO;
}

typedef struct {
    BOOL hasPromotionalText;
    BOOL hasOtherText;
} NEINPromotionalTextSummary;

static void NEINAddPromotionalText(NSString *text,
                                   NEINPromotionalTextSummary *summary) {
    if (!text.length) return;
    if (NEINExactPromotionalTitle(text)) {
        summary->hasPromotionalText = YES;
    } else if ([text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet].length > 0) {
        summary->hasOtherText = YES;
    }
}

static void NEINCollectPromotionalText(UIView *root,
                                      NEINPromotionalTextSummary *summary) {
    if (summary->hasPromotionalText && summary->hasOtherText) return;
    NEINAddPromotionalText(root.accessibilityLabel, summary);
    if ([root isKindOfClass:UILabel.class]) {
        UILabel *label = (UILabel *)root;
        NEINAddPromotionalText(label.text, summary);
        NEINAddPromotionalText(label.attributedText.string, summary);
    }
    if ([root isKindOfClass:UIButton.class]) {
        UIButton *button = (UIButton *)root;
        NEINAddPromotionalText(button.currentTitle, summary);
        NEINAddPromotionalText(button.currentAttributedTitle.string, summary);
    }
    for (UIView *child in root.subviews) {
        NEINCollectPromotionalText(child, summary);
        if (summary->hasPromotionalText && summary->hasOtherText) return;
    }
}

static char NEINTabOriginalHiddenKey;

static void NEINUpdatePromotionalButtons(UIView *root) {
    for (UIView *child in root.subviews) {
        // A shared control wrapping multiple buttons is not a single tab.
        if ([child isKindOfClass:UIControl.class] && !NEINContainsControl(child)) {
            NSNumber *original = objc_getAssociatedObject(child, &NEINTabOriginalHiddenKey);
            NEINPromotionalTextSummary textSummary = {0};
            NEINCollectPromotionalText(child, &textSummary);
            if (textSummary.hasPromotionalText && !textSummary.hasOtherText) {
                if (!original) {
                    objc_setAssociatedObject(child, &NEINTabOriginalHiddenKey,
                        @(child.hidden), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                }
                child.hidden = YES;
            } else if (original) {
                child.hidden = original.boolValue;
                objc_setAssociatedObject(child, &NEINTabOriginalHiddenKey,
                    nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
        } else {
            NEINUpdatePromotionalButtons(child);
        }
    }
}
