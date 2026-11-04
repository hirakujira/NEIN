#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include "NEINObjCRuntime.h"

static NSString * const NEINIconPickerConfigurationKey = @"NEINIconPicker";
static char NEINIconPickerEmbeddedKey;

static NSDictionary *NEINIconPickerBundleInfo(void) {
    NSString *path = [NSBundle.mainBundle pathForResource:@"Info" ofType:@"plist"];
    NSDictionary *rawInfo = path ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
    return rawInfo ?: NSBundle.mainBundle.infoDictionary;
}

@interface NEINIconPickerItem : NSObject
@property(nonatomic, copy) NSString *name;
@property(nonatomic, copy) NSString *category;
@property(nonatomic, strong) UIImage *image;
@end

@implementation NEINIconPickerItem
@end

@interface NEINIconPickerCell : UICollectionViewCell
@property(nonatomic, strong) UIImageView *iconView;
@property(nonatomic, strong) UIImageView *checkmarkView;
- (void)configureWithItem:(NEINIconPickerItem *)item selected:(BOOL)selected;
@end

@implementation NEINIconPickerCell

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;

    self.contentView.backgroundColor = UIColor.clearColor;
    self.contentView.layer.cornerRadius = 12;
    self.contentView.layer.borderWidth = 2;
    self.contentView.layer.borderColor = UIColor.clearColor.CGColor;
    self.contentView.clipsToBounds = YES;

    _iconView = [UIImageView new];
    _iconView.translatesAutoresizingMaskIntoConstraints = NO;
    _iconView.contentMode = UIViewContentModeScaleAspectFit;
    _iconView.layer.cornerRadius = 14;
    _iconView.clipsToBounds = YES;
    _iconView.isAccessibilityElement = NO;

    _checkmarkView = [[UIImageView alloc] initWithImage:
        [UIImage systemImageNamed:@"checkmark.circle.fill"]];
    _checkmarkView.translatesAutoresizingMaskIntoConstraints = NO;
    _checkmarkView.tintColor = UIColor.systemBlueColor;
    _checkmarkView.backgroundColor = UIColor.systemBackgroundColor;
    _checkmarkView.layer.cornerRadius = 10;
    _checkmarkView.isAccessibilityElement = NO;

    [self.contentView addSubview:_iconView];
    [self.contentView addSubview:_checkmarkView];
    [NSLayoutConstraint activateConstraints:@[
        [_iconView.centerYAnchor constraintEqualToAnchor:self.contentView.centerYAnchor],
        [_iconView.centerXAnchor constraintEqualToAnchor:self.contentView.centerXAnchor],
        [_iconView.widthAnchor constraintEqualToConstant:68],
        [_iconView.heightAnchor constraintEqualToConstant:68],
        [_checkmarkView.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_checkmarkView.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-4],
        [_checkmarkView.widthAnchor constraintEqualToConstant:20],
        [_checkmarkView.heightAnchor constraintEqualToConstant:20],
    ]];
    self.isAccessibilityElement = YES;
    self.accessibilityTraits = UIAccessibilityTraitButton;
    return self;
}

- (void)prepareForReuse {
    [super prepareForReuse];
    self.iconView.image = nil;
    self.checkmarkView.hidden = YES;
    self.contentView.layer.borderColor = UIColor.clearColor.CGColor;
    self.accessibilityLabel = nil;
    self.accessibilityValue = nil;
    self.accessibilityTraits = UIAccessibilityTraitButton;
}

- (void)configureWithItem:(NEINIconPickerItem *)item selected:(BOOL)selected {
    self.iconView.image = item.image;
    self.checkmarkView.hidden = !selected;
    self.contentView.layer.borderColor = selected
        ? UIColor.systemBlueColor.CGColor : UIColor.clearColor.CGColor;
    self.accessibilityLabel = item.name;
    self.accessibilityValue = selected ? @"目前使用" : nil;
    if (selected) self.accessibilityTraits |= UIAccessibilityTraitSelected;
}

@end

@interface NEINIconPickerViewController : UIViewController
    <UICollectionViewDataSource, UICollectionViewDelegateFlowLayout, UISearchResultsUpdating>
@property(nonatomic, strong) NSDictionary *configuration;
@property(nonatomic, strong) NSArray<NEINIconPickerItem *> *allItems;
@property(nonatomic, copy) NSArray<NSString *> *visibleCategories;
@property(nonatomic, copy) NSArray<NEINIconPickerItem *> *visibleItems;
@property(nonatomic, copy) NSDictionary<NSString *, NSArray<NEINIconPickerItem *> *> *visibleItemsByCategory;
@property(nonatomic, strong) UICollectionView *collectionView;
@property(nonatomic, strong) UILabel *messageLabel;
@property(nonatomic, copy) NSString *currentIconName;
@property(nonatomic, copy) NSString *configurationError;
@property(nonatomic) BOOL changingIcon;
- (instancetype)initWithConfiguration:(NSDictionary *)configuration;
@end

@implementation NEINIconPickerViewController

- (instancetype)initWithConfiguration:(NSDictionary *)configuration {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _configuration = [configuration copy];
        _currentIconName = UIApplication.sharedApplication.alternateIconName
            ?: configuration[@"PrimaryIcon"];
        [self loadItems];
    }
    return self;
}

- (void)setVisibleItems:(NSArray<NEINIconPickerItem *> *)visibleItems {
    _visibleItems = [visibleItems copy] ?: @[];

    NSMutableArray<NSString *> *categories = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSMutableArray<NEINIconPickerItem *> *> *groupedItems =
        [NSMutableDictionary dictionary];
    for (NEINIconPickerItem *item in _visibleItems) {
        NSMutableArray<NEINIconPickerItem *> *categoryItems = groupedItems[item.category];
        if (!categoryItems) {
            categoryItems = [NSMutableArray array];
            groupedItems[item.category] = categoryItems;
            [categories addObject:item.category];
        }
        [categoryItems addObject:item];
    }

    NSMutableDictionary<NSString *, NSArray<NEINIconPickerItem *> *> *itemsByCategory =
        [NSMutableDictionary dictionaryWithCapacity:categories.count];
    for (NSString *category in categories) {
        itemsByCategory[category] = [groupedItems[category] copy];
    }
    self.visibleCategories = categories;
    self.visibleItemsByCategory = itemsByCategory;
}

- (void)loadItems {
    NSArray *allowedNames = self.configuration[@"AllowedIconNames"];
    NSString *primaryName = self.configuration[@"PrimaryIcon"];
    NSString *manifestPath = self.configuration[@"PreviewManifest"];
    // NSBundle.infoDictionary may omit device-specific keys such as CFBundleIcons~ipad.
    NSDictionary *info = NEINIconPickerBundleInfo();
    NSString *iconKey = UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad
        ? @"CFBundleIcons~ipad" : @"CFBundleIcons";
    NSDictionary *alternates = info[iconKey][@"CFBundleAlternateIcons"];
    if (![allowedNames isKindOfClass:NSArray.class] ||
        ![primaryName isKindOfClass:NSString.class] ||
        ![manifestPath isKindOfClass:NSString.class] ||
        ![alternates isKindOfClass:NSDictionary.class] ||
        ![allowedNames containsObject:primaryName]) {
        self.configurationError = @"NEIN 圖示設定不完整。";
        return;
    }

    NSString *resourceRoot = NSBundle.mainBundle.resourcePath;
    NSString *resolvedManifest = [resourceRoot stringByAppendingPathComponent:manifestPath];
    NSData *manifestData = [NSData dataWithContentsOfFile:resolvedManifest];
    NSDictionary *manifest = manifestData
        ? [NSJSONSerialization JSONObjectWithData:manifestData options:0 error:NULL]
        : nil;
    NSArray *manifestItems = manifest[@"icons"];
    NSString *originalPrimaryName = self.configuration[@"OriginalPrimaryIcon"];
    if (![manifestItems isKindOfClass:NSArray.class] ||
        manifestItems.count != allowedNames.count) {
        self.configurationError = @"圖示預覽清單缺失或不完整。";
        return;
    }
    if (![originalPrimaryName isKindOfClass:NSString.class] ||
        ![allowedNames containsObject:originalPrimaryName]) {
        self.configurationError = @"原版圖示不在允許清單中。";
        return;
    }

    NSMutableSet *seen = [NSMutableSet setWithCapacity:allowedNames.count];
    NSMutableArray<NEINIconPickerItem *> *items =
        [NSMutableArray arrayWithCapacity:allowedNames.count];
    for (id entry in manifestItems) {
        if (![entry isKindOfClass:NSDictionary.class]) {
            self.configurationError = @"圖示預覽清單格式錯誤。";
            return;
        }
        NSString *name = entry[@"name"];
        NSString *filename = entry[@"file"];
        NSString *category = entry[@"category"];
        if (![name isKindOfClass:NSString.class]) {
            self.configurationError = @"圖示預覽清單格式錯誤。";
            return;
        }
        BOOL registered =
            [name isEqualToString:primaryName] ||
            [alternates[name] isKindOfClass:NSDictionary.class];
        if (![allowedNames containsObject:name] || [seen containsObject:name] ||
            !registered ||
            ![filename isKindOfClass:NSString.class] ||
            ![category isKindOfClass:NSString.class] ||
            ![filename.lastPathComponent isEqualToString:filename]) {
            self.configurationError = @"圖示清單與 iPhone／iPad 註冊不相符。";
            return;
        }
        NSString *imagePath = [resourceRoot
            stringByAppendingPathComponent:@"NEINIconPreviews"];
        imagePath = [imagePath stringByAppendingPathComponent:filename];
        UIImage *image = [UIImage imageWithContentsOfFile:imagePath];
        if (!image) {
            self.configurationError = @"部分圖示預覽無法載入，請重新打包 NEIN。";
            return;
        }
        NEINIconPickerItem *item = [NEINIconPickerItem new];
        item.name = name;
        item.category = category;
        item.image = image;
        [items addObject:item];
        [seen addObject:name];
    }
    if (seen.count != allowedNames.count ||
        ![seen containsObject:originalPrimaryName]) {
        self.configurationError = @"圖示預覽與允許清單不相符。";
        return;
    }

    self.allItems = [items sortedArrayUsingComparator:
        ^NSComparisonResult(NEINIconPickerItem *left, NEINIconPickerItem *right) {
            NSComparisonResult categoryResult =
                [left.category localizedStandardCompare:right.category];
            return categoryResult == NSOrderedSame
                ? [left.name localizedStandardCompare:right.name]
                : categoryResult;
        }];
    self.visibleItems = self.allItems;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"NEIN 圖示";
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    if (self.configurationError) {
        self.messageLabel = [UILabel new];
        self.messageLabel.translatesAutoresizingMaskIntoConstraints = NO;
        self.messageLabel.text = self.configurationError;
        self.messageLabel.textColor = UIColor.secondaryLabelColor;
        self.messageLabel.textAlignment = NSTextAlignmentCenter;
        self.messageLabel.numberOfLines = 0;
        self.messageLabel.accessibilityTraits = UIAccessibilityTraitStaticText;
        [self.view addSubview:self.messageLabel];
        [NSLayoutConstraint activateConstraints:@[
            [self.messageLabel.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:24],
            [self.messageLabel.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-24],
            [self.messageLabel.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        ]];
        return;
    }

    UICollectionViewFlowLayout *layout = [UICollectionViewFlowLayout new];
    layout.minimumInteritemSpacing = 10;
    layout.minimumLineSpacing = 14;
    layout.sectionInset = UIEdgeInsetsMake(12, 16, 20, 16);
    layout.headerReferenceSize = CGSizeMake(0, 38);
    self.collectionView = [[UICollectionView alloc] initWithFrame:CGRectZero
                                             collectionViewLayout:layout];
    self.collectionView.translatesAutoresizingMaskIntoConstraints = NO;
    self.collectionView.backgroundColor = UIColor.systemBackgroundColor;
    self.collectionView.dataSource = self;
    self.collectionView.delegate = self;
    [self.collectionView registerClass:NEINIconPickerCell.class
            forCellWithReuseIdentifier:@"IconCell"];
    [self.collectionView registerClass:UICollectionReusableView.class
            forSupplementaryViewOfKind:UICollectionElementKindSectionHeader
                   withReuseIdentifier:@"IconHeader"];
    [self.view addSubview:self.collectionView];
    [NSLayoutConstraint activateConstraints:@[
        [self.collectionView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.collectionView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.collectionView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.collectionView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];

    UISearchController *search = [[UISearchController alloc]
        initWithSearchResultsController:nil];
    search.searchResultsUpdater = self;
    search.obscuresBackgroundDuringPresentation = NO;
    search.searchBar.placeholder = @"搜尋圖示";
    self.navigationItem.searchController = search;
    self.navigationItem.hidesSearchBarWhenScrolling = YES;
    self.definesPresentationContext = YES;
}

- (NSArray<NEINIconPickerItem *> *)itemsInSection:(NSInteger)section {
    return self.visibleItemsByCategory[self.visibleCategories[section]];
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *query = searchController.searchBar.text ?: @"";
    if (!query.length) {
        self.visibleItems = self.allItems;
    } else {
        self.visibleItems = [self.allItems filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(NEINIconPickerItem *item, NSDictionary *bindings) {
                (void)bindings;
                return [item.name rangeOfString:query
                    options:NSCaseInsensitiveSearch].location != NSNotFound;
            }]];
    }
    [self.collectionView reloadData];
}

- (NSInteger)numberOfSectionsInCollectionView:(UICollectionView *)collectionView {
    (void)collectionView;
    return self.visibleCategories.count;
}

- (NSInteger)collectionView:(UICollectionView *)collectionView
     numberOfItemsInSection:(NSInteger)section {
    (void)collectionView;
    return [self itemsInSection:section].count;
}

- (__kindof UICollectionViewCell *)collectionView:(UICollectionView *)collectionView
                           cellForItemAtIndexPath:(NSIndexPath *)indexPath {
    NEINIconPickerCell *cell = [collectionView
        dequeueReusableCellWithReuseIdentifier:@"IconCell" forIndexPath:indexPath];
    NEINIconPickerItem *item = [self itemsInSection:indexPath.section][indexPath.item];
    [cell configureWithItem:item selected:[item.name isEqualToString:self.currentIconName]];
    return cell;
}

- (UICollectionReusableView *)collectionView:(UICollectionView *)collectionView
              viewForSupplementaryElementOfKind:(NSString *)kind
                                    atIndexPath:(NSIndexPath *)indexPath {
    UICollectionReusableView *header = [collectionView
        dequeueReusableSupplementaryViewOfKind:kind
                           withReuseIdentifier:@"IconHeader"
                                  forIndexPath:indexPath];
    UILabel *label = [header viewWithTag:7001];
    if (!label) {
        label = [UILabel new];
        label.tag = 7001;
        label.translatesAutoresizingMaskIntoConstraints = NO;
        label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
        label.adjustsFontForContentSizeCategory = YES;
        label.textColor = UIColor.labelColor;
        [header addSubview:label];
        [NSLayoutConstraint activateConstraints:@[
            [label.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:16],
            [label.trailingAnchor constraintEqualToAnchor:header.trailingAnchor constant:-16],
            [label.bottomAnchor constraintEqualToAnchor:header.bottomAnchor constant:-4],
        ]];
    }
    label.text = self.visibleCategories[indexPath.section];
    return header;
}

- (CGSize)collectionView:(UICollectionView *)collectionView
                  layout:(UICollectionViewLayout *)layout
  sizeForItemAtIndexPath:(NSIndexPath *)indexPath {
    (void)layout;
    (void)indexPath;
    CGFloat available = CGRectGetWidth(collectionView.bounds) - 32;
    NSInteger columns = MAX(3, (NSInteger)floor((available + 10) / 92));
    CGFloat spacing = 10;
    CGFloat width = floor((available - spacing * (columns - 1)) / columns);
    return CGSizeMake(width, width);
}

- (void)collectionView:(UICollectionView *)collectionView
 didSelectItemAtIndexPath:(NSIndexPath *)indexPath {
    (void)collectionView;
    if (self.changingIcon) return;
    NEINIconPickerItem *item = [self itemsInSection:indexPath.section][indexPath.item];
    if ([item.name isEqualToString:self.currentIconName]) return;

    if (![UIApplication.sharedApplication supportsAlternateIcons]) {
        [self showIconChangeError:@"此圖示不在目前 App 的允許清單中。"];
        return;
    }

    self.changingIcon = YES;
    NSString *requestedName = [item.name isEqualToString:self.configuration[@"PrimaryIcon"]]
        ? nil : item.name;
    [UIApplication.sharedApplication setAlternateIconName:requestedName
        completionHandler:^(NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.changingIcon = NO;
                if (error) {
                    [self showIconChangeError:error.localizedDescription
                        ?: @"系統無法切換 App 圖示。"];
                    return;
                }
                self.currentIconName = item.name;
                [self.collectionView reloadData];
            });
        }];
}

- (void)showIconChangeError:(NSString *)message {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"無法切換圖示"
                         message:message
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end

static void NEINEmbedIconPicker(UIViewController *controller) {
    if (objc_getAssociatedObject(controller, &NEINIconPickerEmbeddedKey)) return;
    NSDictionary *configuration =
        NSBundle.mainBundle.infoDictionary[NEINIconPickerConfigurationKey];
    if (![configuration[@"Enabled"] boolValue]) return;

    NEINIconPickerViewController *picker =
        [[NEINIconPickerViewController alloc] initWithConfiguration:configuration];
    UIView *nativeView = controller.view;
    [controller addChildViewController:picker];
    for (UIView *view in nativeView.subviews) {
        view.accessibilityElementsHidden = YES;
    }
    picker.view.translatesAutoresizingMaskIntoConstraints = NO;
    [nativeView addSubview:picker.view];
    [NSLayoutConstraint activateConstraints:@[
        [picker.view.topAnchor constraintEqualToAnchor:nativeView.topAnchor],
        [picker.view.leadingAnchor constraintEqualToAnchor:nativeView.leadingAnchor],
        [picker.view.trailingAnchor constraintEqualToAnchor:nativeView.trailingAnchor],
        [picker.view.bottomAnchor constraintEqualToAnchor:nativeView.bottomAnchor],
    ]];
    controller.navigationItem.searchController = picker.navigationItem.searchController;
    controller.navigationItem.hidesSearchBarWhenScrolling = YES;
    controller.title = picker.title;
    controller.definesPresentationContext = YES;
    [picker didMoveToParentViewController:controller];
    objc_setAssociatedObject(controller, &NEINIconPickerEmbeddedKey, picker,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static IMP NEINOriginalAppIconViewDidLoad;

static void NEINIconPickerAppIconViewDidLoad(id self, SEL selector) {
    ((void (*)(id, SEL))NEINOriginalAppIconViewDidLoad)(self, selector);
    NEINEmbedIconPicker(self);
}

static BOOL NEINClassDefinesMethod(Class cls, SEL selector, Method *result) {
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return NO;
    BOOL found = NO;
    for (unsigned i = 0; i < count; ++i) {
        if (method_getName(methods[i]) == selector) {
            if (result) *result = methods[i];
            found = YES;
            break;
        }
    }
    free(methods);
    return found;
}

static void NEINInstallIconPicker(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *configuration =
            NSBundle.mainBundle.infoDictionary[NEINIconPickerConfigurationKey];
        if (![configuration[@"Enabled"] boolValue]) return;

        Class iconClass = NSClassFromString(
            @"_TtC14LineSettingsUI21AppIconViewController");
        if (!iconClass || ![iconClass isSubclassOfClass:UIViewController.class]) {
            NSLog(@"[NEINIconPicker] LINE app icon controller not found; skipping.");
            return;
        }

        SEL selector = @selector(viewDidLoad);
        Method inherited = class_getInstanceMethod(iconClass, selector);
        if (!NEINMethodHasType(inherited, "v", 2, NULL, NULL)) {
            NSLog(@"[NEINIconPicker] Unexpected app icon viewDidLoad signature; skipping.");
            return;
        }

        Method ownMethod = NULL;
        if (NEINClassDefinesMethod(iconClass, selector, &ownMethod)) {
            NEINOriginalAppIconViewDidLoad = method_setImplementation(
                ownMethod, (IMP)NEINIconPickerAppIconViewDidLoad);
        } else {
            NEINOriginalAppIconViewDidLoad = method_getImplementation(inherited);
            if (!class_addMethod(iconClass, selector,
                                 (IMP)NEINIconPickerAppIconViewDidLoad,
                                 method_getTypeEncoding(inherited))) {
                NSLog(@"[NEINIconPicker] Cannot hook app icon page; skipping.");
                return;
            }
        }
        NSLog(@"[NEINIconPicker] LINE app icon page now hosts the NEIN picker.");
    });
}
