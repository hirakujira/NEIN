#import <AppKit/AppKit.h>
#import <ImageIO/ImageIO.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <regex.h>

@interface NSObject (NEINCoreUICatalog)
- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
- (NSArray<NSString *> *)allImageNames;
- (id)imageWithName:(NSString *)name scaleFactor:(CGFloat)scale;
- (CGImageRef)image;
@end

static const size_t NEINPreviewSize = 144;

static BOOL NEINValidIconName(NSString *name) {
    const char *value = name.UTF8String;
    if (!value) return NO;
    regex_t expression;
    if (regcomp(&expression, "^[A-Za-z0-9_-]+$", REG_EXTENDED | REG_NOSUB) != 0) {
        return NO;
    }
    BOOL valid = regexec(&expression, value, 0, NULL, 0) == 0;
    regfree(&expression);
    return valid;
}

static CGImageRef NEINCreatePreview(CGImageRef source) {
    size_t sourceWidth = CGImageGetWidth(source);
    size_t sourceHeight = CGImageGetHeight(source);
    if (sourceWidth == 0 || sourceHeight == 0) return NULL;

    CGFloat scale = MIN((CGFloat)NEINPreviewSize / sourceWidth,
                        (CGFloat)NEINPreviewSize / sourceHeight);
    size_t width = MAX((size_t)1, (size_t)llround(sourceWidth * scale));
    size_t height = MAX((size_t)1, (size_t)llround(sourceHeight * scale));
    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!colorSpace) return NULL;

    CGContextRef context = CGBitmapContextCreate(
        NULL, NEINPreviewSize, NEINPreviewSize, 8, NEINPreviewSize * 4,
        colorSpace, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big
    );
    CGColorSpaceRelease(colorSpace);
    if (!context) return NULL;

    CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
    CGRect destination = CGRectMake(
        (NEINPreviewSize - width) / 2.0,
        (NEINPreviewSize - height) / 2.0,
        width, height
    );
    CGContextDrawImage(context, destination, source);
    CGImageRef preview = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    return preview;
}

static BOOL NEINWritePNG(CGImageRef image, NSURL *url, NSError **error) {
    CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
        (__bridge CFURLRef)url, (__bridge CFStringRef)UTTypePNG.identifier, 1, NULL
    );
    if (!destination) return NO;
    CGImageDestinationAddImage(destination, image, NULL);
    BOOL success = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    if (!success && error) {
        *error = [NSError errorWithDomain:@"NEINIconPreview"
                                     code:1
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"Could not encode the icon preview as PNG."}];
    }
    return success;
}

static NSString *NEINCategoryForName(NSString *name) {
    NSString *prefix = [[name componentsSeparatedByString:@"_"] firstObject];
    NSDictionary *categories = @{
        @"basic": @"LINE 基本圖示",
        @"promotion": @"活動圖示",
        @"special": @"特別版圖示",
        @"collaboration": @"聯名圖示",
        @"design": @"設計圖示",
    };
    return categories[prefix] ?: @"其他圖示";
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 4) {
            fprintf(stderr, "usage: extract_icon_previews Assets.car icon-names.json output-directory\n");
            return 2;
        }

        NSURL *catalogURL = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[1]]];
        NSURL *namesURL = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[2]]];
        NSURL *outputURL = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[3]] isDirectory:YES];
        NSData *namesData = [NSData dataWithContentsOfURL:namesURL];
        NSArray *names = namesData
            ? [NSJSONSerialization JSONObjectWithData:namesData options:0 error:NULL]
            : nil;
        if (![names isKindOfClass:NSArray.class] || names.count == 0) {
            fprintf(stderr, "icon-names.json must contain a non-empty JSON array.\n");
            return 2;
        }

        NSString *frameworkPath =
            @"/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI";
        if (!dlopen(frameworkPath.fileSystemRepresentation, RTLD_NOW)) {
            fprintf(stderr, "Could not load macOS CoreUI.\n");
            return 1;
        }
        Class catalogClass = NSClassFromString(@"CUICatalog");
        if (!catalogClass) {
            fprintf(stderr, "CUICatalog is not available in CoreUI.\n");
            return 1;
        }
        NSError *error = nil;
        id catalog = [[catalogClass alloc] initWithURL:catalogURL error:&error];
        if (!catalog) {
            fprintf(stderr, "Could not open Assets.car: %s\n",
                    error.localizedDescription.UTF8String ?: "unknown error");
            return 1;
        }
        NSSet<NSString *> *availableNames =
            [NSSet setWithArray:[catalog allImageNames]];
        if (![[NSFileManager defaultManager] createDirectoryAtURL:outputURL
                                     withIntermediateDirectories:YES
                                                      attributes:nil
                                                           error:&error]) {
            fprintf(stderr, "Could not create preview directory: %s\n",
                    error.localizedDescription.UTF8String ?: "unknown error");
            return 1;
        }

        NSMutableArray *entries = [NSMutableArray arrayWithCapacity:names.count];
        NSMutableSet *seen = [NSMutableSet setWithCapacity:names.count];
        for (id value in names) {
            if (![value isKindOfClass:NSString.class] ||
                !NEINValidIconName(value) || [seen containsObject:value]) {
                fprintf(stderr, "Icon names must be unique, safe strings.\n");
                return 2;
            }
            NSString *name = value;
            [seen addObject:name];
            if (![availableNames containsObject:name]) {
                fprintf(stderr, "Missing icon rendition in Assets.car: %s\n",
                        name.UTF8String);
                return 1;
            }

            id rendition = [catalog imageWithName:name scaleFactor:1.0];
            CGImageRef source = NULL;
            if (rendition) {
                CGImageRef (*imageFunction)(id, SEL) = (CGImageRef (*)(id, SEL))
                    [rendition methodForSelector:@selector(image)];
                source = imageFunction(rendition, @selector(image));
            }
            if (!source) {
                fprintf(stderr, "Could not decode icon rendition: %s\n",
                        name.UTF8String);
                return 1;
            }
            CGImageRef preview = NEINCreatePreview(source);
            if (!preview) {
                fprintf(stderr, "Could not render icon preview: %s\n",
                        name.UTF8String);
                return 1;
            }

            NSString *filename = [name stringByAppendingPathExtension:@"png"];
            NSURL *previewURL = [outputURL URLByAppendingPathComponent:filename];
            BOOL written = NEINWritePNG(preview, previewURL, &error);
            CGImageRelease(preview);
            if (!written) {
                fprintf(stderr, "Could not write icon preview %s: %s\n",
                        filename.UTF8String,
                        error.localizedDescription.UTF8String ?: "unknown error");
                return 1;
            }
            [entries addObject:@{
                @"name": name,
                @"file": filename,
                @"category": NEINCategoryForName(name),
            }];
        }

        NSDictionary *manifest = @{
            @"schemaVersion": @1,
            @"icons": entries,
        };
        NSData *manifestData = [NSJSONSerialization dataWithJSONObject:manifest
                                    options:NSJSONWritingPrettyPrinted error:&error];
        NSURL *manifestURL = [outputURL URLByAppendingPathComponent:@"manifest.json"];
        if (!manifestData ||
            ![manifestData writeToURL:manifestURL options:NSDataWritingAtomic error:&error]) {
            fprintf(stderr, "Could not write icon preview manifest: %s\n",
                    error.localizedDescription.UTF8String ?: "unknown error");
            return 1;
        }
        return 0;
    }
}
