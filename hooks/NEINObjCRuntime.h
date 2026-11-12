#pragma once

#import <objc/runtime.h>
#include <string.h>

static inline BOOL NEINMethodHasType(Method method, const char *returnType,
                                   unsigned argumentCount, const char *argument2,
                                   const char *argument3) {
    if (!method || method_getNumberOfArguments(method) != argumentCount) return NO;
    char type[32] = {0};
    method_getReturnType(method, type, sizeof(type));
    if (strcmp(type, returnType) != 0) return NO;
    if (argument2) {
        method_getArgumentType(method, 2, type, sizeof(type));
        if (strcmp(type, argument2) != 0) return NO;
    }
    if (argument3) {
        method_getArgumentType(method, 3, type, sizeof(type));
        if (strcmp(type, argument3) != 0) return NO;
    }
    return YES;
}

static inline BOOL NEINHook(Class cls, SEL selector, const char *returnType,
                          unsigned argumentCount, const char *argument2,
                          const char *argument3, IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!NEINMethodHasType(method, returnType, argumentCount, argument2, argument3)) {
        return NO;
    }
    if (original) *original = method_getImplementation(method);
    method_setImplementation(method, replacement);
    return YES;
}

// Replaces the method on cls only. An inherited implementation is shadowed by
// an added method so the superclass and its other subclasses stay untouched.
static inline BOOL NEINHookOwnMethod(Class cls, SEL selector, const char *returnType,
                                   unsigned argumentCount, const char *argument2,
                                   const char *argument3, IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!NEINMethodHasType(method, returnType, argumentCount, argument2, argument3)) {
        return NO;
    }
    IMP previous = method_getImplementation(method);
    if (original) *original = previous;
    const char *encoding = method_getTypeEncoding(method);
    if (!class_addMethod(cls, selector, replacement, encoding)) {
        method_setImplementation(method, replacement);
    }
    return YES;
}

static inline BOOL NEINHookClassMethod(Class cls, SEL selector, const char *returnType,
                                     unsigned argumentCount, const char *argument2,
                                     const char *argument3, IMP replacement, IMP *original) {
    return NEINHook(object_getClass(cls), selector, returnType, argumentCount,
                    argument2, argument3, replacement, original);
}
