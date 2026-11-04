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

static inline BOOL NEINHookClassMethod(Class cls, SEL selector, const char *returnType,
                                     unsigned argumentCount, const char *argument2,
                                     const char *argument3, IMP replacement, IMP *original) {
    Class meta = object_getClass(cls);
    Method method = meta ? class_getInstanceMethod(meta, selector) : NULL;
    if (!NEINMethodHasType(method, returnType, argumentCount, argument2, argument3)) {
        return NO;
    }
    if (original) *original = method_getImplementation(method);
    method_setImplementation(method, replacement);
    return YES;
}
