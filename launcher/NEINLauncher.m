#import <Foundation/Foundation.h>
#include <errno.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(void) {
    @autoreleasepool {
        NSString *launcherPath = NSBundle.mainBundle.bundlePath;
        NSString *templatePath = [launcherPath
            stringByAppendingPathComponent:
                @"Contents/Resources/LINE.app"];

        NSString *templateExecutable = [templatePath
            stringByAppendingPathComponent:@"Contents/MacOS/LINE"];
        if (![[NSFileManager defaultManager] isExecutableFileAtPath:templateExecutable]) {
            NSLog(@"[NEINLauncher] inner LINE executable is missing: %@", templateExecutable);
            return ENOENT;
        }

        NSString *runtimeRoot = [NSHomeDirectory()
            stringByAppendingPathComponent:@"Library/Application Support/NEIN/Runtime"];
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:runtimeRoot
            withIntermediateDirectories:YES attributes:nil error:&error]) {
            NSLog(@"[NEINLauncher] cannot create runtime directory: %@", error);
            return EIO;
        }

        NSString *innerInfoPath = [templatePath
            stringByAppendingPathComponent:@"Contents/Info.plist"];
        NSDictionary *innerInfo = [NSDictionary dictionaryWithContentsOfFile:innerInfoPath];
        NSString *version = innerInfo[@"CFBundleShortVersionString"] ?: @"current";
        // Keep one stable runtime path per LINE version.  A random path on
        // every launch makes macOS TCC treat the app as a new file location
        // and repeatedly ask for folder access.
        NSString *runtimeName = [NSString stringWithFormat:@"LINE-%@.app", version];
        NSString *runtimeApp = [runtimeRoot stringByAppendingPathComponent:runtimeName];
        NSString *runtimeExecutable = [runtimeApp
            stringByAppendingPathComponent:@"Contents/MacOS/LINE"];
        if (![[NSFileManager defaultManager] isExecutableFileAtPath:runtimeExecutable]) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:runtimeApp] &&
                ![[NSFileManager defaultManager] removeItemAtPath:runtimeApp error:&error]) {
                NSLog(@"[NEINLauncher] cannot replace runtime copy: %@", error);
                return EIO;
            }
            if (![[NSFileManager defaultManager] copyItemAtPath:templatePath
                toPath:runtimeApp error:&error]) {
                NSLog(@"[NEINLauncher] cannot prepare runtime copy: %@", error);
                return EIO;
            }
        }

        NSString *linePath = runtimeExecutable;
        NSString *workingDirectory = [linePath stringByDeletingLastPathComponent];
        if (chdir(workingDirectory.fileSystemRepresentation) != 0) {
            NSLog(@"[NEINLauncher] cannot change working directory: %s", strerror(errno));
            return errno;
        }

        pid_t child = 0;
        char *arguments[] = {(char *)linePath.fileSystemRepresentation, NULL};
        int spawnError = posix_spawn(&child, arguments[0], NULL, NULL, arguments, environ);
        if (spawnError != 0) {
            NSLog(@"[NEINLauncher] posix_spawn failed: %s", strerror(spawnError));
            return spawnError;
        }

        int childStatus = 0;
        while (waitpid(child, &childStatus, 0) < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        if (WIFEXITED(childStatus)) return WEXITSTATUS(childStatus);
        if (WIFSIGNALED(childStatus)) return 128 + WTERMSIG(childStatus);
        return 1;
    }
}
