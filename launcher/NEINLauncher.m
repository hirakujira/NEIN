#import <Foundation/Foundation.h>
#include <errno.h>
#include <spawn.h>
#include <fcntl.h>
#include <sys/file.h>
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
#ifdef NEIN_TEST_RUNTIME_ROOT
        const char *testRoot = getenv("NEIN_TEST_RUNTIME_ROOT");
        if (testRoot) runtimeRoot = [NSString stringWithUTF8String:testRoot];
#endif
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:runtimeRoot
            withIntermediateDirectories:YES attributes:nil error:&error]) {
            NSLog(@"[NEINLauncher] cannot create runtime directory: %@", error);
            return EIO;
        }
        NSString *lockPath = [runtimeRoot stringByAppendingPathComponent:@"launcher.lock"];
        int lockFD = open(lockPath.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
        if (lockFD < 0) return errno;
        if (flock(lockFD, LOCK_EX | LOCK_NB) != 0) {
            NSLog(@"[NEINLauncher] another instance is already running");
            close(lockFD);
            return 0;
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
        NSFileManager *files = NSFileManager.defaultManager;
        NSString *seal = @"Contents/_CodeSignature/CodeResources";
        NSData *templateSeal = [NSData dataWithContentsOfFile:[templatePath stringByAppendingPathComponent:seal]];
        NSData *runtimeSeal = [NSData dataWithContentsOfFile:[runtimeApp stringByAppendingPathComponent:seal]];
        if (!templateSeal) {
            NSLog(@"[NEINLauncher] inner app signature seal is missing");
            return EIO;
        }
        if (![files isExecutableFileAtPath:runtimeExecutable] ||
            ![templateSeal isEqualToData:runtimeSeal] ||
            ![files contentsEqualAtPath:templateExecutable andPath:runtimeExecutable]) {
            NSString *staging = [runtimeRoot stringByAppendingPathComponent:
                [NSString stringWithFormat:@".LINE-stage-%@.app", NSUUID.UUID.UUIDString]];
            if (![files copyItemAtPath:templatePath toPath:staging error:&error]) {
                NSLog(@"[NEINLauncher] cannot prepare runtime copy: %@", error);
                return EIO;
            }
            if ([files fileExistsAtPath:runtimeApp]) {
                if (renamex_np(staging.fileSystemRepresentation, runtimeApp.fileSystemRepresentation, RENAME_SWAP) != 0) {
                    NSLog(@"[NEINLauncher] cannot swap runtime copy: %s", strerror(errno));
                    [files removeItemAtPath:staging error:nil];
                    return EIO;
                }
                [files removeItemAtPath:staging error:nil];
            } else if (![files moveItemAtPath:staging toPath:runtimeApp error:&error]) {
                NSLog(@"[NEINLauncher] cannot install runtime copy: %@", error);
                [files removeItemAtPath:staging error:nil];
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
