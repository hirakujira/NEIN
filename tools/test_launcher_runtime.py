import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LauncherRuntimeTests(unittest.TestCase):
    def test_first_launch_reuse_update_and_running_lock(self):
        with tempfile.TemporaryDirectory(prefix='nein-launcher-test-') as directory:
            root = Path(directory)
            contents = root / 'NEIN.app/Contents'
            launcher = contents / 'MacOS/NEINLauncher'
            launcher.parent.mkdir(parents=True)
            (contents / 'Info.plist').write_bytes(plistlib.dumps({
                'CFBundleExecutable': 'NEINLauncher', 'CFBundleIdentifier': 'test.nein.launcher',
                'CFBundlePackageType': 'APPL',
            }))
            inner = contents / 'Resources/LINE.app/Contents'
            executable = inner / 'MacOS/LINE'
            seal = inner / '_CodeSignature/CodeResources'
            executable.parent.mkdir(parents=True)
            seal.parent.mkdir()
            (inner / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': '26.4.2'}))
            seal.write_text('seal-one')
            executable.write_text('#!/bin/sh\necho first >> "$NEIN_TEST_RESULTS"\n')
            executable.chmod(0o755)
            subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-DNEIN_TEST_RUNTIME_ROOT',
                            '-framework', 'Foundation', str(ROOT / 'launcher/NEINLauncher.m'),
                            '-o', str(launcher)], check=True)
            env = dict(os.environ, NEIN_TEST_RUNTIME_ROOT=str(root / 'runtime'),
                       NEIN_TEST_RESULTS=str(root / 'results'))
            runtime = root / 'runtime/LINE-26.4.2.app/Contents/MacOS/LINE'
            subprocess.run([str(launcher)], env=env, check=True)
            inode = runtime.stat().st_ino
            subprocess.run([str(launcher)], env=env, check=True)
            self.assertEqual(runtime.stat().st_ino, inode)
            executable.write_text('#!/bin/sh\necho updated >> "$NEIN_TEST_RESULTS"\n')
            subprocess.run([str(launcher)], env=env, check=True)
            self.assertEqual((root / 'results').read_text().splitlines(), ['first', 'first', 'updated'])
            self.assertEqual(runtime.read_text(), executable.read_text())
            executable.write_text('#!/bin/sh\necho running >> "$NEIN_TEST_RESULTS"\nsleep 2\n')
            child = subprocess.Popen([str(launcher)], env=env)
            try:
                deadline = time.monotonic() + 10
                while 'running' not in (root / 'results').read_text() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertIn('running', (root / 'results').read_text())
                subprocess.run([str(launcher)], env=env, check=True)
                self.assertEqual((root / 'results').read_text().splitlines().count('running'), 1)
            finally:
                child.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
