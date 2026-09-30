import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import main

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin', 'iOS hook compilation requires macOS.')
class IconPickerCompileTests(unittest.TestCase):
    def test_icon_picker_hook_compiles_for_ios(self):
        sdk = subprocess.check_output(
            ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True,
        ).strip()
        subprocess.run([
            'xcrun', '--sdk', 'iphoneos', 'clang',
            '-target', 'arm64-apple-ios18.0',
            '-isysroot', sdk,
            '-fobjc-arc', '-fblocks', '-fsyntax-only',
            '-DNEIN_MULTI_ICON_PICKER=1',
            str(ROOT / 'hooks' / 'NEINHooks.m'),
        ], check=True)

    def test_ad_removal_hook_compiles_for_ios(self):
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / 'NEINAdDomains.h'
            header.write_text(
                main.scan_ad_domains.render_header(main.load_ad_domains()),
                encoding='utf-8',
            )
            sdk = subprocess.check_output(
                ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True,
            ).strip()
            subprocess.run([
                'xcrun', '--sdk', 'iphoneos', 'clang',
                '-target', 'arm64-apple-ios18.0',
                '-isysroot', sdk,
                '-fobjc-arc', '-fblocks', '-fsyntax-only',
                '-DNEIN_MULTI_REMOVE_ADS=1',
                '-I', directory,
                str(ROOT / 'hooks' / 'NEINHooks.m'),
            ], check=True)


if __name__ == '__main__':
    unittest.main()
