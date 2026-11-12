import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'hooks' / 'NEINHooks.m'
FULL_COMBO = (
    'KEYCHAIN_COMPAT', 'DIAGNOSTICS', 'REMOVE_ADS', 'HIDE_PROMOTIONAL_TABS',
    'IPHONE_DUO', 'ICON_PICKER',
)


@unittest.skipUnless(sys.platform == 'darwin', 'iOS hook compilation requires macOS.')
class IconPickerCompileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = tempfile.TemporaryDirectory()
        directory = Path(cls.generated.name)
        (directory / 'NEINAdDomains.h').write_text(
            main.scan_ad_domains.render_header(main.load_ad_domains()), encoding='utf-8',
        )
        profile = sorted(main.analyze_patch_profile.PROFILE_DIR.glob('*.json'))[-1]
        (directory / 'NEINKeychainProfileData.h').write_text(
            main.analyze_patch_profile.render_c_header(
                json.loads(profile.read_text(encoding='utf-8'))['keychain'],
            ),
            encoding='utf-8',
        )

    @classmethod
    def tearDownClass(cls):
        cls.generated.cleanup()

    def compile_hooks(self, *macros, check=True):
        # Same target and warnings as main.build_compat_dylib, plus -Werror.
        return subprocess.run([
            'xcrun', '--sdk', 'iphoneos', 'clang',
            '-target', 'arm64-apple-ios18.0',
            '-fobjc-arc', '-fblocks', '-fsyntax-only', '-Wall', '-Wextra', '-Werror',
            *(f'-DNEIN_MULTI_{macro}=1' for macro in macros),
            '-I', self.generated.name, str(HOOKS),
        ], check=check, capture_output=not check, text=True)

    def test_hook_flag_combinations_compile_for_ios(self):
        for macros in (
            (),
            ('ICON_PICKER',),
            ('DIAGNOSTICS',),
            ('KEYCHAIN_COMPAT', 'DIAGNOSTICS'),
            ('REMOVE_ADS',),
            ('HIDE_PROMOTIONAL_TABS',),
            ('REMOVE_ADS', 'HIDE_PROMOTIONAL_TABS'),
            ('IPHONE_DUO',),
            ('IPHONE_DUO', 'HIDE_PROMOTIONAL_TABS', 'ICON_PICKER'),
            FULL_COMBO,
        ):
            with self.subTest(macros=macros):
                self.compile_hooks(*macros)

    def test_keychain_compat_requires_diagnostics(self):
        result = self.compile_hooks('KEYCHAIN_COMPAT', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires NEIN_MULTI_DIAGNOSTICS', result.stderr)


if __name__ == '__main__':
    unittest.main()
