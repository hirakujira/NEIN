import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin', 'Requires macOS Objective-C runtime')
class PromotionalTabsTests(unittest.TestCase):
    def test_production_selection_with_view_doubles(self):
        self.compile_and_run(Path(__file__).with_suffix('.m'))

    def test_native_presentation_lifecycle_with_view_doubles(self):
        self.compile_and_run(Path(__file__).with_name('test_visible_tab_bar.m'))

    def test_skin_icons_with_view_doubles(self):
        self.compile_and_run(Path(__file__).with_name('test_visible_tab_bar.m'), skin=True)

    def test_skin_settings_fallback_with_view_doubles(self):
        for settings in ('voom', 'wallet', 'none', 'legacy-today'):
            with self.subTest(settings=settings):
                self.compile_and_run(Path(__file__).with_name('test_visible_tab_bar.m'),
                                     skin=True, settings=settings)

    def test_ad_domain_boundary_matching(self):
        self.compile_and_run(Path(__file__).with_name('test_ad_domain_matcher.m'))

    def test_duo_split_layout_with_view_doubles(self):
        self.compile_and_run(Path(__file__).with_name('test_duo_split_layout.m'))

    def test_duo_camera_layout_with_catalyst_uikit(self):
        sdk = subprocess.run(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], check=True,
                             capture_output=True, text=True).stdout.strip()
        frameworks = sdk + '/System/iOSSupport/System/Library/Frameworks'
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'camera-tests'
            subprocess.run([
                'xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-ios18.0-macabi',
                '-iframework', frameworks, '-F', frameworks, '-fobjc-arc',
                '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                '-framework', 'CoreGraphics', '-framework', 'UIKit', '-framework', 'QuartzCore',
                str(Path(__file__).with_name('test_duo_camera_layout.m')), '-o', str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)

    def compile_and_run(self, source, skin=False, settings='today'):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'tab-tests'
            if skin:
                (Path(directory) / 'NEINThemeConfig.h').write_text(
                    'static const char *const NEINSkinThemeTarget = "owned-theme";\n')
                rules = {
                    'liquid.tabBar.home': {'icon.image': {
                        'normal': {'light': 'skin-home-light.png', 'dark': 'skin-home-dark.png'},
                        'selected': {'light': 'skin-home-on.png', 'dark': 'skin-home-on-dark.png'},
                    }},
                    'liquid.tabBar.chat': {'icon.image': {
                        'normal': 'skin-chat.png', 'selected': 'skin-chat-on.png',
                    }},
                    'liquid.tabBar.call': {'icon.image': {
                        'normal': 'missing.png', 'selected': 'missing-on.png',
                    }},
                    'line.tabBar.call': {'icon.image': {
                        'normal': 'skin-call.png', 'selected': 'skin-call-on.png',
                    }},
                    'liquid.tabBar.setting': {'icon.image': []},
                }
                for role in ('today', 'voom', 'wallet'):
                    available = settings != 'none' and (
                        role == settings or role == 'wallet' or
                        (settings in ('today', 'legacy-today') and role == 'voom'))
                    stem = ('skin-' if available else 'missing-') + role
                    rules['liquid.tabBar.' + role] = {'icon.image': {
                        'normal': stem + '.png', 'selected': stem + '-on.png',
                    }}
                if settings == 'legacy-today':
                    rules['line.tabBar.today'] = {'icon.image': {
                        'normal': 'skin-today.png', 'selected': 'skin-today-on.png',
                    }}
                (Path(directory) / 'default.json').write_text(json.dumps(rules))
            subprocess.run([
                'xcrun', '--sdk', 'macosx', 'clang', '-fobjc-arc',
                '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                '-framework', 'CoreGraphics',
                *(['-DNEIN_MULTI_SKIN_THEME=1', '-I', directory] if skin else []),
                str(source), '-o', str(executable),
            ], check=True)
            subprocess.run([str(executable), *([settings] if skin else [])], check=True)
