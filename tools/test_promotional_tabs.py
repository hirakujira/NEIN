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

    def test_ad_domain_boundary_matching(self):
        self.compile_and_run(Path(__file__).with_name('test_ad_domain_matcher.m'))

    def test_duo_split_layout_with_view_doubles(self):
        self.compile_and_run(Path(__file__).with_name('test_duo_split_layout.m'))

    def compile_and_run(self, source):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'tab-tests'
            subprocess.run([
                'xcrun', '--sdk', 'macosx', 'clang', '-fobjc-arc',
                '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                '-framework', 'CoreGraphics',
                str(source), '-o', str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)
