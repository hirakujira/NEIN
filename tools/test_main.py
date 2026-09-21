import hashlib
import json
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main  # noqa: E402


class MainToolTests(unittest.TestCase):
    def sample_info(self):
        icons = {
            'CFBundlePrimaryIcon': {
                'CFBundleIconFiles': ['basic_default60x60'],
                'CFBundleIconName': 'basic_default',
            },
            'CFBundleAlternateIcons': {
                'design_deep_blue': {'CFBundleIconName': 'design_deep_blue'},
                'design_simple_banana': {'CFBundleIconName': 'design_simple_banana'},
            },
        }
        return {
            'CFBundleIdentifier': 'jp.naver.line',
            'CFBundleShortVersionString': '26.14.0',
            'CFBundleVersion': '2026.828.1845',
            'CFBundleDisplayName': 'LINE',
            'CFBundleName': 'LINE',
            'CFBundleURLTypes': [{
                'CFBundleURLSchemes': ['line', 'lineauth2'],
            }],
            'CFBundleURLTypes~ipad': [{
                'CFBundleURLSchemes': ['line'],
            }],
            'CFBundleIcons': icons,
            'CFBundleIcons~ipad': icons,
        }

    def sample_binary(self, reference=False):
        image_base = 0x100000000
        text_address = 0x100001000
        text_offset = 200
        text_size = 60 * 4
        branch_index = 12
        target_index = 14
        branch = 0x36000000 | ((target_index - branch_index) << 5)
        instructions = [main.analyze_patch_profile.NOP] * 60
        instructions[branch_index] = branch
        if reference:
            instructions[:len(main.analyze_patch_profile.REFERENCE_WINDOW)] = (
                main.analyze_patch_profile.REFERENCE_WINDOW
            )
            instructions[branch_index] |= (target_index - branch_index) << 5
        text = struct.pack('<60I', *instructions)
        binary = bytearray(text_offset + text_size + 3)
        struct.pack_into('<I', binary, 0, 0xFEEDFACF)
        struct.pack_into('<I', binary, 4, 0x0100000C)
        struct.pack_into('<II', binary, 16, 2, 168)
        struct.pack_into('<II', binary, 32, 0x19, 152)
        binary[40:46] = b'__TEXT'
        struct.pack_into('<QQQQ', binary, 56, image_base, 0x2000, 0, len(binary))
        struct.pack_into('<IIII', binary, 88, 7, 5, 1, 0)
        section = 104
        binary[section:section + 6] = b'__text'
        binary[section + 16:section + 22] = b'__TEXT'
        struct.pack_into(
            '<QQI', binary, section + 32, text_address, text_size, text_offset,
        )
        struct.pack_into('<IIII', binary, 184, 0x26, 16, 440, 3)
        binary[text_offset:text_offset + text_size] = text
        binary[440:443] = b'\x80\x20\0'
        return bytes(binary)

    def combined_profile(self, info, original, offset=0xf8):
        return {
            'schema_version': main.analyze_patch_profile.PROFILE_SCHEMA_VERSION,
            'profile_type': main.analyze_patch_profile.PROFILE_TYPE,
            'bundle_identifier': 'jp.naver.line',
            'version': info['CFBundleShortVersionString'],
            'build': info['CFBundleVersion'],
            'executable_sha256': hashlib.sha256(original).hexdigest(),
            'architecture': 'arm64',
            'login_patch': {
                'kind': 'secondary_login_entry_branch',
                'file_offset': hex(offset),
                'virtual_address': '0x100001030',
                'target_address': '0x100001038',
                'instruction': 'tbz w0, #0, 0x100001038',
                'original_hex': '40000036',
                'patched_hex': '1f2003d5',
            },
            'keychain': {'profile_type': 'line_keychain'},
        }

    def test_entry_patch_requires_expected_instruction(self):
        profile = main.PatchProfile(
            '26.14.0', 'test', '0' * 64, 248, 0x100001030,
            bytes.fromhex('40000036'), 'tbz w0, #0, 0x100001038',
        )
        binary = bytearray(self.sample_binary())
        patched = main.patched_binary(bytes(binary), profile, verify_hash=False)
        self.assertEqual(patched[profile.patch_offset:profile.patch_offset + 4], main.NOP)

    def test_entry_patch_rejects_wrong_instruction(self):
        profile = main.PatchProfile(
            '26.14.0', 'test', '0' * 64, 248, 0x100001030,
            bytes.fromhex('40000036'), 'tbz w0, #0, 0x100001038',
        )
        binary = bytearray(self.sample_binary())
        binary[248:252] = bytes.fromhex('1f2003d5')
        with self.assertRaises(ValueError):
            main.patched_binary(bytes(binary), profile, verify_hash=False)

    def test_digest_file_streams_large_input(self):
        content = b'nein' * (1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.ipa'
            path.write_bytes(content)
            with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('full read')):
                self.assertEqual(main.digest_file(path), hashlib.sha256(content).hexdigest())

    def test_entry_only_preserves_large_archive_members(self):
        info = self.sample_info()
        info['MinimumOSVersion'] = '18.0'
        original = self.sample_binary()
        profile = main.PatchProfile(
            '26.14.0', 'test', hashlib.sha256(original).hexdigest(),
            248, 0x100001030, bytes.fromhex('40000036'),
            'tbz w0, #0, 0x100001038',
        )
        payload = b'nein' * (1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr(main.EXECUTABLE, original)
                archive.writestr(main.PLIST, plistlib.dumps(info))
                archive.writestr('Payload/LINE.app/Frameworks/', b'')
                member = zipfile.ZipInfo('Payload/LINE.app/large.dat')
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, payload)
                archive.writestr('Payload/LINE.app/PlugIns/removed.appex/file', b'removed')
            args = main.parse_args([str(source), str(output), '--entry-only'])
            with mock.patch.object(main, 'parse_args', return_value=args), \
                    mock.patch.object(main, 'select_profile', return_value=(profile, None)), \
                    redirect_stderr(StringIO()), \
                    mock.patch('sys.stdout', new_callable=StringIO):
                main.main()
            with zipfile.ZipFile(output) as archive:
                self.assertIn('Payload/LINE.app/Frameworks/', archive.namelist())
                self.assertEqual(archive.read('Payload/LINE.app/large.dat'), payload)
                self.assertEqual(archive.getinfo('Payload/LINE.app/large.dat').compress_type,
                                 zipfile.ZIP_DEFLATED)
                self.assertNotIn('Payload/LINE.app/PlugIns/removed.appex/file',
                                 archive.namelist())
                self.assertEqual(archive.read(main.EXECUTABLE),
                                 main.patched_binary(original, profile))
            manifest = json.loads(output.with_suffix('.manifest.json').read_text())
            self.assertEqual(manifest['source_ipa_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(manifest['output_ipa_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(manifest['changed_byte_offsets'], ['0xf8', '0xf9', '0xfa', '0xfb'])

    def test_streamed_archive_copy_rejects_corrupt_member(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'bad.ipa'
            output = Path(directory) / 'output.ipa'
            with zipfile.ZipFile(source, 'w') as archive:
                archive.writestr('Payload/LINE.app/payload', b'corrupt me')
            damaged = bytearray(source.read_bytes())
            damaged[damaged.index(b'corrupt me')] ^= 1
            source.write_bytes(damaged)
            with zipfile.ZipFile(source) as archive, zipfile.ZipFile(output, 'w') as target:
                with self.assertRaises(zipfile.BadZipFile):
                    main.copy_archive_member(
                        archive, target, archive.getinfo('Payload/LINE.app/payload'),
                    )

    def test_profile_loader_matches_version_build_and_binary_hash(self):
        info = self.sample_info()
        original = self.sample_binary()
        document = self.combined_profile(info, original)
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            return_value=(document, False),
        ):
            profile, result = main.select_profile(
                info, original, auto_login_patch=True,
            )
        self.assertEqual(profile.patch_offset, 0xf8)
        self.assertEqual(profile.original, bytes.fromhex('40000036'))
        self.assertEqual(profile.patch_va, 0x100001030)
        self.assertEqual(result['mode'], 'saved_profile')
        self.assertTrue(result['automatic_patch'])
        self.assertTrue(result['patch_applied'])
        self.assertTrue(result['profile_loaded'])

    def test_exact_profile_allows_normal_hook_build_mode(self):
        info = self.sample_info()
        info['CFBundleShortVersionString'] = '26.15.1'
        info['CFBundleVersion'] = '2026.928.1406'
        original = self.sample_binary()
        document = self.combined_profile(info, original)
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            return_value=(document, False),
        ):
            profile, result = main.select_profile(
                info, original,
            )
        with tempfile.TemporaryDirectory() as directory:
            args = main.parse_args([
                str(Path(directory) / 'input.ipa'),
                str(Path(directory) / 'output.ipa'),
                '--keychain-compat', '--remove-ads', '--hide-promotional-tabs',
            ])
        self.assertEqual(profile.version, '26.15.1')
        self.assertIsNone(result)
        self.assertFalse(args.entry_only)
        self.assertTrue(args.keychain_compat)
        self.assertTrue(args.remove_ads)
        self.assertTrue(args.hide_promotional_tabs)

    def test_missing_profile_is_analyzed_saved_and_loaded(self):
        info = self.sample_info()
        info['CFBundleShortVersionString'] = '26.15.1'
        info['CFBundleVersion'] = '2026.928.1406'
        original = self.sample_binary(reference=True)
        document = self.combined_profile(info, original)
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            return_value=(document, True),
        ):
            profile, result = main.select_profile(
                info, original, auto_login_patch=True,
            )

        self.assertTrue(result['automatic_patch'])
        self.assertTrue(result['profile_loaded'])
        self.assertTrue(result['profile_created'])
        self.assertEqual(result['mode'], 'analyzed_and_saved')
        self.assertEqual(profile.version, '26.15.1')
        self.assertEqual(profile.build, '2026.928.1406')
        self.assertEqual(profile.executable_sha256, main.digest(original))
        self.assertEqual(profile.patch_offset, 0xf8)

    def test_missing_inconclusive_profile_refuses_and_saves_nothing(self):
        info = self.sample_info()
        original = self.sample_binary()
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            side_effect=ValueError('No high-confidence login patch candidate to save.'),
        ):
            with self.assertRaisesRegex(ValueError, 'No high-confidence'):
                main.find_profile(info, original)

    def test_auto_profile_refuses_unknown_binary_hash(self):
        info = self.sample_info()
        original = self.sample_binary()
        changed = bytearray(original)
        changed[200] = 1
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            side_effect=ValueError('Combined patch profile does not exactly match this IPA.'),
        ):
            with self.assertRaisesRegex(ValueError, 'exactly match'):
                main.select_profile(
                    info, bytes(changed), auto_login_patch=True,
                )

    def test_auto_login_patch_requires_entry_only(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            with self.assertRaises(SystemExit):
                main.parse_args([
                    str(source), str(output), '--auto-login-patch',
                ])

    def test_friend_tab_initial_state_collapses_friend_case(self):
        last = max(main.FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS)
        binary = bytearray(last + 4)
        struct.pack_into('<I', binary, 0, 0xFEEDFACF)
        for offset in main.FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS:
            binary[offset:offset + 4] = main.FRIEND_TAB_DEFAULT_EXPANDED_ORIGINAL

        patched = main.patch_friend_tab_default_collapsed(bytes(binary), verify_hash=False)

        for offset in main.FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS:
            self.assertEqual(patched[offset:offset + 4], main.FRIEND_TAB_COLLAPSED)

    def test_embedded_extensions_and_watch_app_are_excluded(self):
        names = [
            'Payload/LINE.app/Info.plist',
            'Payload/LINE.app/Extensions/LineAppIntentsExtension.appex/',
            'Payload/LINE.app/Extensions/LineAppIntentsExtension.appex/Info.plist',
            'Payload/LINE.app/PlugIns/',
            'Payload/LINE.app/PlugIns/LineShareExtension.appex/Info.plist',
            'Payload/LINE.app/Watch/',
            'Payload/LINE.app/Watch/LineWatchKitApp.app/Info.plist',
        ]
        self.assertEqual(main.retained_archive_members(names), [
            'Payload/LINE.app/Info.plist',
        ])

    def test_output_info_plist_uses_default_bundle_id(self):
        source = self.sample_info()
        output = plistlib.loads(main.patched_info_plist(source))
        self.assertEqual(output['CFBundleIdentifier'], 'kinta.ma.nein')
        self.assertEqual(output['CFBundleDisplayName'], 'NEIN')
        self.assertEqual(output['CFBundleName'], 'NEIN')
        self.assertNotIn('CFBundleURLTypes', output)
        self.assertNotIn('CFBundleURLTypes~ipad', output)
        self.assertEqual(
            output['CFBundleIcons']['CFBundlePrimaryIcon']['CFBundleIconName'],
            'design_simple_banana',
        )
        self.assertEqual(
            output['CFBundleIcons~ipad']['CFBundlePrimaryIcon']['CFBundleIconName'],
            'design_simple_banana',
        )
        self.assertEqual(source['CFBundleIdentifier'], 'jp.naver.line')
        self.assertEqual(output['CFBundleShortVersionString'], '26.14.0')
        self.assertEqual(
            source['CFBundleIcons']['CFBundlePrimaryIcon']['CFBundleIconName'],
            'basic_default',
        )

    def test_icon_picker_registers_all_icons_and_original_primary(self):
        source = self.sample_info()
        output = plistlib.loads(main.patched_info_plist(
            source, enable_icon_picker=True,
        ))
        expected_names = ['basic_default', 'design_deep_blue', 'design_simple_banana']
        config = output['NEINIconPicker']
        self.assertEqual(config['AllowedIconNames'], expected_names)
        self.assertTrue(config['Enabled'])
        self.assertEqual(config['PrimaryIcon'], 'design_simple_banana')
        self.assertEqual(config['OriginalPrimaryIcon'], 'basic_default')
        for key in ('CFBundleIcons', 'CFBundleIcons~ipad'):
            icons = output[key]
            self.assertEqual(
                icons['CFBundlePrimaryIcon']['CFBundleIconName'],
                'design_simple_banana',
            )
            self.assertEqual(
                set(icons['CFBundleAlternateIcons']),
                {'basic_default', 'design_deep_blue'},
            )
            self.assertEqual(
                icons['CFBundleAlternateIcons']['basic_default']['CFBundleIconName'],
                'basic_default',
            )

    def test_entry_only_plist_does_not_enable_icon_picker(self):
        output = plistlib.loads(main.patched_info_plist(
            self.sample_info(), enable_icon_picker=False,
        ))
        self.assertNotIn('NEINIconPicker', output)
        self.assertEqual(
            set(output['CFBundleIcons']['CFBundleAlternateIcons']),
            {'design_deep_blue'},
        )

    def test_icon_list_requires_matching_iphone_and_ipad_registration(self):
        source = self.sample_info()
        source['CFBundleIcons~ipad'] = dict(source['CFBundleIcons~ipad'])
        source['CFBundleIcons~ipad']['CFBundleAlternateIcons'] = dict(
            source['CFBundleIcons~ipad']['CFBundleAlternateIcons'],
        )
        source['CFBundleIcons~ipad']['CFBundleAlternateIcons'].pop('design_deep_blue')
        with self.assertRaisesRegex(ValueError, 'lists do not match'):
            main.app_icon_names(source)

    def test_icon_preview_manifest_is_checked_against_full_allowlist(self):
        names = ['basic_default', 'design_simple_banana']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                'schemaVersion': 1,
                'icons': [
                    {'name': name, 'file': name + '.png'}
                    for name in names
                ],
            }
            (root / 'manifest.json').write_text(json.dumps(manifest))
            for name in names:
                (root / (name + '.png')).write_bytes(b'\x89PNG\r\n\x1a\nvalid')
            files = main.collect_icon_preview_assets(root, names)
            self.assertEqual(
                list(files),
                [
                    main.ICON_PREVIEW_ROOT + 'basic_default.png',
                    main.ICON_PREVIEW_ROOT + 'design_simple_banana.png',
                    main.ICON_PREVIEW_ROOT + 'manifest.json',
                ],
            )

    def test_icon_preview_manifest_rejects_missing_or_mismatched_previews(self):
        names = ['basic_default', 'design_simple_banana']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'manifest.json').write_text(json.dumps({
                'schemaVersion': 1,
                'icons': [{'name': names[0], 'file': names[0] + '.png'}],
            }))
            with self.assertRaisesRegex(ValueError, 'does not match'):
                main.collect_icon_preview_assets(root, names)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'manifest.json').write_text(json.dumps({
                'schemaVersion': 1,
                'icons': [
                    {'name': name, 'file': name + '.png'}
                    for name in names
                ],
            }))
            (root / (names[0] + '.png')).write_bytes(b'not png')
            with self.assertRaisesRegex(ValueError, 'missing icon preview'):
                main.collect_icon_preview_assets(root, names)

    def test_icon_preview_extraction_requires_main_assets_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / 'line.ipa'
            with zipfile.ZipFile(ipa, 'w') as archive:
                archive.writestr('Payload/LINE.app/Info.plist', b'plist')
            with mock.patch.object(main.sys, 'platform', 'darwin'):
                with self.assertRaisesRegex(ValueError, 'main Assets.car'):
                    main.extract_icon_previews(ipa, ['basic_default'])

    def test_output_info_plist_requires_default_icon(self):
        source = self.sample_info()
        source['CFBundleIcons']['CFBundleAlternateIcons'].pop(main.DEFAULT_ICON)
        with self.assertRaisesRegex(ValueError, 'Default app icon is unavailable'):
            main.patched_info_plist(source)

    def test_icon_option_is_not_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                main.parse_args([
                    str(source), str(output), '--icon', 'design_deep_blue',
                ])

    def test_ad_removal_options_are_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            args = main.parse_args([
                str(source), str(output), '--remove-ads',
                '--hide-promotional-tabs',
            ])
        self.assertTrue(args.remove_ads)
        self.assertTrue(args.hide_promotional_tabs)

    def test_ad_removal_option_enables_network_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            args = main.parse_args([
                str(Path(directory) / 'input.ipa'),
                str(Path(directory) / 'output.ipa'),
                '--remove-ads',
            ])
        self.assertTrue(args.remove_ads)

    def test_ad_removal_has_no_separate_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            args = main.parse_args([
                str(Path(directory) / 'input.ipa'),
                str(Path(directory) / 'output.ipa'),
                '--remove-ads',
            ])
        self.assertNotIn('aggressive_remove_ads', vars(args))

    def test_ad_domain_list_is_unique_and_buildable(self):
        domains = main.load_ad_domains()
        self.assertEqual(domains, (
            'ad.line-scdn.net',
            'admob-gmats.uc.r.appspot.com',
            'doubleclick-cn.net',
            'doubleclick.net',
            'googleadservices.com',
            'googlesyndication.com',
            'imasdk.googleapis.com',
            'taboola.com',
            'taboolanews.com',
        ))
        header = main.scan_ad_domains.render_header(domains)
        self.assertIn('NEINAdBlockedDomains', header)
        self.assertIn('@"taboola.com"', header)

    def test_primary_login_mode_is_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            args = main.parse_args([
                str(source), str(output), '--primary-login',
            ])
        self.assertTrue(args.primary_login)

    def test_friends_cold_launch_collapse_option_is_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            args = main.parse_args([
                str(Path(directory) / 'input.ipa'),
                str(Path(directory) / 'output.ipa'),
                '--collapse-friends-on-launch',
            ])
        self.assertTrue(args.collapse_friends_on_launch)

    def test_tab_diagnostics_requires_promotional_tabs(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [str(Path(directory) / 'input.ipa'),
                     str(Path(directory) / 'output.ipa')]
            self.assertFalse(main.parse_args(paths).tab_diagnostics)
            with self.assertRaises(SystemExit):
                main.parse_args(paths + ['--tab-diagnostics'])
            args = main.parse_args(paths + ['--tab-diagnostics', '--hide-promotional-tabs'])
            self.assertTrue(args.tab_diagnostics)
            with self.assertRaises(SystemExit):
                main.parse_args(paths + ['--tab-diagnostics', '--hide-promotional-tabs',
                                         '--entry-only'])

    def test_entry_only_rejects_primary_login(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            with self.assertRaises(SystemExit):
                main.parse_args([
                    str(source), str(output), '--entry-only', '--primary-login',
                ])

    def test_entry_only_rejects_ad_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.ipa'
            output = Path(directory) / 'output.ipa'
            with self.assertRaises(SystemExit):
                main.parse_args([
                    str(source), str(output), '--entry-only', '--remove-ads',
                ])


if __name__ == '__main__':
    unittest.main()
