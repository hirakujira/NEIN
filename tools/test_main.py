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
from test_analyze_login_patch import sample_macho  # noqa: E402


class MainToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.source = self.directory / 'input.ipa'

    def args(self, *flags, output='output.ipa'):
        return main.parse_args([str(self.source), str(self.directory / output), *flags])

    def profile(self, binary=None, **fields):
        return main.PatchProfile(**{
            'version': '26.14.0', 'build': 'test',
            'executable_sha256': main.digest(binary) if binary else '0' * 64,
            'patch_offset': 248, 'patch_va': 0x100001030,
            'original': bytes.fromhex('40000036'),
            'instruction': 'tbz w0, #0, 0x100001038',
            **fields,
        })

    def write_ipa(self, binary, info, members=()):
        with zipfile.ZipFile(self.source, 'w') as archive:
            archive.writestr(main.EXECUTABLE, binary)
            archive.writestr(main.PLIST, plistlib.dumps(info))
            for name, content in members:
                archive.writestr(name, content)

    def run_main(self, args, profile, **patches):
        with mock.patch.multiple(
                main, parse_args=mock.Mock(return_value=args),
                find_profile=mock.Mock(return_value=profile), **patches), \
                redirect_stderr(StringIO()), \
                mock.patch('sys.stdout', new_callable=StringIO):
            main.main()
        return json.loads(args.output.with_suffix('.manifest.json').read_text())

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
            'MinimumOSVersion': '18.0',
            'CFBundleURLTypes': [{
                'CFBundleURLSchemes': ['line', 'lineauth2'],
            }],
            'CFBundleURLTypes~ipad': [{
                'CFBundleURLSchemes': ['line'],
            }],
            'CFBundleIcons': icons,
            'CFBundleIcons~ipad': icons,
        }

    def build_version_binary(self, sdk=0x1A0500, platform=main.PLATFORM_IOS,
                             build_versions=1):
        text_offset = 0x400
        binary = bytearray(text_offset + 16)
        struct.pack_into(
            '<6I', binary, 0, 0xFEEDFACF, 0x0100000C, 0, 2,
            1 + build_versions, 152 + 24 * build_versions,
        )
        struct.pack_into('<II', binary, 32, 0x19, 152)
        binary[40:46] = b'__TEXT'
        struct.pack_into('<QQQQ', binary, 56, 0x100000000, 0x2000, 0, len(binary))
        struct.pack_into('<IIII', binary, 88, 7, 5, 1, 0)
        binary[104:110] = b'__text'
        binary[120:126] = b'__TEXT'
        struct.pack_into('<QQI', binary, 136, 0x100000400, 16, text_offset)
        for index in range(build_versions):
            struct.pack_into(
                '<6I', binary, 184 + 24 * index, main.LC_BUILD_VERSION, 24,
                platform, 0x120000, sdk, 0,
            )
        binary[text_offset:text_offset + 4] = bytes.fromhex('40000036')
        return bytes(binary)

    def test_entry_patch_requires_expected_instruction(self):
        profile = self.profile()
        patched = main.patched_binary(sample_macho(), profile, verify_hash=False)
        self.assertEqual(patched[profile.patch_offset:profile.patch_offset + 4], main.NOP)
        binary = bytearray(sample_macho())
        binary[248:252] = main.NOP
        with self.assertRaises(ValueError):
            main.patched_binary(bytes(binary), profile, verify_hash=False)

    def test_digest_file_streams_large_input(self):
        content = b'nein' * (1024 * 1024)
        path = self.directory / 'large.bin'
        path.write_bytes(content)
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('full read')):
            self.assertEqual(main.digest_file(path), hashlib.sha256(content).hexdigest())

    def test_entry_only_preserves_large_archive_members(self):
        original = sample_macho()
        profile = self.profile(original)
        payload = b'nein' * (1024 * 1024)
        stale_metadata = [
            'Payload/LINE.app/_CodeSignature/',
            'Payload/LINE.app/_CodeSignature/CodeResources',
            'META-INF/',
            'META-INF/com.apple.ZipMetadata.plist',
            'META-INF/com.apple.FixedZipMetadata.bin',
            'iTunesMetadata.plist',
            'Payload/LINE.app/SC_Info/',
            'Payload/LINE.app/SC_Info/Manifest.plist',
            'Payload/LINE.app/SC_Info/LINE.sinf',
            'Payload/LINE.app/Frameworks/Test.framework/SC_Info/',
            'Payload/LINE.app/Frameworks/Test.framework/SC_Info/Test.sinf',
        ]
        framework_signature = 'Payload/LINE.app/Frameworks/Test.framework/_CodeSignature/CodeResources'
        large = zipfile.ZipInfo('Payload/LINE.app/large.dat')
        large.compress_type = zipfile.ZIP_DEFLATED
        self.write_ipa(original, self.sample_info(), [
            ('Payload/LINE.app/Frameworks/', b''),
            (large, payload),
            ('Payload/LINE.app/PlugIns/removed.appex/file', b'removed'),
            *[
                (name, plistlib.dumps({'SinfReplicationPaths': [
                    'PlugIns/LineNotificationServiceExtension.appex/SC_Info/extension.sinf',
                ]}) if name.endswith('SC_Info/Manifest.plist') else
                 b'' if name.endswith('/') else b'stale metadata')
                for name in stale_metadata
            ],
            (framework_signature, b'unchanged framework signature'),
        ])
        args = self.args('--entry-only')
        manifest = self.run_main(args, profile)
        with zipfile.ZipFile(args.output) as archive:
            self.assertIn('Payload/LINE.app/Frameworks/', archive.namelist())
            self.assertEqual(archive.read('Payload/LINE.app/large.dat'), payload)
            self.assertEqual(archive.getinfo('Payload/LINE.app/large.dat').compress_type,
                             zipfile.ZIP_DEFLATED)
            self.assertNotIn('Payload/LINE.app/PlugIns/removed.appex/file',
                             archive.namelist())
            for name in stale_metadata:
                self.assertNotIn(name, archive.namelist())
            self.assertEqual(archive.read(framework_signature), b'unchanged framework signature')
            self.assertEqual(archive.read(main.EXECUTABLE),
                             main.patched_binary(original, profile))
        self.assertEqual(manifest['source_ipa_sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(manifest['output_ipa_sha256'], hashlib.sha256(args.output.read_bytes()).hexdigest())
        self.assertEqual(manifest['changed_byte_offsets'], ['0xf8', '0xf9', '0xfa', '0xfb'])
        self.assertFalse(manifest['enable_sticker_shop'])
        self.assertNotIn('sticker_shop', manifest)
        self.assertEqual(manifest['shops_skipped'],
                         'No audited sticker-shop patch for this build; '
                         'sticker and theme shop patches skipped.')
        self.assertTrue(manifest['source_signing_and_store_metadata_removed'])

    def test_entry_only_sticker_shop_and_friends_round_trip(self):
        original = bytearray(sample_macho())
        sites = []

        def site(offset, original_hex, patched_hex):
            original[offset:offset + len(original_hex) // 2] = bytes.fromhex(original_hex)
            sites.append({'file_offset': hex(offset), 'original_hex': original_hex,
                          'patched_hex': patched_hex})
            return sites[-1]

        friends = {'kind': 'friend_tab_default_collapsed', 'patches': [
            site(0x180, 'e8179f1a', '08008052'), site(0x188, 'e8179f1a', '08008052'),
        ]}
        sticker_shop = {
            **site(0x190, '10000000', '20000000'),
            'liff_route': site(0x194, '96000037', '1f2003d5'),
            'native_routes': {**site(0x198, '15030036', '2a000014'),
                              'code_cave': site(0x140, '00' * 8, 'aa' * 8)},
            'coin_entry': site(0x19c, '60008052', '00008052'),
        }
        original = bytes(original)
        profile = self.profile(original, home_friends=friends, sticker_shop=sticker_shop)
        self.write_ipa(original, self.sample_info(), [('Payload/LINE.app/untouched', b'unchanged')])
        args = self.args('--entry-only', '--collapse-friends-on-launch')
        manifest = self.run_main(args, profile)
        expected = bytearray(main.patched_binary(original, profile))
        for item in sites:
            offset = int(item['file_offset'], 16)
            patched = bytes.fromhex(item['patched_hex'])
            expected[offset:offset + len(patched)] = patched
        with zipfile.ZipFile(args.output) as archive:
            self.assertEqual(archive.read(main.EXECUTABLE), bytes(expected))
            self.assertEqual(archive.read('Payload/LINE.app/untouched'), b'unchanged')
        self.assertTrue(manifest['enable_sticker_shop'])
        self.assertFalse(manifest['enable_theme_shop'])
        self.assertEqual(manifest['shops_skipped'],
                         'No audited theme-shop patch for this build; theme shop patch skipped.')
        self.assertEqual(manifest['home_friends'], friends)
        self.assertEqual(manifest['sticker_shop']['native_routes'], sticker_shop['native_routes'])
        for offset in ('0x140', '0x180', '0x188', '0x190', '0x194', '0x198', '0x19c'):
            self.assertIn(offset, manifest['changed_byte_offsets'])

    def test_entry_only_theme_shop_replaces_the_sticker_code_cave(self):
        original = bytearray(sample_macho())

        def site(offset, original_hex, patched_hex):
            original[offset:offset + len(original_hex) // 2] = bytes.fromhex(original_hex)
            return {'file_offset': hex(offset), 'original_hex': original_hex,
                    'patched_hex': patched_hex}

        sticker_cave = site(0x140, '00' * 8, 'aa' * 8)
        sticker_shop = {
            **site(0x190, '10000000', '20000000'),
            'liff_route': site(0x194, '96000037', '1f2003d5'),
            'native_routes': {**site(0x198, '15030036', '2a000014'),
                              'code_cave': sticker_cave},
            'coin_entry': site(0x19c, '60008052', '00008052'),
        }
        theme_shop = {
            **site(0x1a0, '10000000', '20000000'),
            'liff_route': site(0x1a4, '77000037', '1f2003d5'),
            'code_cave': site(0x140, '00' * 12, 'bb' * 12),
        }
        original = bytes(original)
        profile = self.profile(original, sticker_shop=sticker_shop, theme_shop=theme_shop)
        self.write_ipa(original, self.sample_info())
        args = self.args('--entry-only')
        manifest = self.run_main(args, profile)
        expected = bytearray(main.patched_binary(original, profile))
        for item in (sticker_shop, sticker_shop['liff_route'],
                     sticker_shop['native_routes'], theme_shop['code_cave'],
                     sticker_shop['coin_entry'], theme_shop, theme_shop['liff_route']):
            offset = int(item['file_offset'], 16)
            patched = bytes.fromhex(item['patched_hex'])
            expected[offset:offset + len(patched)] = patched
        with zipfile.ZipFile(args.output) as archive:
            self.assertEqual(archive.read(main.EXECUTABLE), bytes(expected))
        self.assertTrue(manifest['enable_theme_shop'])
        self.assertTrue(manifest['enable_sticker_shop'])
        self.assertNotIn('shops_skipped', manifest)
        self.assertEqual(manifest['theme_shop']['liff_route'], theme_shop['liff_route'])
        self.assertEqual(manifest['theme_shop']['code_cave'], theme_shop['code_cave'])
        for offset in ('0x140', '0x14b', '0x1a0', '0x1a4'):
            self.assertIn(offset, manifest['changed_byte_offsets'])

    def test_unverified_executable_skips_both_shops(self):
        original = sample_macho()
        self.write_ipa(original, self.sample_info())
        site = {'file_offset': '0x190', 'original_hex': '00000000', 'patched_hex': '20000000'}
        profile = self.profile(
            executable_sha256='0' * 64,
            sticker_shop={**site, 'native_routes': {'code_cave': site},
                          'liff_route': site, 'coin_entry': site},
            theme_shop={**site, 'liff_route': site, 'code_cave': site},
        )
        args = self.args('--entry-only', '--allow-unverified')
        manifest = self.run_main(args, profile)
        with zipfile.ZipFile(args.output) as archive:
            self.assertEqual(archive.read(main.EXECUTABLE),
                             main.patched_binary(original, profile, verify_hash=False))
        self.assertFalse(manifest['enable_sticker_shop'])
        self.assertFalse(manifest['enable_theme_shop'])
        self.assertNotIn('sticker_shop', manifest)
        self.assertNotIn('theme_shop', manifest)
        self.assertEqual(manifest['shops_skipped'],
                         'Executable is not the audited one for this profile; '
                         'sticker and theme shop patches skipped.')

    def test_streamed_archive_copy_rejects_corrupt_member(self):
        with zipfile.ZipFile(self.source, 'w') as archive:
            archive.writestr('Payload/LINE.app/payload', b'corrupt me')
        damaged = bytearray(self.source.read_bytes())
        damaged[damaged.index(b'corrupt me')] ^= 1
        self.source.write_bytes(damaged)
        with zipfile.ZipFile(self.source) as archive, \
                zipfile.ZipFile(self.directory / 'output.ipa', 'w') as target:
            with self.assertRaises(zipfile.BadZipFile):
                main.copy_archive_member(
                    archive, target, archive.getinfo('Payload/LINE.app/payload'),
                )

    def test_profile_loader_builds_profile_and_honors_allow_unverified(self):
        info = self.sample_info()
        original = sample_macho()
        document = {
            'version': info['CFBundleShortVersionString'],
            'build': info['CFBundleVersion'],
            'executable_sha256': main.digest(original),
            'login_patch': {
                'file_offset': '0xf8',
                'virtual_address': '0x100001030',
                'original_hex': '40000036',
                'instruction': 'tbz w0, #0, 0x100001038',
            },
            'keychain': {'profile_type': 'line_keychain'},
        }
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            return_value=(document, False),
        ) as load:
            profile = main.find_profile(info, original, allow_unverified=True)
        load.assert_called_once_with(info, original, allow_unverified=True)
        self.assertEqual(profile, self.profile(
            original, build='2026.828.1845',
            keychain_profile={'profile_type': 'line_keychain'},
        ))

    def test_missing_inconclusive_profile_refuses_and_saves_nothing(self):
        with mock.patch.object(
            main.analyze_patch_profile, 'load_or_create_profile',
            side_effect=ValueError('No high-confidence login patch candidate to save.'),
        ):
            with self.assertRaisesRegex(ValueError, 'No high-confidence'):
                main.find_profile(self.sample_info(), sample_macho())

    def test_patch_sites_require_original_bytes_and_report_ranges(self):
        binary = bytearray(0x120)
        sites = []
        for offset in (0x100, 0x110):
            binary[offset:offset + 4] = bytes.fromhex('e8179f1a')
            sites.append({'file_offset': hex(offset), 'original_hex': 'e8179f1a',
                          'patched_hex': '08008052'})
        patched, ranges = main.apply_patch_sites(bytes(binary), sites)
        self.assertEqual(ranges, [(0x100, 0x104), (0x110, 0x114)])
        for offset in (0x100, 0x110):
            self.assertEqual(patched[offset:offset + 4], bytes.fromhex('08008052'))
        for name, data, site in (
            ('already patched', patched, sites[0]),
            ('length change', bytes(binary), {**sites[0], 'patched_hex': '08'}),
        ):
            with self.subTest(name), self.assertRaisesRegex(ValueError, 'Expected original'):
                main.apply_patch_sites(data, [site])

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

    def test_stale_signing_and_store_metadata_are_excluded(self):
        retained = [
            main.PLIST,
            main.EXECUTABLE,
            'iTunesArtwork',
            'Payload/LINE.app/Frameworks/Test.framework/_CodeSignature/CodeResources',
            'Payload/LINE.app/Resources/META-INF/license',
            'Payload/LINE.app/Metadata.appintents/version.json',
        ]
        removed = [
            'Payload/LINE.app/_CodeSignature/',
            'Payload/LINE.app/_CodeSignature/CodeResources',
            'META-INF/',
            'META-INF/com.apple.ZipMetadata.plist',
            'META-INF/com.apple.FixedZipMetadata.bin',
            'iTunesMetadata.plist',
            'Payload/LINE.app/SC_Info/',
            'Payload/LINE.app/SC_Info/Manifest.plist',
            'Payload/LINE.app/SC_Info/LINE.sinf',
            'Payload/LINE.app/Frameworks/Test.framework/SC_Info/',
            'Payload/LINE.app/Frameworks/Test.framework/SC_Info/Test.sinf',
        ]
        self.assertEqual(main.retained_archive_members(retained + removed), retained)

    def test_notification_background_settings_are_preserved(self):
        source = self.sample_info()
        source['UIBackgroundModes'] = ['audio', 'remote-notification', 'voip']
        source['NSSupportsLiveActivities'] = True
        output = plistlib.loads(main.patched_info_plist(source))
        self.assertEqual(output['UIBackgroundModes'], source['UIBackgroundModes'])
        self.assertTrue(output['NSSupportsLiveActivities'])

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
        manifest = {
            'schemaVersion': 1,
            'icons': [
                {'name': name, 'file': name + '.png'}
                for name in names
            ],
        }
        (self.directory / 'manifest.json').write_text(json.dumps(manifest))
        for name in names:
            (self.directory / (name + '.png')).write_bytes(b'\x89PNG\r\n\x1a\nvalid')
        files = main.collect_icon_preview_assets(self.directory, names)
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
        (self.directory / 'manifest.json').write_text(json.dumps({
            'schemaVersion': 1,
            'icons': [{'name': names[0], 'file': names[0] + '.png'}],
        }))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            main.collect_icon_preview_assets(self.directory, names)

        (self.directory / 'manifest.json').write_text(json.dumps({
            'schemaVersion': 1,
            'icons': [
                {'name': name, 'file': name + '.png'}
                for name in names
            ],
        }))
        (self.directory / (names[0] + '.png')).write_bytes(b'not png')
        with self.assertRaisesRegex(ValueError, 'missing icon preview'):
            main.collect_icon_preview_assets(self.directory, names)

    def test_icon_preview_extraction_requires_main_assets_catalog(self):
        with zipfile.ZipFile(self.source, 'w') as archive:
            archive.writestr('Payload/LINE.app/Info.plist', b'plist')
        with mock.patch.object(main.sys, 'platform', 'darwin'):
            with self.assertRaisesRegex(ValueError, 'main Assets.car'):
                main.extract_icon_previews(self.source, ['basic_default'])

    def test_output_info_plist_requires_default_icon(self):
        source = self.sample_info()
        source['CFBundleIcons']['CFBundleAlternateIcons'].pop(main.DEFAULT_ICON)
        with self.assertRaisesRegex(ValueError, 'Default app icon is unavailable'):
            main.patched_info_plist(source)

    def test_ad_domain_list_is_unique_and_buildable(self):
        self.assertEqual(main.load_ad_domains(), (
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

    def test_options_are_opt_in(self):
        for flag in ('--remove-ads', '--hide-promotional-tabs', '--primary-login',
                     '--collapse-friends-on-launch', '--iphone-duo'):
            attribute = flag[2:].replace('-', '_')
            with self.subTest(flag=flag):
                self.assertFalse(getattr(self.args(), attribute))
                self.assertTrue(getattr(self.args(flag), attribute))
        args = self.args('--keychain-compat')
        self.assertTrue(args.keychain_compat)
        self.assertTrue(args.diagnostics)

    def test_rejects_incompatible_options(self):
        for flags in (
            ('--entry-only', '--primary-login'),
            ('--entry-only', '--remove-ads'),
            ('--entry-only', '--keychain-compat'),
            ('--entry-only', '--iphone-duo'),
            ('--entry-only', '--skin-theme',
             'dffa6443-27c7-4361-a481-39750b03b5c5=3cc08ba6-5d04-4c52-ab76-651231ead8ef'),
        ):
            with self.subTest(flags=flags), redirect_stderr(StringIO()), \
                    self.assertRaises(SystemExit):
                self.args(*flags)

    def test_iphone_duo_sdk_patch_changes_only_sdk_field(self):
        original = self.build_version_binary()
        patched, result = main.patch_build_version_sdk(original)
        self.assertEqual(
            [i for i, (a, b) in enumerate(zip(original, patched)) if a != b],
            [0xc9, 0xca],
        )
        self.assertEqual(len(patched), len(original))
        self.assertEqual(struct.unpack_from('<I', patched, 0xc8)[0], 0x1B0100)
        self.assertEqual(result, {
            'sdk_field_offset': '0xc8',
            'minimum_os': '18.0.0',
            'original_sdk': '26.5.0',
            'patched_sdk': '27.1.0',
        })

    def test_iphone_duo_sdk_patch_keeps_newer_sdk(self):
        original = self.build_version_binary(sdk=0x1B0200)
        patched, result = main.patch_build_version_sdk(original)
        self.assertEqual(patched, original)
        self.assertEqual(result['patched_sdk'], '27.2.0')

    def test_iphone_duo_sdk_patch_rejects_unexpected_build_version(self):
        fat = bytearray(self.build_version_binary())
        struct.pack_into('<I', fat, 0, 0xCAFEBABE)
        truncated = bytearray(self.build_version_binary())
        struct.pack_into('<I', truncated, 188, 16)
        for name, binary, message in (
            ('fat', bytes(fat), 'thin 64-bit'),
            ('missing', self.build_version_binary(build_versions=0), 'exactly one'),
            ('duplicate', self.build_version_binary(build_versions=2), 'exactly one'),
            ('mac catalyst', self.build_version_binary(platform=6), 'not iOS'),
            ('truncated', bytes(truncated), 'Truncated|layout|mismatch'),
        ):
            with self.subTest(name), self.assertRaisesRegex(ValueError, message):
                main.patch_build_version_sdk(binary)

    def test_iphone_duo_plist_marks_ios_27_1_sdk(self):
        source = {
            **self.sample_info(),
            'DTSDKName': 'iphoneos26.5', 'DTPlatformVersion': '26.5',
            'DTXcode': '2650',
        }
        default = plistlib.loads(main.patched_info_plist(source))
        self.assertEqual(default['DTSDKName'], 'iphoneos26.5')
        self.assertEqual(default['DTPlatformVersion'], '26.5')
        duo = plistlib.loads(main.patched_info_plist(source, iphone_duo=True))
        self.assertEqual(duo['DTSDKName'], 'iphoneos27.1')
        self.assertEqual(duo['DTPlatformVersion'], '27.1')
        self.assertEqual(duo['DTXcode'], '2650')
        self.assertEqual(duo['MinimumOSVersion'], '18.0')
        self.assertEqual(source['DTSDKName'], 'iphoneos26.5')
        newer = {**source, 'DTSDKName': 'iphoneos27.2', 'DTPlatformVersion': '27.2'}
        self.assertEqual(main.iphone_duo_info_plist_changes(newer), {})

    def test_iphone_duo_build_patches_sdk_and_records_manifest(self):
        info = {
            **self.sample_info(),
            'DTSDKName': 'iphoneos26.5', 'DTPlatformVersion': '26.5',
        }
        original = self.build_version_binary()
        profile = self.profile(original, patch_offset=0x400, patch_va=0x100000400,
                               instruction='tbz w0, #0, 0x100000408')
        self.write_ipa(original, info)
        for iphone_duo in (False, True):
            with self.subTest(iphone_duo=iphone_duo):
                args = self.args(*(['--iphone-duo'] if iphone_duo else []),
                                 output=f'output-{iphone_duo}.ipa')
                build = mock.Mock(return_value=(None, b'dylib'))
                manifest = self.run_main(
                    args, profile, build_compat_dylib=build,
                    extract_icon_previews=mock.Mock(return_value={}),
                )
                self.assertEqual(build.call_args.args[0].iphone_duo, iphone_duo)
                expected, _ = main.add_dylib(main.patched_binary(original, profile))
                if iphone_duo:
                    expected, _ = main.patch_build_version_sdk(expected)
                with zipfile.ZipFile(args.output) as archive:
                    executable = archive.read(main.EXECUTABLE)
                    output_info = plistlib.loads(archive.read(main.PLIST))
                self.assertEqual(executable, expected)
                self.assertEqual(
                    struct.unpack_from('<I', executable, 0xc8)[0],
                    0x1B0100 if iphone_duo else 0x1A0500,
                )
                self.assertEqual(struct.unpack_from('<I', executable, 0xc4)[0], 0x120000)
                self.assertEqual(output_info['DTSDKName'],
                                 'iphoneos27.1' if iphone_duo else 'iphoneos26.5')
                if not iphone_duo:
                    self.assertIsNone(manifest['iphone_duo'])
                    continue
                section = manifest['iphone_duo']
                self.assertEqual(section['build_version'], {
                    'sdk_field_offset': '0xc8', 'minimum_os': '18.0.0',
                    'original_sdk': '26.5.0', 'patched_sdk': '27.1.0',
                })
                self.assertEqual(section['info_plist'], {
                    'DTSDKName': {'original': 'iphoneos26.5', 'patched': 'iphoneos27.1'},
                    'DTPlatformVersion': {'original': '26.5', 'patched': '27.1'},
                })
                self.assertEqual(section['split_layout']['device_model'], 'iPhone19,4')
                self.assertEqual(section['split_layout']['minimum_window_short_side_points'], 600)

    def test_iphone_duo_split_guard_matches_hook(self):
        header = (main.ROOT / 'hooks' / 'NEINDuoSplitLayout.h').read_text(encoding='utf-8')
        self.assertIn('NEINDuoModelIdentifier = @"%s";' % main.IPHONE_DUO_MODEL, header)
        self.assertIn(
            'NEINDuoSplitMinimumCanvasSide = %d;' % main.IPHONE_DUO_SPLIT_MINIMUM_SIDE, header,
        )


if __name__ == '__main__':
    unittest.main()
