import struct
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_patch_profile as analyzer  # noqa: E402
import main  # noqa: E402


class StickerShopTests(unittest.TestCase):
    def native(self):
        native = {
            'kind': 'native_sticker_routes',
            'guard_address': '0x1000004e0', 'deny_address': '0x100000540',
            'kind_resolver_address': '0x100000780',
            'command_resolver_address': '0x1000007a0',
            'file_offset': '0x4e0', 'original_hex': '15030036',
            'patched_hex': struct.pack('<I', analyzer._branch26(0x1000004E0, 0x100000500)).hex(),
            'code_cave': {'address': '0x100000500', 'file_offset': '0x500'},
        }
        code = analyzer.sticker_shop_native_code(native)
        native['code_cave'].update(original_hex=bytes(len(code)).hex(), patched_hex=code.hex())
        return native

    def sample(self, return_word=0xA9447BFD, delta=0):
        base = 0x100000000
        binary = bytearray(0xD00)
        # ObjC thunk calls a type accessor, then the shared Swift gate.
        struct.pack_into('<4I', binary, 0x80, 0x94000004, 0x9400003F,
                         0x12000000, 0xD65F03C0)
        struct.pack_into('<8I', binary, 0xB0,
                         0xA9BF7BFD, 0x910003FD, 0x90000000, 0x91000000,
                         0x94000000, 0xD2800001, 0xA8C17BFD, 0xD65F03C0)
        words = [
            0xD10143FF, 0xA9015FF8, 0xA90257F6, 0xA9034FF4,
            0xA9047BFD, 0x910103FD, 0xAA0003E8, 0xF100D81F,
            0x54001E48, 0x52800020, 0x90000009, 0x91100129,
            0x1000000A, 0xB8A8792B, 0x8B0B014A, 0xD61F0140,
            0x94000000, 0xAA0003F4, 0x94000000, 0x12000000,
            return_word,
        ]
        struct.pack_into('<21I', binary, 0x180, *words)
        struct.pack_into('<55i', binary, 0x400, *([16] * 55))
        struct.pack_into('<I', binary, 0x4E0, 0x36000315)
        branch = 0x6C8

        def call(offset, target):
            struct.pack_into('<I', binary, offset, 0x94000000 | (((target - offset) // 4) & 0x3FFFFFF))

        struct.pack_into('<11I', binary, branch - 132 - delta,
                         0x528E0C37, 0x72A00E17, 0xD2FC6018, 0xA9026017,
                         0, 0xA9400008, 0xA9030288, 0x94000000,
                         0xAA1403E0 if not delta else 0x94000000,
                         0, 0xAA0003F6)
        call(branch - 116 - delta, 0x780)
        call(branch - 96 - delta, 0x7A0)
        struct.pack_into('<2I', binary, branch - 52 - delta,
                         0x90000008, 0x91000108 | (0xA30 << 10))
        struct.pack_into('<6I', binary, branch - 44 - delta,
                         0xA9026017, 0xD1008108, 0xB2410108,
                         0xD2800269, 0xF2FA0009, 0xA9032009)
        call(branch - 20, 0x7A0)
        binary[branch:branch + 16] = bytes.fromhex('9600003777000037160080520b000014')
        struct.pack_into('<4I', binary, branch + 84,
                         0x528D0E68, 0x72AE0DE8, 0xD2FC8009, 0xA9022408)
        call(branch + 100 + delta, 0x7A0)
        struct.pack_into('<2I', binary, branch + 120 + delta, 0x2A160268, 0x12000100)
        struct.pack_into('<3I', binary, 0x780, 0x90000000, 0x91240000, 0xD65F03C0)
        struct.pack_into('<QQ', binary, 0x900, 0xD000000000000013, 0x9E0)
        binary[0xA00:0xA14] = b'1359301715-JKd7Y7j1\0'
        binary[0xA30:0xA44] = b'1359301715-lw9jxjqV\0'
        struct.pack_into('<19I', binary, 0xC00,
                         0xB24403BD, 0xD10083FF, 0xA9017BFD, 0xF90007F6, 0x910043FD,
                         0xF9400AC0, 0, 0xD2800000, 0, 0xAA0003F4, 0x52800060,
                         0, 0xF94006C1, 0x12000000, 0xD2800014, 0xA9417BFD,
                         0x9243FBBD, 0x910083FF, 0xD61F0020)
        call(0xC18, 0x100)
        call(0xC20, 0xB0)
        call(0xC2C, 0x180)
        binary = bytes(binary)
        image = analyzer.Image(
            binary, base, base + 0x80, 0x80, len(binary) - 0x80,
            (base + 0x80, base + 0x90, base + 0xB0, base + 0xD0, base + 0x180, base + 0x400,
             base + 0x600, base + 0x768, base + 0x780, base + 0x78C,
             base + 0xC00, base + 0xC4C),
            b'\0' * 16, (), ((base, len(binary), 0, len(binary)),),
            (0, 0, 0, 0), (0, 0),
        )
        methods = [{
            'class': 'UniversalFeatureController',
            'is_class_method': True,
            'selector': 'canUseFeature:',
            'implementation': base + 0x80,
        }]
        return binary, image, methods

    def analyze(self, binary, image, methods):
        image = replace(image, data=binary)
        with mock.patch.object(analyzer, 'parse_image', return_value=image), \
                mock.patch.object(analyzer, '_objc_methods', return_value=methods) as lookup, \
                mock.patch.object(analyzer, '_analyze_native_sticker_routes', return_value=self.native()):
            result = analyzer.analyze_sticker_shop_executable(binary)
            lookup.assert_called_once_with(image, 'UniversalFeatureController')
            return result

    def test_patch_only_changes_feature_zero_and_sticker_route(self):
        for return_word, delta in ((0xA9447BFD, 0), (0x140000C8, 4)):
            with self.subTest(return_word=hex(return_word), delta=delta):
                binary, image, methods = self.sample(return_word, delta)
                profile = self.analyze(binary, image, methods)
                self.assertEqual(profile['gate_address'], '0x100000180')
                self.assertEqual(profile['file_offset'], '0x400')
                self.assertEqual(profile['feature'], 0)
                self.assertEqual(profile['liff_route']['file_offset'], '0x6c8')
                self.assertEqual(profile['liff_route']['liff_id'], '1359301715-JKd7Y7j1')
                patched = main.patch_sticker_shop(binary, profile)
                self.assertEqual(patched[:0x400], binary[:0x400])
                self.assertEqual(patched[0x404:0x4E0], binary[0x404:0x4E0])
                self.assertEqual(patched[0x4E4:0x500], binary[0x4E4:0x500])
                self.assertEqual(patched[0x538:0x6C8], binary[0x538:0x6C8])
                self.assertEqual(patched[0x6CC:0xC28], binary[0x6CC:0xC28])
                self.assertEqual(patched[0xC2C:], binary[0xC2C:])
                self.assertEqual(struct.unpack_from('<i', patched, 0x400)[0], 32)
                self.assertEqual(patched[0x4E0:0x4E4].hex(), profile['native_routes']['patched_hex'])
                self.assertEqual(patched[0x500:0x538].hex(), profile['native_routes']['code_cave']['patched_hex'])
                self.assertEqual(patched[0x6C8:0x6CC], main.NOP)
                self.assertEqual(patched[0xC28:0xC2C].hex(), '00008052')
                self.assertEqual(profile['coin_entry']['original_feature'], 3)
                self.assertEqual(profile['coin_entry']['enabled_feature'], 0)
                with self.assertRaisesRegex(ValueError, 'dispatch entry'):
                    main.patch_sticker_shop(patched, profile)

    def test_changed_coin_callback_or_targets_are_rejected(self):
        binary, image, methods = self.sample()
        for index in range(19):
            altered = bytearray(binary)
            struct.pack_into('<I', altered, 0xC00 + index * 4, analyzer.NOP)
            with self.subTest(index=index):
                self.assertIsNone(self.analyze(bytes(altered), image, methods))
        for index in range(8):
            altered = bytearray(binary)
            struct.pack_into('<I', altered, 0xB0 + index * 4, analyzer.NOP)
            with self.subTest(metadata_index=index):
                self.assertIsNone(self.analyze(bytes(altered), image, methods))

    def test_ambiguous_coin_callback_is_rejected(self):
        binary, image, methods = self.sample()
        altered = bytearray(binary) + bytearray(0x100)
        altered[0xD00:0xD4C] = binary[0xC00:0xC4C]
        for offset, target in ((0xD18, 0x100), (0xD20, 0xB0), (0xD2C, 0x180)):
            struct.pack_into('<I', altered, offset, analyzer._branch26(offset, target, link=True))
        image = replace(image, text_size=len(altered) - 0x80,
                        function_starts=image.function_starts + (image.image_base + 0xD00, image.image_base + 0xD4C),
                        segments=((image.image_base, len(altered), 0, len(altered)),))
        self.assertIsNone(self.analyze(bytes(altered), image, methods))

    def test_liff_matcher_rejects_changed_ids_guards_or_calls(self):
        binary, image, methods = self.sample()
        offsets = (
            0x6C8, 0x6CC, 0x6D0, 0x6D4, 0xA00, 0xA30, 0x900, 0x908,
            0x780, 0x784, 0x788, 0x6C8 - 116, 0x6C8 - 132,
            0x6C8 - 96, 0x6C8 - 20, 0x6C8 + 100, 0x6C8 + 84, 0x6C8 + 120,
        )
        for offset in offsets:
            altered = bytearray(binary)
            struct.pack_into('<I', altered, offset, analyzer.NOP)
            with self.subTest(offset=hex(offset)):
                self.assertIsNone(self.analyze(bytes(altered), image, methods))
        altered = bytearray(binary)
        altered[0x500:0x510] = binary[0x6C8:0x6D8]
        self.assertIsNone(self.analyze(bytes(altered), image, methods))

    def test_profile_cannot_redirect_liff_patch_to_theme(self):
        binary, image, methods = self.sample()
        profile = self.analyze(binary, image, methods)
        route = {**profile['liff_route'], 'file_offset': '0x6cc'}
        with mock.patch.object(analyzer, 'parse_image', return_value=image), \
                mock.patch.object(analyzer, '_objc_methods', return_value=methods), \
                mock.patch.object(analyzer, '_analyze_native_sticker_routes', return_value=self.native()), \
                self.assertRaisesRegex(ValueError, 'dispatch mismatch'):
            analyzer._validate_sticker_shop_section(
                {'sticker_shop': {**profile, 'liff_route': route}}, binary,
            )

    def test_missing_ambiguous_or_instance_method_is_rejected(self):
        binary, image, methods = self.sample()
        for candidates in ([], methods * 2, [{**methods[0], 'is_class_method': False}]):
            with self.subTest(candidates=candidates):
                self.assertIsNone(self.analyze(binary, image, candidates))

    def test_modified_switch_or_account_predicate_is_rejected(self):
        binary, image, methods = self.sample()
        for index in range(6, 21):
            altered = bytearray(binary)
            struct.pack_into('<I', altered, 0x180 + index * 4, analyzer.NOP)
            with self.subTest(index=index):
                self.assertIsNone(self.analyze(bytes(altered), image, methods))
        altered = bytearray(binary)
        struct.pack_into('<I', altered, 0x80, analyzer.NOP)
        self.assertIsNone(self.analyze(bytes(altered), image, methods))

    def test_invalid_table_or_already_patched_entry_is_rejected(self):
        binary, image, methods = self.sample()
        for table in (0x181, 0x180, 0x5F0):
            altered = bytearray(binary)
            struct.pack_into('<I', altered, 0x180 + 44, 0x91000129 | (table << 10))
            with self.subTest(table=hex(table)):
                self.assertIsNone(self.analyze(bytes(altered), image, methods))
        altered = bytearray(binary)
        struct.pack_into('<I', altered, 0x400, 32)
        self.assertIsNone(self.analyze(bytes(altered), image, methods))

    def test_profile_cannot_redirect_patch_to_another_feature(self):
        binary, image, methods = self.sample()
        profile = self.analyze(binary, image, methods)
        with mock.patch.object(analyzer, 'parse_image', return_value=image), \
                mock.patch.object(analyzer, '_objc_methods', return_value=methods), \
                mock.patch.object(analyzer, '_analyze_native_sticker_routes', return_value=self.native()):
            analyzer._validate_sticker_shop_section({}, binary)
            analyzer._validate_sticker_shop_section({'sticker_shop': profile}, binary)
            for key, value in (('file_offset', '0x404'), ('feature', 1),
                               ('patched_hex', '30000000'), ('selector', 'isSecondary'),
                               ('coin_entry', {**profile['coin_entry'], 'file_offset': '0xc2c'})):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'dispatch mismatch'):
                    analyzer._validate_sticker_shop_section(
                        {'sticker_shop': {**profile, key: value}}, binary,
                    )
            with self.assertRaises(ValueError):
                analyzer._validate_sticker_shop_section({'sticker_shop': []}, binary)

    def test_patch_rejects_missing_malformed_and_out_of_bounds_sites(self):
        binary, image, methods = self.sample()
        profile = self.analyze(binary, image, methods)
        invalid = [
            None, {}, {**profile, 'file_offset': '-0x4'},
            {**profile, 'file_offset': '0x401'},
            {**profile, 'file_offset': '0x600'},
            {**profile, 'file_offset': None},
            {**profile, 'original_hex': '10'},
            {**profile, 'patched_hex': '2000000000'},
            {**profile, 'patched_hex': 'not hex'},
            {**profile, 'liff_route': None},
            {**profile, 'liff_route': {}},
            {**profile, 'liff_route': {**profile['liff_route'], 'file_offset': '0x6cc'}},
            {**profile, 'liff_route': {**profile['liff_route'], 'patched_hex': '00008052'}},
            {**profile, 'coin_entry': None},
            {**profile, 'coin_entry': {}},
            {**profile, 'coin_entry': {**profile['coin_entry'], 'patched_hex': '20008052'}},
            {**profile, 'native_routes': None},
            {**profile, 'native_routes': {}},
            {**profile, 'native_routes': {**self.native(), 'deny_address': '0x100000544'}},
            {**profile, 'native_routes': {**self.native(), 'code_cave': {
                **self.native()['code_cave'], 'patched_hex': '00' * 56,
            }}},
            {**profile, 'native_routes': {**self.native(), 'code_cave': {
                **self.native()['code_cave'], 'file_offset': '0x4e0',
            }}},
        ]
        for site in invalid:
            with self.subTest(site=site), self.assertRaises(ValueError):
                main.patch_sticker_shop(binary, site)


class NativeStickerRouteTests(unittest.TestCase):
    def sample(self):
        base = 0x100000000
        binary = bytearray(0x3000)
        struct.pack_into('<II', binary, 16, 1, 72)
        struct.pack_into('<II', binary, 32, 0x19, 72)
        binary[40:46] = b'__TEXT'
        struct.pack_into('<QQQQ', binary, 56, base, len(binary), 0, len(binary))
        struct.pack_into('<II', binary, 88, 7, 5)

        def call(offset, target):
            struct.pack_into('<I', binary, offset, analyzer._branch26(offset, target, link=True))

        site = 0x12F0
        struct.pack_into('<16I', binary, site,
                         0, 0x360003A0, 0, 0, 0x9102C2C1, 0,
                         0xA9405295, 0, 0xD63F02A0, 0xAA0003F5, 0,
                         0x36000315, 0xF94072D4, 0xAA1303E0, 0, 0x36000420)
        call(site, 0x1100)
        call(site + 56, 0x1500)
        struct.pack_into('<7I', binary, 0x1538,
                         0xAA1303E0, 0, 0x12001C16, 0xAA1303E0,
                         0, 0x35000476, 0x12001C08)
        call(0x153C, 0x1600)
        call(0x1548, 0x1700)
        for offset in (0x1610, 0x1710):
            call(offset, 0x1800)
        call(0x1630, 0x1900)
        call(0x1734, 0x1940)
        struct.pack_into('<2I', binary, 0x1634, 0x12001C00, 0x7100101F)
        struct.pack_into('<I', binary, 0x1648, 0x52800000)
        struct.pack_into('<2I', binary, 0x1738, 0x12001C00, 0x7100281F)
        struct.pack_into('<I', binary, 0x174C, 0x52800120)
        string_offset = 0x2500
        for resolver, table, values in (
            (0x1900, 0x2000, ['sticker', 'emoji', 'theme', 'accountRegist']),
            (0x1940, 0x2200, ['new', 'hot', 'event', 'category', 'author', 'detail',
                             'premium', 'download', 'preview', 'invalid']),
        ):
            struct.pack_into('<2I', binary, resolver + 20,
                             0xB0000000, 0x91000000 | ((table & 4095) << 10))
            struct.pack_into('<Q', binary, table + 16, len(values))
            for index, value in enumerate(values):
                struct.pack_into('<QQQ', binary, table + 32 + index * 24,
                                 string_offset, len(value), 2)
                encoded = value.encode() + b'\0'
                binary[string_offset:string_offset + len(encoded)] = encoded
                string_offset += len(encoded)
        binary = bytes(binary)
        image = analyzer.Image(
            binary, base, base + 0x1000, 0x1000, 0x1000,
            (base + 0x1100, base + 0x1264, base + 0x1500, base + 0x1600,
             base + 0x1700, base + 0x1800, base + 0x1900, base + 0x1940),
            b'\0' * 16, (), ((base, len(binary), 0, len(binary)),),
            (0, 0, 0, 0), (0, 0),
        )
        return binary, image, {'matcher_address': hex(base + 0x1100)}

    def test_native_guard_uses_original_kind_and_command_resolvers(self):
        binary, image, route = self.sample()
        result = analyzer._analyze_native_sticker_routes(binary, image, route)
        self.assertEqual(result['file_offset'], '0x131c')
        self.assertEqual(result['kind_resolver_address'], '0x100001600')
        self.assertEqual(result['command_resolver_address'], '0x100001700')
        self.assertEqual(result['code_cave']['file_offset'], '0xf00')
        code = bytes.fromhex(result['code_cave']['patched_hex'])
        self.assertEqual(len(code), 56)
        self.assertEqual(struct.unpack_from('<I', code)[0], 0x36000055)
        self.assertEqual(struct.unpack_from('<2I', code, 32), (0x7100241F, 0x54000062))
        self.assertEqual(binary, image.data)

    def test_changed_guard_types_commands_or_executable_padding_is_rejected(self):
        binary, image, route = self.sample()
        for offset in (0x131C, 0x1320, 0x1324, 0x1538, 0x1638, 0x1648,
                       0x173C, 0x174C, 0x2500, 0x2000 + 16, 0xF00, 92):
            altered = bytearray(binary)
            struct.pack_into('<I', altered, offset, analyzer.NOP)
            with self.subTest(offset=hex(offset)):
                self.assertIsNone(analyzer._analyze_native_sticker_routes(
                    bytes(altered), replace(image, data=bytes(altered)), route,
                ))

    def test_branch_generation_rejects_unaligned_and_out_of_range_targets(self):
        for target in (1, -(1 << 27) - 4, 1 << 27):
            with self.subTest(target=target), self.assertRaises(ValueError):
                analyzer._branch26(0, target)


if __name__ == '__main__':
    unittest.main()
