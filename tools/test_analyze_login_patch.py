import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_patch_profile as analyzer  # noqa: E402


def encode_uleb128(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def sample_macho(reference=False):
    image_base = 0x100000000
    text_address = 0x100001000
    text_offset = 200
    branch_index = 12
    branch_address = text_address + branch_index * 4
    target_address = text_address + 14 * 4
    branch_immediate = (target_address - branch_address) // 4
    tbz = 0x36000000 | (branch_immediate << 5)
    instructions = [analyzer.NOP] * 60
    instructions[branch_index] = tbz
    if reference:
        instructions[:len(analyzer.REFERENCE_WINDOW)] = analyzer.REFERENCE_WINDOW
        instructions[branch_index] |= (14 - branch_index) << 5
    text = struct.pack('<60I', *instructions)

    data = bytearray(text_offset + len(text) + 3)
    struct.pack_into('<I', data, 0, 0xFEEDFACF)
    struct.pack_into('<I', data, 4, 0x0100000C)
    struct.pack_into('<I', data, 12, 2)
    struct.pack_into('<II', data, 16, 2, 168)

    # LC_SEGMENT_64 with one __TEXT,__text section.
    struct.pack_into('<II', data, 32, 0x19, 152)
    data[40:46] = b'__TEXT'
    struct.pack_into('<QQQQ', data, 56, image_base, 0x2000, 0, len(data))
    struct.pack_into('<IIII', data, 88, 7, 5, 1, 0)
    section = 104
    data[section:section + 6] = b'__text'
    data[section + 16:section + 22] = b'__TEXT'
    struct.pack_into('<QQI', data, section + 32, text_address, len(text), text_offset)

    # LC_FUNCTION_STARTS stores the first function at the start of __text.
    struct.pack_into('<IIII', data, 184, 0x26, 16, 440, 3)
    data[text_offset:text_offset + len(text)] = text
    data[440:443] = encode_uleb128(0x1000) + b'\0'
    return bytes(data)


class LoginPatchAnalyzerTests(unittest.TestCase):
    def test_parse_and_locate_tbz_candidate(self):
        binary = sample_macho()
        image = analyzer.parse_arm64_macho(binary)
        branch_count, candidate_count, _, candidates = analyzer.locate_login_branch(
            binary, image,
        )

        self.assertEqual(branch_count, 1)
        self.assertEqual(candidate_count, 1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].file_offset, 248)
        self.assertEqual(candidates[0].virtual_address, 0x100001030)
        self.assertEqual(candidates[0].target_address, 0x100001038)
        self.assertEqual(candidates[0].instruction, 'tbz w0, #0')
        self.assertEqual(candidates[0].function_start, 0x100001000)

    def test_recommends_unique_normalized_reference_match(self):
        analysis = analyzer.analyze_login_executable(
            sample_macho(reference=True), version='test', build='2',
        )
        self.assertEqual(analysis['recommended_patch_offset'], '0xf8')
        self.assertEqual(analysis['best_similarity'], 1.0)
        self.assertEqual(analysis['high_confidence_candidate_count'], 1)
        self.assertFalse(analysis['automatic_patch'])

    def test_creates_login_section_for_combined_profile(self):
        analysis = analyzer.analyze_login_executable(
            sample_macho(reference=True), version='26.15.1', build='test-build',
        )
        document = analyzer.profile_document(analysis)
        self.assertEqual(document['version'], '26.15.1')
        self.assertEqual(document['patch']['file_offset'], '0xf8')
        self.assertEqual(document['patch']['original_hex'], '40000036')
        self.assertNotIn('analysis', document)

    def test_refuses_inconclusive_login_profile_section(self):
        analysis = analyzer.analyze_login_executable(
            sample_macho(), version='test', build='inconclusive',
        )
        with self.assertRaisesRegex(ValueError, 'No high-confidence'):
            analyzer.profile_document(analysis)

    def test_decodes_cbz_and_conditional_branch(self):
        cbz = analyzer._decode_branch(0x34000040, 0x1000)
        self.assertEqual(cbz, ('cbz w0', 0x1008, 'zero'))
        beq = analyzer._decode_branch(0x54000040, 0x1000)
        self.assertEqual(beq, ('b.eq', 0x1008, 'eq'))

    def test_rejects_non_arm64_thin_macho(self):
        with self.assertRaisesRegex(ValueError, 'thin little-endian 64-bit Mach-O'):
            analyzer.parse_arm64_macho(b'not a Mach-O')

    def test_analyze_ipa_is_explicitly_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / 'line.ipa'
            info = {
                'CFBundleIdentifier': 'jp.naver.line',
                'CFBundleShortVersionString': 'test',
                'CFBundleVersion': '1',
            }
            with zipfile.ZipFile(ipa, 'w') as archive:
                archive.writestr(analyzer.PLIST, plistlib.dumps(info))
                archive.writestr(analyzer.EXECUTABLE, sample_macho())

            result = analyzer.analyze_login_ipa(ipa)

        self.assertFalse(result['automatic_patch'])
        self.assertEqual(result['structural_candidate_count'], 1)
        self.assertEqual(result['version'], 'test')


if __name__ == '__main__':
    unittest.main()
