import struct
import unittest

import mac_main


class MacMainTests(unittest.TestCase):
    def make_slice(self, command_count=1, command_size=152, section_offset=512):
        data = bytearray(1024)
        struct.pack_into('<I', data, 0, 0xFEEDFACF)
        struct.pack_into('<II', data, 16, command_count, command_size)
        # LC_SEGMENT_64 with one section and enough zero-filled header slack.
        struct.pack_into('<II', data, 32, 0x19, 72 + 80)
        struct.pack_into('<I', data, 32 + 64, 1)
        struct.pack_into('<I', data, 32 + 72 + 48, section_offset)
        return bytes(data)

    def test_injects_thin_slice_without_changing_size(self):
        source = self.make_slice()
        patched = mac_main.add_dylib_to_slice(source)
        self.assertEqual(len(source), len(patched))
        self.assertEqual(struct.unpack_from('<I', patched, 16)[0], 2)
        self.assertIn(mac_main.HOOK_LOAD_PATH.encode(), patched)

    def test_injects_each_universal_slice(self):
        first = self.make_slice()
        second = self.make_slice()
        header_size = 8 + 2 * 20
        first_offset = header_size
        second_offset = first_offset + len(first)
        header = struct.pack('>II', 0xCAFEBABE, 2)
        header += struct.pack('>iiIII', 0x0100000C, 0, first_offset, len(first), 2)
        header += struct.pack('>iiIII', 0x01000007, 3, second_offset, len(second), 2)
        source = header + first + second
        patched = mac_main.add_dylib_to_universal(source)
        self.assertEqual(len(source), len(patched))
        self.assertEqual(struct.unpack_from('<I', patched, first_offset + 16)[0], 2)
        self.assertEqual(struct.unpack_from('<I', patched, second_offset + 16)[0], 2)


if __name__ == '__main__':
    unittest.main()
