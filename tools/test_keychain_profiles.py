import subprocess
import tempfile
import unittest
from pathlib import Path

import analyze_patch_profile as analyzer


ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'hooks'


def sample_profile(version, uuid, got_address, got_offset, auth_offset, e2ee_offset):
    return {
        'schema_version': analyzer.KEYCHAIN_PROFILE_SCHEMA_VERSION,
        'profile_type': 'line_keychain',
        'bundle_identifier': 'jp.naver.line',
        'version': version,
        'build': 'test-build',
        'architecture': 'arm64',
        'executable_sha256': '0' * 64,
        'macho_uuid': uuid,
        'got': {
            'address': hex(got_address),
            'offset': hex(got_offset),
            'file_offset': hex(got_offset),
        },
        'imports': {
            name: {
                'stub_address': hex(index + 0x1000),
                'got_address': hex(got_address + index * 8),
            }
            for index, name in enumerate(('add', 'copy', 'delete', 'update'))
        },
        'authentication_sites': [
            {
                'operation': operation,
                'return_offset': hex(auth_offset + index * 4),
                'selector': selector,
                'class': 'NLAuthenticationManager',
            }
            for selector, operations in (
                ('saveToKeychainData:forQuery:', ('add', 'add', 'update')),
                ('dataFromKeychainForQuery:errorCode:', ('copy',)),
                ('deleteFromKeychainWithQuery:', ('delete', 'delete')),
            )
            for index, operation in enumerate(operations)
        ],
        'e2ee_sites': [{
            'operation': 'copy',
            'return_offset': hex(e2ee_offset),
        }],
    }


class KeychainProfileTests(unittest.TestCase):
    def test_e2ee_instructions_serialize_as_fixed_width_hex(self):
        signatures = [{
            'operations': ['copy', 'add'],
            'instructions': [0x94000000, 0xD503201F, 0x1],
        }]

        serialized = analyzer._encode_e2ee_reference_instructions(signatures)

        self.assertEqual(serialized[0]['instructions'], [
            '0x94000000', '0xd503201f', '0x00000001',
        ])
        self.assertEqual(
            analyzer._decode_e2ee_reference_instructions(serialized),
            signatures,
        )

    def test_e2ee_instruction_decoder_rejects_invalid_values(self):
        for instruction in ('94000000', '0x100000000', -1, True):
            with self.subTest(instruction=instruction):
                with self.assertRaises(ValueError):
                    analyzer._decode_e2ee_reference_instructions([{
                        'operations': ['copy'],
                        'instructions': [instruction],
                    }])

    def test_generated_profile_header_compiles_for_both_versions(self):
        profiles = (
            sample_profile(
                '26.14.0', '0bab483cca8538ce89840c20c92511e4',
                0x10b377cd8, 0xb377cd8, 0x37c6ee0, 0x3d63558,
            ),
            sample_profile(
                '26.15.1', 'e3b7a4f019f13a5abfad2da2c7b528a2',
                0x10bc66d30, 0xbc66d30, 0x39e6410, 0x3f80638,
            ),
        )
        for profile in profiles:
            with self.subTest(version=profile['version']):
                header = analyzer.render_c_header(profile)
                source = r'''
#include <assert.h>
#include <string.h>
#include "LINEKeychainProfiles.h"
#include "LINEKeychainProfileData.h"

int main(void) {
    assert(strcmp(LMKEmbeddedKeychainProfile.version, "VERSION") == 0);
    assert(LMKEmbeddedKeychainProfile.got_address == GOT_ADDRESS);
    assert(LMKEmbeddedKeychainProfile.got_offset == GOT_OFFSET);
    assert(LMKEmbeddedKeychainProfile.authentication_site_count == 6);
    assert(LMKEmbeddedKeychainProfile.e2ee_site_count == 1);
    assert(LMKKeychainProfileHasCallSite(
        LMKEmbeddedKeychainProfile.authentication_sites,
        LMKEmbeddedKeychainProfile.authentication_site_count,
        LMK_KEYCHAIN_ADD, AUTH_SITE));
    assert(LMKKeychainProfileHasCallSite(
        LMKEmbeddedKeychainProfile.e2ee_sites,
        LMKEmbeddedKeychainProfile.e2ee_site_count,
        LMK_KEYCHAIN_COPY, E2EE_SITE));
    return 0;
}
'''
                source = (
                    source.replace('VERSION', profile['version'])
                    .replace('GOT_ADDRESS', f"{profile['got']['address']}ULL")
                    .replace('GOT_OFFSET', f"{profile['got']['offset']}ULL")
                    .replace(
                        'AUTH_SITE',
                        f"{profile['authentication_sites'][0]['return_offset']}ULL",
                    )
                    .replace(
                        'E2EE_SITE',
                        f"{profile['e2ee_sites'][0]['return_offset']}ULL",
                    )
                )
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'LINEKeychainProfileData.h').write_text(
                        header, encoding='utf-8',
                    )
                    c_file = root / 'profile_test.c'
                    executable = root / 'profile_test'
                    c_file.write_text(source, encoding='utf-8')
                    subprocess.run([
                        'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(HOOKS), '-I', str(root),
                        str(c_file), '-o', str(executable),
                    ], check=True)
                    subprocess.run([str(executable)], check=True)

    def test_header_generation_rejects_non_contiguous_got(self):
        profile = sample_profile(
            '26.15.1', 'e3b7a4f019f13a5abfad2da2c7b528a2',
            0x10bc66d30, 0xbc66d30, 0x39e6410, 0x3f80638,
        )
        profile['imports']['update']['got_address'] = '0x10bc66d58'
        with self.assertRaisesRegex(ValueError, 'not contiguous'):
            analyzer.render_c_header(profile)


if __name__ == '__main__':
    unittest.main()
