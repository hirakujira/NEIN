#!/usr/bin/env python3
"""Build an experimental ad-blocking copy of the installed LINE macOS app."""

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = Path('/Applications/LINE.app')
DEFAULT_OUTPUT = ROOT / 'output' / 'NEIN-26.4.2.app'
DEFAULT_BUNDLE_IDENTIFIER = 'jp.naver.line.mac.nein'
MAIN_BINARY = Path('Contents/MacOS/LINE')
HOOK_SOURCE = ROOT / 'hooks' / 'NEINMacHooks.mm'
HOOK_NAME = 'NEINMacHooks.dylib'
HOOK_RELATIVE = Path('Contents/Frameworks') / HOOK_NAME
HOOK_LOAD_PATH = '@executable_path/../Frameworks/' + HOOK_NAME
BLOCKED_DOMAINS = (
    'ad.line-scdn.net',
    'admob-gmats.uc.r.appspot.com',
    'doubleclick-cn.net',
    'doubleclick.net',
    'googleadservices.com',
    'googlesyndication.com',
    'imasdk.googleapis.com',
    'taboola.com',
    'taboolanews.com',
)
NOP = bytes.fromhex('1f2003d5')


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def macho_header(data):
    if len(data) < 32 or struct.unpack_from('<I', data, 0)[0] != 0xFEEDFACF:
        raise ValueError('Expected a little-endian 64-bit Mach-O slice.')
    command_count, command_size = struct.unpack_from('<II', data, 16)
    return command_count, command_size


def add_dylib_to_slice(data, load_path=HOOK_LOAD_PATH):
    command_count, command_size = macho_header(data)
    cursor = 32
    first_section = len(data)
    for _ in range(command_count):
        if cursor + 8 > len(data):
            raise ValueError('Truncated Mach-O load command.')
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or size % 8 or cursor + size > 32 + command_size:
            raise ValueError('Invalid Mach-O load-command layout.')
        if command in (0xC, 0x80000018, 0x8000001F):
            relative = struct.unpack_from('<I', data, cursor + 8)[0]
            raw_name = data[cursor + relative:cursor + size].split(b'\0')[0]
            if raw_name == load_path.encode():
                raise ValueError('Hook dylib is already referenced.')
        if command == 0x19:  # LC_SEGMENT_64
            sections = struct.unpack_from('<I', data, cursor + 64)[0]
            for index in range(sections):
                section = cursor + 72 + index * 80
                offset = struct.unpack_from('<I', data, section + 48)[0]
                if offset:
                    first_section = min(first_section, offset)
        cursor += size
    if cursor != 32 + command_size:
        raise ValueError('Mach-O load-command size mismatch.')

    raw = load_path.encode() + b'\0'
    size = (24 + len(raw) + 7) & ~7
    command = struct.pack('<6I', 0xC, size, 24, 0, 0, 0) + raw
    command += bytes(size - len(command))
    if cursor + size > first_section or any(data[cursor:cursor + size]):
        raise ValueError('No zero-filled Mach-O header padding for injection.')

    result = bytearray(data)
    struct.pack_into('<II', result, 16, command_count + 1, command_size + size)
    result[cursor:cursor + size] = command
    return bytes(result)


def add_dylib_to_universal(data):
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic == 0xCAFEBABE:
        _, count = struct.unpack_from('>II', data, 0)
        arch_size = 20
        arch_format = '>iiIII'
    elif magic == 0xCAFEBABF:
        _, count = struct.unpack_from('>II', data, 0)
        arch_size = 32
        arch_format = '>iiQQI'
    else:
        return add_dylib_to_slice(data)

    result = bytearray(data)
    for index in range(count):
        offset = 8 + index * arch_size
        fields = struct.unpack_from(arch_format, data, offset)
        slice_offset, slice_size = fields[2], fields[3]
        patched = add_dylib_to_slice(data[slice_offset:slice_offset + slice_size])
        if len(patched) != slice_size:
            raise ValueError('Injection would change a universal slice size.')
        result[slice_offset:slice_offset + slice_size] = patched
    return bytes(result)


def compile_hook(output, minimum_os, framework_dir, qt_ad_hiding=True):
    sdk = subprocess.check_output(
        ['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True,
    ).strip()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        'xcrun', '--sdk', 'macosx', 'clang++',
        '-target', 'arm64-apple-macos' + minimum_os,
        '-arch', 'arm64', '-arch', 'x86_64',
        '-isysroot', sdk, '-mmacosx-version-min=' + minimum_os,
        '-fobjc-arc', '-std=c++17', '-O2', '-Wall', '-Wextra',
    ]
    if qt_ad_hiding:
        command.extend([
            '-DNEIN_ENABLE_QT_AD_HIDING',
            '-dynamiclib', '-F', str(framework_dir),
            '-framework', 'Foundation', '-framework', 'WebKit',
            str(framework_dir / 'QtCore.framework/Versions/A/QtCore'),
            str(framework_dir / 'QtQuick.framework/Versions/A/QtQuick'),
        ])
    else:
        command.extend(['-dynamiclib', '-framework', 'Foundation', '-framework', 'WebKit'])
    command.extend([
        '-Wl,-rpath,@loader_path',
        '-Wl,-install_name,@rpath/' + HOOK_NAME,
        str(HOOK_SOURCE), '-o', str(output),
    ])
    subprocess.run(command, check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', str(output)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(output)], check=True)


def read_entitlements(app):
    result = subprocess.run(
        ['codesign', '-d', '--entitlements', ':-', str(app)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
    )
    if not result.stdout.strip():
        raise ValueError('Source app has no readable entitlements.')
    return result.stdout


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', type=Path, default=DEFAULT_INPUT)
    parser.add_argument('output', nargs='?', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        '--signing-identity', default='-',
        help='codesign identity; use - for ad-hoc signing (default: -)',
    )
    parser.add_argument(
        '--bundle-identifier', default=DEFAULT_BUNDLE_IDENTIFIER,
        help='bundle identifier for the standalone NEIN copy',
    )
    parser.add_argument(
        '--disable-qt-ad-hiding', action='store_true',
        help='build the stable WebKit-only copy without Qt visibility hooks',
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    source = args.input.resolve()
    output = args.output.resolve()
    binary = source / MAIN_BINARY
    info_path = source / 'Contents/Info.plist'
    if not source.is_dir() or not binary.is_file() or not info_path.is_file():
        raise ValueError('Input must be a complete macOS LINE.app bundle.')
    if output.exists():
        raise ValueError('Output already exists; choose a new output path.')
    info = plistlib.loads(info_path.read_bytes())
    if info.get('CFBundleIdentifier') != 'jp.naver.line.mac':
        raise ValueError('Expected jp.naver.line.mac.')
    if info.get('CFBundleShortVersionString') != '26.4.2':
        raise ValueError('This prototype is locked to LINE 26.4.2.')

    minimum_os = str(info.get('LSMinimumSystemVersion', '14.0'))
    original_binary = binary.read_bytes()
    patched_binary = add_dylib_to_universal(original_binary)

    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, output, symlinks=True)
    output_info_path = output / info_path.relative_to(source)
    output_info = plistlib.loads(output_info_path.read_bytes())
    output_info['CFBundleIdentifier'] = args.bundle_identifier
    output_info['CFBundleName'] = 'NEIN'
    output_info['CFBundleDisplayName'] = 'NEIN'
    output_info_path.write_bytes(plistlib.dumps(output_info, fmt=plistlib.FMT_BINARY))
    output_binary = output / MAIN_BINARY
    output_binary.write_bytes(patched_binary)

    hook_path = output / HOOK_RELATIVE
    with tempfile.TemporaryDirectory(prefix='nein-mac-build-') as temp:
        built_hook = Path(temp) / HOOK_NAME
        compile_hook(
            built_hook, minimum_os, source / 'Contents/Frameworks',
            qt_ad_hiding=not args.disable_qt_ad_hiding,
        )
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built_hook, hook_path)
        entitlements = Path(temp) / 'entitlements.plist'
        entitlements.write_bytes(read_entitlements(source))
        # Ad-hoc builds can retain the source declarations. A Developer ID
        # build must not claim LINE's original team entitlements.
        sign_command = [
            'codesign', '--force', '--deep', '--sign', args.signing_identity,
            '--options', 'runtime',
        ]
        if args.signing_identity == '-':
            sign_command.extend(['--entitlements', str(entitlements)])
        sign_command.append(str(output))
        subprocess.run(sign_command, check=True)
        subprocess.run(['codesign', '--verify', '--deep', '--strict', str(output)], check=True)

    manifest = {
        'status': (
            'webkit_only_no_qt_hiding'
            if args.disable_qt_ad_hiding
            else 'experimental_qt_qml_ad_hiding'
        ),
        'source_app': str(source),
        'output_app': str(output),
        'source_bundle_identifier': info['CFBundleIdentifier'],
        'bundle_identifier': args.bundle_identifier,
        'version': info['CFBundleShortVersionString'],
        'build': info.get('CFBundleVersion'),
        'architectures': ['arm64', 'x86_64'],
        'source_binary_sha256': sha256(binary),
        'patched_binary_sha256': sha256(output_binary),
        'hook': HOOK_NAME,
        'dns_blocking': False,
        'qt_ad_hiding': not args.disable_qt_ad_hiding,
        'qt_widgets_ad_hiding': False,
        'signing_identity': 'ad-hoc' if args.signing_identity == '-' else args.signing_identity,
        'blocked_domains': BLOCKED_DOMAINS,
        'limitations': [
            'The stable profile does not hide native Qt/QML or Qt Widgets ad panels.',
            'Real LINE login, chat, media and advertisement behavior require device testing.',
            'The app is not notarized for App Store distribution.',
        ],
    }
    manifest_path = output.with_suffix('.manifest.json')
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
