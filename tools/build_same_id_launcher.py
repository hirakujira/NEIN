#!/usr/bin/env python3
"""Build a double-clickable launcher for the same-ID NEIN app."""

import argparse
import json
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_SOURCE = ROOT / 'launcher' / 'NEINLauncher.m'
LAUNCHER_BINARY = 'NEINLauncher'
INNER_RELATIVE = Path('Contents/Resources/LINE.app')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inner_app', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument(
        '--signing-identity', default='-',
        help='codesign identity; use - for ad-hoc signing',
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    inner = args.inner_app.resolve()
    output = args.output.resolve()
    inner_info_path = inner / 'Contents/Info.plist'
    if not inner.is_dir() or not inner_info_path.is_file():
        raise ValueError('inner_app must be a complete app bundle.')
    if output.exists():
        raise ValueError('Output already exists; choose a new output path.')

    inner_info = plistlib.loads(inner_info_path.read_bytes())
    if inner_info.get('CFBundleIdentifier') != 'jp.naver.line.mac':
        raise ValueError('The inner app must retain jp.naver.line.mac.')

    inner_manifest_path = inner.with_suffix('.manifest.json')
    inner_manifest = {}
    if inner_manifest_path.is_file():
        inner_manifest = json.loads(inner_manifest_path.read_text(encoding='utf-8'))

    launcher_contents = output / 'Contents'
    launcher_contents.mkdir(parents=True)
    resources = launcher_contents / 'Resources'
    resources.mkdir()
    shutil.copytree(inner, resources / 'LINE.app', symlinks=True)

    icon_source = inner / 'Contents/Resources/LINE.icns'
    if not icon_source.is_file():
        raise ValueError('The inner app is missing its LINE.icns icon.')
    shutil.copy2(icon_source, resources / 'NEIN.icns')

    info = {
        'CFBundleDevelopmentRegion': 'en',
        'CFBundleDisplayName': 'NEIN',
        'CFBundleExecutable': LAUNCHER_BINARY,
        'CFBundleIdentifier': 'jp.naver.line.mac.nein.launcher',
        'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleName': 'NEIN',
        'CFBundleIconFile': 'NEIN.icns',
        'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': inner_info.get('CFBundleShortVersionString', '26.4.2'),
        'CFBundleVersion': inner_info.get('CFBundleVersion', '3955'),
        'LSMinimumSystemVersion': inner_info.get('LSMinimumSystemVersion', '14.0'),
        'LSUIElement': True,
        'NSHighResolutionCapable': True,
    }
    (launcher_contents / 'Info.plist').write_bytes(
        plistlib.dumps(info, fmt=plistlib.FMT_BINARY),
    )

    with tempfile.TemporaryDirectory(prefix='nein-launcher-build-') as temp_dir:
        binary = Path(temp_dir) / LAUNCHER_BINARY
        sdk = subprocess.check_output(
            ['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True,
        ).strip()
        subprocess.run([
            'xcrun', '--sdk', 'macosx', 'clang',
            '-target', 'arm64-apple-macos' + str(info['LSMinimumSystemVersion']),
            '-arch', 'arm64', '-arch', 'x86_64',
            '-isysroot', sdk,
            '-mmacosx-version-min=' + str(info['LSMinimumSystemVersion']),
            '-fobjc-arc', '-framework', 'Foundation',
            str(LAUNCHER_SOURCE), '-o', str(binary),
        ], check=True)
        target_binary = launcher_contents / 'MacOS' / LAUNCHER_BINARY
        target_binary.parent.mkdir()
        shutil.copy2(binary, target_binary)

        subprocess.run([
            'codesign', '--force', '--deep', '--sign', args.signing_identity,
            '--options', 'runtime', str(output),
        ], check=True)
        subprocess.run([
            'codesign', '--verify', '--deep', '--strict', str(output),
        ], check=True)

    manifest = {
        'status': 'same_bundle_id_runtime_launcher',
        'launcher_app': str(output),
        'launcher_bundle_identifier': info['CFBundleIdentifier'],
        'inner_app': str(output / INNER_RELATIVE),
        'inner_bundle_identifier': inner_info['CFBundleIdentifier'],
        'runtime_copy': True,
        'dns_blocking': False,
        'qt_ad_hiding': inner_manifest.get('qt_ad_hiding', True),
        'qt_widgets_ad_hiding': inner_manifest.get('qt_widgets_ad_hiding', False),
        'signing_identity': (
            'ad-hoc' if args.signing_identity == '-' else args.signing_identity
        ),
        'limitations': [
            'The inner LINE process keeps jp.naver.line.mac for data compatibility.',
            'The launcher copies the signed inner app to a temporary runtime directory before starting it.',
            'The original /Applications/LINE.app is not modified.',
            'Real account sync and message history still require user-side testing.',
        ],
    }
    output.with_suffix('.manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8',
    )

    print(output)


if __name__ == '__main__':
    main()
