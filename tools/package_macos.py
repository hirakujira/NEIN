#!/usr/bin/env python3
"""Create installable PKG and drag-and-drop DMG artifacts for a NEIN.app."""

import argparse
import os
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    parser.add_argument('output_dir', type=Path)
    parser.add_argument('--base-name', default=None)
    parser.add_argument('--force', action='store_true')
    return parser.parse_args(argv)


def run(command):
    subprocess.run(command, check=True)


def remove_existing(path, force):
    if not path.exists():
        return
    if not force:
        raise ValueError(f'Output already exists: {path} (use --force to replace it)')
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def main(argv=None):
    args = parse_args(argv)
    app = args.app.resolve()
    output_dir = args.output_dir.resolve()
    info_path = app / 'Contents/Info.plist'
    executable = app / 'Contents/MacOS/NEINLauncher'
    if not app.is_dir() or not info_path.is_file():
        raise ValueError('app must be a complete .app bundle')
    if not executable.is_file():
        raise ValueError('app must contain Contents/MacOS/NEINLauncher')

    info = plistlib.loads(info_path.read_bytes())
    app_name = info.get('CFBundleDisplayName') or info.get('CFBundleName') or app.stem
    version = info.get('CFBundleShortVersionString', 'unknown')
    base_name = args.base_name or f'{app_name}-{version}'
    output_dir.mkdir(parents=True, exist_ok=True)
    pkg = output_dir / f'{base_name}.pkg'
    dmg = output_dir / f'{base_name}.dmg'
    remove_existing(pkg, args.force)
    remove_existing(dmg, args.force)

    run(['codesign', '--verify', '--deep', '--strict', str(app)])
    run([
        'pkgbuild', '--component', str(app), '--install-location', '/Applications',
        str(pkg),
    ])

    with tempfile.TemporaryDirectory(prefix='nein-dmg-') as staging:
        staging_dir = Path(staging)
        shutil.copytree(app, staging_dir / app.name, symlinks=True)
        os.symlink('/Applications', staging_dir / 'Applications')
        run([
            'hdiutil', 'create', '-volname', app_name,
            '-srcfolder', str(staging_dir), '-ov', '-format', 'UDZO', str(dmg),
        ])

    print(pkg)
    print(dmg)


if __name__ == '__main__':
    main()
