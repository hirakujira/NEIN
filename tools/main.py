#!/usr/bin/env python3
"""Build a version-locked LINE secondary-login IPA.

Includes private App Group fallback unless --entry-only is selected.
"""
import argparse
from copy import copy
from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

import analyze_patch_profile
import scan_ad_domains

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = 'Payload/LINE.app/LINE'
PLIST = 'Payload/LINE.app/Info.plist'
NOP = bytes.fromhex('1f2003d5')
LIB_NAME = 'NEINHooks.dylib'
LIB_ENTRY = 'Payload/LINE.app/Frameworks/' + LIB_NAME
LOAD_PATH = '@executable_path/Frameworks/' + LIB_NAME
APP_ROOT = 'Payload/LINE.app/'
ICON_PREVIEW_ROOT = APP_ROOT + 'NEINIconPreviews/'
ICON_PICKER_KEY = 'NEINIconPicker'
ICON_PREVIEW_MANIFEST = 'NEINIconPreviews/manifest.json'
REMOVED_ARCHIVE_PREFIXES = (
    'Payload/LINE.app/PlugIns/',
    'Payload/LINE.app/Watch/',
    # Original signing and store catalogs no longer describe the modified app.
    'Payload/LINE.app/_CodeSignature/',
    'META-INF/',
)
DEFAULT_BUNDLE_ID = 'kinta.ma.nein'
DEFAULT_APP_NAME = 'NEIN'
DEFAULT_ICON = 'design_simple_banana'
AD_DOMAIN_LIST = ROOT / 'ad_domains.txt'
PATCH_PROFILE_DIR = ROOT / 'patch_profiles'
LC_BUILD_VERSION = 0x32
PLATFORM_IOS = 2
IPHONE_DUO_SDK = (27, 1, 0)

@dataclass(frozen=True)
class PatchProfile:
    version: str
    build: str
    executable_sha256: str
    patch_offset: int
    patch_va: int
    original: bytes
    instruction: str
    keychain_profile: dict | None = None
    home_friends: dict | None = None
    sticker_shop: dict | None = None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    checksum = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def same_contents(left, right):
    while True:
        chunk = left.read(1024 * 1024)
        if chunk != right.read(1024 * 1024):
            return False
        if not chunk:
            return True


def copy_archive_member(source, target, entry):
    copied = copy(entry)
    if entry.is_dir():
        target.writestr(copied, b'')
    else:
        with source.open(entry) as original, target.open(copied, 'w') as output:
            shutil.copyfileobj(original, output, 1024 * 1024)


def retained_archive_members(names):
    return [
        name for name in names
        if not is_removed_archive_member(name)
    ]


def is_removed_archive_member(name):
    # FairPlay replication paths can recreate removed extension directories.
    return (
        name == 'iTunesMetadata.plist' or
        name.startswith(REMOVED_ARCHIVE_PREFIXES) or
        (name.startswith(APP_ROOT) and ('.appex/' in name or '/SC_Info/' in name))
    )


def app_icon_names(info):
    phone = info.get('CFBundleIcons')
    pad = info.get('CFBundleIcons~ipad')
    if not isinstance(phone, dict) or not isinstance(pad, dict):
        raise ValueError('Both iPhone and iPad app icon definitions are required.')

    phone_primary = phone.get('CFBundlePrimaryIcon')
    pad_primary = pad.get('CFBundlePrimaryIcon')
    if not isinstance(phone_primary, dict) or not isinstance(pad_primary, dict):
        raise ValueError('Both iPhone and iPad primary app icons are required.')
    phone_name = phone_primary.get('CFBundleIconName')
    pad_name = pad_primary.get('CFBundleIconName')
    if not isinstance(phone_name, str) or not phone_name or phone_name != pad_name:
        raise ValueError('iPhone and iPad primary app icon names do not match.')

    phone_alternates = phone.get('CFBundleAlternateIcons')
    pad_alternates = pad.get('CFBundleAlternateIcons')
    if not isinstance(phone_alternates, dict) or not isinstance(pad_alternates, dict):
        raise ValueError('Both iPhone and iPad alternate app icon lists are required.')
    if set(phone_alternates) != set(pad_alternates):
        raise ValueError('iPhone and iPad alternate app icon lists do not match.')
    if phone_name in phone_alternates:
        raise ValueError('The original primary icon is duplicated as an alternate icon.')

    names = [phone_name]
    for name in phone_alternates:
        if not isinstance(name, str) or not name:
            raise ValueError('The app icon list contains an invalid name.')
        for definition in (phone_alternates[name], pad_alternates[name]):
            if not isinstance(definition, dict):
                raise ValueError(f'App icon metadata is missing for {name}.')
            definition_name = definition.get('CFBundleIconName')
            if definition_name is not None and definition_name != name:
                raise ValueError(f'App icon metadata name mismatch for {name}.')
        names.append(name)
    return phone_name, names


def collect_icon_preview_assets(output_path, icon_names):
    manifest_path = output_path / 'manifest.json'
    try:
        manifest_data = manifest_path.read_bytes()
        manifest = json.loads(manifest_data)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError('Could not read the generated icon preview manifest.') from error
    entries = manifest.get('icons') if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict) or
        manifest.get('schemaVersion') != 1 or
        not isinstance(entries, list) or
        len(entries) != len(icon_names) or
        any(not isinstance(entry, dict) for entry in entries) or
        [entry.get('name') for entry in entries] != icon_names
    ):
        raise ValueError('Icon preview manifest does not match the Info.plist list.')

    files = {}
    for entry in entries:
        name = entry['name']
        filename = entry.get('file')
        if filename != name + '.png' or Path(filename).name != filename:
            raise ValueError('Icon preview manifest contains an unexpected filename.')
        try:
            data = (output_path / filename).read_bytes()
        except OSError as error:
            raise ValueError(f'Invalid or missing icon preview: {name}.') from error
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError(f'Invalid or missing icon preview: {name}.')
        files[ICON_PREVIEW_ROOT + filename] = data
    files[ICON_PREVIEW_ROOT + 'manifest.json'] = manifest_data
    if len(files) != len(icon_names) + 1:
        raise ValueError('Icon preview count does not match the icon list.')
    return files


def iphone_duo_info_plist_changes(info):
    try:
        version = tuple(int(part) for part in str(info.get('DTPlatformVersion')).split('.'))
    except ValueError:
        version = ()
    if version >= IPHONE_DUO_SDK[:2]:
        return {}
    return {'DTSDKName': 'iphoneos%d.%d' % IPHONE_DUO_SDK[:2],
            'DTPlatformVersion': '%d.%d' % IPHONE_DUO_SDK[:2]}


def patched_info_plist(info, enable_icon_picker=False, iphone_duo=False):
    result = dict(info)
    result['CFBundleIdentifier'] = DEFAULT_BUNDLE_ID
    result['CFBundleDisplayName'] = DEFAULT_APP_NAME
    result['CFBundleName'] = DEFAULT_APP_NAME
    for key in tuple(result):
        if key.startswith('CFBundleURLTypes'):
            del result[key]
    original_primary_name, icon_names = app_icon_names(info)
    if DEFAULT_ICON not in icon_names:
        raise ValueError(f'Default app icon is unavailable: {DEFAULT_ICON}')

    for key in ('CFBundleIcons', 'CFBundleIcons~ipad'):
        icon_config = dict(info[key])
        primary_icon = icon_config['CFBundlePrimaryIcon']
        alternates = dict(icon_config['CFBundleAlternateIcons'])
        selected_icon = alternates.get(
            DEFAULT_ICON,
            primary_icon if DEFAULT_ICON == original_primary_name else None,
        )
        if not selected_icon:
            raise ValueError(f'Default app icon is unavailable: {DEFAULT_ICON}')
        alternates.pop(DEFAULT_ICON, None)
        if enable_icon_picker:
            if DEFAULT_ICON != original_primary_name:
                alternates[original_primary_name] = dict(primary_icon)
        icon_config['CFBundleAlternateIcons'] = alternates
        icon_config['CFBundlePrimaryIcon'] = dict(selected_icon)
        result[key] = icon_config

    if enable_icon_picker:
        result[ICON_PICKER_KEY] = {
            'Enabled': True,
            'PrimaryIcon': DEFAULT_ICON,
            'OriginalPrimaryIcon': original_primary_name,
            'AllowedIconNames': icon_names,
            'PreviewManifest': ICON_PREVIEW_MANIFEST,
        }
    if iphone_duo:
        result.update(iphone_duo_info_plist_changes(info))
    return plistlib.dumps(result, fmt=plistlib.FMT_XML, sort_keys=False)


def extract_icon_previews(ipa_path, icon_names):
    if sys.platform != 'darwin':
        raise ValueError('App icon preview extraction requires macOS CoreUI.')
    with zipfile.ZipFile(ipa_path) as archive:
        catalog_name = APP_ROOT + 'Assets.car'
        if catalog_name not in archive.namelist():
            raise ValueError('The LINE app does not contain its main Assets.car.')
        catalog_data = archive.read(catalog_name)

    with tempfile.TemporaryDirectory(prefix='nein-icon-previews-') as directory:
        temporary = Path(directory)
        catalog_path = temporary / 'Assets.car'
        names_path = temporary / 'icon-names.json'
        output_path = temporary / 'NEINIconPreviews'
        helper_path = temporary / 'extract_icon_previews'
        catalog_path.write_bytes(catalog_data)
        names_path.write_text(json.dumps(icon_names), encoding='utf-8')

        sdk = subprocess.check_output(
            ['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True,
        ).strip()
        subprocess.run([
            'xcrun', '--sdk', 'macosx', 'clang',
            '-isysroot', sdk, '-fobjc-arc', '-fblocks',
            '-framework', 'AppKit', '-framework', 'ImageIO',
            '-framework', 'UniformTypeIdentifiers',
            str(ROOT / 'tools' / 'extract_icon_previews.m'),
            '-o', str(helper_path),
        ], check=True)
        subprocess.run([
            str(helper_path), str(catalog_path), str(names_path), str(output_path),
        ], check=True)

        return collect_icon_preview_assets(output_path, icon_names)


def verify_profile_for_binary(profile, original):
    image = analyze_patch_profile.parse_arm64_macho(original)
    expected_offset = (
        image.text_offset + profile.patch_va - image.text_address
    )
    if (
        expected_offset != profile.patch_offset or
        profile.patch_va < image.text_address or
        profile.patch_va + 4 > image.text_address + image.text_size or
        original[profile.patch_offset:profile.patch_offset + 4] != profile.original
    ):
        raise ValueError('Patch profile address, offset or instruction mismatch.')


def find_profile(info, original, allow_unverified=False, profile_dir=None):
    document, _ = analyze_patch_profile.load_or_create_profile(
        info, original,
        PATCH_PROFILE_DIR if profile_dir is None else profile_dir,
        allow_unverified=allow_unverified,
    )
    patch = document['login_patch']
    profile = PatchProfile(
        version=document['version'],
        build=document['build'],
        executable_sha256=document['executable_sha256'],
        patch_offset=int(patch['file_offset'], 16),
        patch_va=int(patch['virtual_address'], 16),
        original=bytes.fromhex(patch['original_hex']),
        instruction=patch['instruction'],
        keychain_profile=document['keychain'],
        home_friends=document.get('home_friends'),
        sticker_shop=document.get('sticker_shop'),
    )
    verify_profile_for_binary(profile, original)
    return profile


def select_profile(
    info, original, auto_login_patch=False, allow_unverified=False,
    profile_dir=None,
):
    if not auto_login_patch:
        return find_profile(info, original, allow_unverified, profile_dir), None
    profile, created = analyze_patch_profile.load_or_create_profile(
        info, original,
        PATCH_PROFILE_DIR if profile_dir is None else profile_dir,
    )
    patch = profile['login_patch']
    profile = PatchProfile(
        version=profile['version'],
        build=profile['build'],
        executable_sha256=profile['executable_sha256'],
        patch_offset=int(patch['file_offset'], 16),
        patch_va=int(patch['virtual_address'], 16),
        original=bytes.fromhex(patch['original_hex']),
        instruction=patch['instruction'],
        keychain_profile=profile['keychain'],
        home_friends=profile.get('home_friends'),
        sticker_shop=profile.get('sticker_shop'),
    )
    analysis = {
        'mode': 'analyzed_and_saved' if created else 'saved_profile',
        'automatic_patch': True,
        'patch_applied': True,
        'profile_loaded': True,
        'profile_version': profile.version,
        'profile_build': profile.build,
        'profile_created': created,
    }
    return profile, analysis


def patched_binary(original, profile, verify_hash=True):
    if verify_hash and digest(original) != profile.executable_sha256:
        raise ValueError('Executable SHA-256 mismatch: this patch is only for the analyzed dump.')
    if struct.unpack_from('<I', original)[0] != 0xFEEDFACF:
        raise ValueError('Expected a thin little-endian 64-bit Mach-O.')
    if original[profile.patch_offset:profile.patch_offset + 4] != profile.original:
        raise ValueError('Expected ARM64 branch not found; refusing to patch.')
    result = bytearray(original)
    result[profile.patch_offset:profile.patch_offset + 4] = NOP
    return bytes(result)


def patch_friend_tab_default_collapsed(binary, profile):
    if not isinstance(profile, dict) or not isinstance(profile.get('patches'), list):
        raise ValueError('No analyzed Friends patch is available for this IPA.')
    result = bytearray(binary)
    for patch in profile['patches']:
        try:
            offset = int(patch['file_offset'], 16)
            original = bytes.fromhex(patch['original_hex'])
            replacement = bytes.fromhex(patch['patched_hex'])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('Malformed analyzed Friends patch site.') from error
        if (
            len(original) != 4 or len(replacement) != 4 or
            offset < 0 or offset + 4 > len(binary) or
            binary[offset:offset + 4] != original
        ):
            raise ValueError('Expected FriendTabViewModel initial expansion instruction not found.')
        result[offset:offset + 4] = replacement
    return bytes(result)


def patch_sticker_shop(binary, profile):
    if not isinstance(profile, dict):
        raise ValueError('No audited sticker-shop patch is available for this IPA.')
    try:
        native = profile['native_routes']
        cave = native['code_cave']
        sites = (profile, profile['liff_route'], native, cave, profile['coin_entry'])
        patches = [
            (int(site['file_offset'], 16), bytes.fromhex(site['original_hex']),
             bytes.fromhex(site['patched_hex']))
            for site in sites
        ]
        guard_address = int(native['guard_address'], 16)
        cave_address = int(cave['address'], 16)
        code = analyze_patch_profile.sticker_shop_native_code(native)
        if (
            int(native['deny_address'], 16) != guard_address + 0x60 or
            guard_address - patches[2][0] != cave_address - patches[3][0]
        ):
            raise ValueError('Native sticker-shop addresses do not match.')
        guard_branch = struct.pack('<I', analyze_patch_profile._branch26(guard_address, cave_address))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Malformed sticker-shop patch site.') from error
    expected = ((b'\x10\0\0\0', b'\x20\0\0\0'),
                (bytes.fromhex('96000037'), NOP),
                (bytes.fromhex('15030036'), guard_branch), (bytes(len(code)), code),
                (bytes.fromhex('60008052'), bytes.fromhex('00008052')))
    ranges = sorted((offset, offset + len(original)) for offset, original, _ in patches)
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])) or any(
        offset < 0 or offset % 4 or offset + len(original) > len(binary) or
        (original, replacement) != allowed or
        binary[offset:offset + len(original)] != original
        for (offset, original, replacement), allowed in zip(patches, expected)
    ):
        raise ValueError('Expected sticker-shop dispatch entry, LIFF branch or native guard not found.')
    result = bytearray(binary)
    for offset, original, replacement in patches:
        result[offset:offset + len(original)] = replacement
    return bytes(result)


def add_dylib(data):
    if struct.unpack_from('<I', data, 0)[0] != 0xfeedfacf:
        raise ValueError('Expected thin 64-bit Mach-O')
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    first_section = len(data)
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or size % 8 or cursor + size > 32 + command_size:
            raise ValueError('Invalid load-command layout')
        if cmd in (0xc, 0x80000018, 0x8000001f):
            relative = struct.unpack_from('<I', data, cursor + 8)[0]
            name = data[cursor + relative:cursor + size].split(b'\0')[0]
            if name == LOAD_PATH.encode():
                raise ValueError('Compatibility dylib already referenced')
        if cmd == 0x19:
            sections = struct.unpack_from('<I', data, cursor + 64)[0]
            for i in range(sections):
                section = cursor + 72 + i * 80
                off = struct.unpack_from('<I', data, section + 48)[0]
                if off:
                    first_section = min(first_section, off)
        cursor += size
    if cursor != 32 + command_size:
        raise ValueError('Load command size mismatch')
    raw = LOAD_PATH.encode() + b'\0'
    size = (24 + len(raw) + 7) & ~7
    command = struct.pack('<6I', 0xc, size, 24, 0, 0, 0) + raw
    command += bytes(size - len(command))
    if cursor + size > first_section or any(data[cursor:cursor + size]):
        raise ValueError('Not enough zero-filled header padding; refusing to shift binary data')
    result = bytearray(data)
    struct.pack_into('<II', result, 16, count + 1, command_size + size)
    result[cursor:cursor + size] = command
    return bytes(result), {'load_command_offset': hex(cursor), 'load_command_size': size,
                           'path': LOAD_PATH, 'first_section_offset': hex(first_section)}


def macho_version(value):
    return f'{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}'


def patch_build_version_sdk(data):
    if struct.unpack_from('<I', data, 0)[0] != 0xfeedfacf:
        raise ValueError('Expected thin 64-bit Mach-O')
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    build_versions = []
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or size % 8 or cursor + size > 32 + command_size:
            raise ValueError('Invalid load-command layout')
        if cmd == LC_BUILD_VERSION:
            if size < 24:
                raise ValueError('Truncated LC_BUILD_VERSION load command')
            build_versions.append(cursor)
        cursor += size
    if cursor != 32 + command_size:
        raise ValueError('Load command size mismatch')
    if len(build_versions) != 1:
        raise ValueError('Expected exactly one LC_BUILD_VERSION load command.')
    offset = build_versions[0]
    platform, minos, sdk = struct.unpack_from('<3I', data, offset + 8)
    if platform != PLATFORM_IOS:
        raise ValueError('LC_BUILD_VERSION platform is not iOS.')
    major, minor, patch = IPHONE_DUO_SDK
    target = (major << 16) | (minor << 8) | patch
    result = bytearray(data)
    if sdk < target:
        struct.pack_into('<I', result, offset + 16, target)
    return bytes(result), {
        'load_command_offset': hex(offset),
        'sdk_field_offset': hex(offset + 16),
        'minimum_os': macho_version(minos),
        'original_sdk': macho_version(sdk),
        'patched_sdk': macho_version(max(sdk, target)),
        'changed': sdk < target,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Original verified IPA, not a previously patched IPA')
    parser.add_argument('output', type=Path)
    parser.add_argument('--entry-only', action='store_true',
                        help='Only patch the secondary-login entry; do not compile or inject a compatibility dylib')
    parser.add_argument('--auto-login-patch', action='store_true',
                        help='Load or generate one combined exact-match patch profile; requires --entry-only')
    parser.add_argument('--primary-login', action='store_true',
                        help='Keep the original primary-phone login branch instead of applying the iPad secondary-login patch')
    parser.add_argument('--diagnostics', action='store_true',
                        help='Log error codes, selected localization keys, container results and LINE offsets')
    parser.add_argument('--keychain-compat', action='store_true',
                        help='Audited E2EE/authentication missing-entitlement retry with default Keychain group; includes diagnostics')
    parser.add_argument('--message-diagnostics', action='store_true',
                        help='Read-only post-login observations; includes current Keychain compatibility')
    parser.add_argument('--remove-ads', action='store_true',
                        help='Block audited ad domains and disable known ad views (verified on 26.14.0; experimental on 26.15.1)')
    parser.add_argument('--hide-promotional-tabs', action='store_true',
                        help='Hide VOOM, News, Shopping and Discover tab buttons (verified on 26.14.0; experimental on 26.15.1 and 26.17.0)')
    parser.add_argument('--tab-diagnostics', action='store_true',
                        help='Add a tab-only JSON export button; requires --hide-promotional-tabs')
    parser.add_argument('--collapse-friends-on-launch', action='store_true',
                        help='Initialize the Friends section as collapsed')
    parser.add_argument('--enable-sticker-shop', action='store_true',
                        help='Experimentally enable audited sticker-shop routes and coin entry; normal billing and authorization still apply')
    parser.add_argument('--iphone-duo', action='store_true',
                        help='Experimentally mark the app as built with the iOS 27.1 SDK so iPhone Duo uses the full inner display; keeps bars horizontal')
    parser.add_argument('--allow-unverified', action='store_true',
                        help='Allow a different executable hash for a known version/build; still checks the original ARM64 instruction')
    args = parser.parse_args(argv)
    if args.enable_sticker_shop and args.allow_unverified:
        parser.error('--enable-sticker-shop cannot be combined with --allow-unverified.')
    if args.tab_diagnostics and not args.hide_promotional_tabs:
        parser.error('--tab-diagnostics requires --hide-promotional-tabs.')
    if args.message_diagnostics:
        args.keychain_compat = True
    if args.keychain_compat:
        args.diagnostics = True
    if args.auto_login_patch and not args.entry_only:
        parser.error('--auto-login-patch requires --entry-only.')
    if args.entry_only and (args.diagnostics or args.remove_ads or
                            args.hide_promotional_tabs):
        parser.error('--entry-only cannot be combined with diagnostics, compatibility hooks, or ad removal.')
    if args.entry_only and args.primary_login:
        parser.error('--entry-only cannot be combined with --primary-login.')
    if args.entry_only and args.iphone_duo:
        parser.error('--entry-only cannot be combined with --iphone-duo.')
    if (args.output.exists() or args.output.with_suffix('.manifest.json').exists() or
            args.output.resolve() == args.input.resolve()):
        parser.error('Output and manifest must be new files distinct from the input.')
    return args


def main():
    args = parse_args()
    with zipfile.ZipFile(args.input) as source:
        if len(source.namelist()) != len(set(source.namelist())):
            raise ValueError('Duplicate ZIP entry names are not supported.')
        original = source.read(EXECUTABLE)
        info = plistlib.loads(source.read(PLIST))
        profile, automatic_analysis = select_profile(
            info, original, args.auto_login_patch, args.allow_unverified,
        )
        if args.collapse_friends_on_launch and profile.home_friends is None:
            raise ValueError('No analyzed Friends patch is available for this IPA.')
        if args.enable_sticker_shop:
            if profile.sticker_shop is None:
                raise ValueError('No audited sticker-shop patch is available for this IPA.')
            if digest(original) != profile.executable_sha256:
                raise ValueError('Sticker-shop patch requires an exact executable SHA-256 match.')
    output_info = patched_info_plist(
        info, enable_icon_picker=not args.entry_only, iphone_duo=args.iphone_duo,
    )
    icon_preview_files = (
        {} if args.entry_only else
        extract_icon_previews(args.input, app_icon_names(info)[1])
    )
    build, lib_data = (
        (None, None) if args.entry_only
        else build_compat_dylib(args, info, original, profile)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.input) as source:
        names = source.namelist()
        if (
            len(names) != len(set(names)) or
            (lib_data is not None and LIB_ENTRY in names) or
            any(name in names for name in icon_preview_files)
        ):
            raise ValueError('Unexpected or duplicate archive member')
        entry_patched = (
            original if args.primary_login else
            patched_binary(original, profile, verify_hash=not args.allow_unverified)
        )
        modified, injection = (entry_patched, None) if args.entry_only else add_dylib(entry_patched)
        if args.collapse_friends_on_launch:
            modified = patch_friend_tab_default_collapsed(
                modified, profile.home_friends,
            )
        if args.enable_sticker_shop:
            modified = patch_sticker_shop(modified, profile.sticker_shop)
        modified, sdk_patch = (
            patch_build_version_sdk(modified) if args.iphone_duo else (modified, None)
        )
        with zipfile.ZipFile(args.output, 'x') as target:
            target.comment = source.comment
            for entry in source.infolist():
                if is_removed_archive_member(entry.filename):
                    continue
                if entry.filename == EXECUTABLE:
                    target.writestr(copy(entry), modified)
                elif entry.filename == PLIST:
                    target.writestr(copy(entry), output_info)
                else:
                    copy_archive_member(source, target, entry)
            if lib_data is not None:
                entry = zipfile.ZipInfo(LIB_ENTRY, (2026, 9, 15, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100755 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(entry, lib_data)
            for name, content in icon_preview_files.items():
                entry = zipfile.ZipInfo(name, (2026, 9, 15, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(entry, content)
    # Exclude stale signing/store metadata and embedded bundles whose IDs cannot
    # remain valid after the main app is re-signed.
    with zipfile.ZipFile(args.input) as source, zipfile.ZipFile(args.output) as target:
        retained_names = retained_archive_members(source.namelist())
        expected_names = (
            retained_names +
            ([LIB_ENTRY] if lib_data is not None else []) +
            list(icon_preview_files)
        )
        if target.namelist() != expected_names:
            raise AssertionError('Unexpected member layout')
        for name in retained_names:
            if name.endswith('/'):
                continue
            expected = (
                BytesIO(modified) if name == EXECUTABLE else
                BytesIO(output_info) if name == PLIST else
                source.open(name)
            )
            with expected, target.open(name) as actual:
                if not same_contents(expected, actual):
                    raise AssertionError('Unexpected changed member: ' + name)
        if lib_data is not None and target.read(LIB_ENTRY) != lib_data:
            raise AssertionError('Dylib or ZIP verification failed')
        for name, content in icon_preview_files.items():
            if target.read(name) != content:
                raise AssertionError('Icon preview archive mismatch: ' + name)
    expected_entry = profile.original if args.primary_login else NOP
    if modified[profile.patch_offset:profile.patch_offset + 4] != expected_entry:
        raise AssertionError('Login entry instruction differs from the selected mode.')
    start = int(injection['load_command_offset'], 16) if injection else 0
    end = start + injection['load_command_size'] if injection else 0
    optional_patch_ranges = (
        [
            (
                int(patch['file_offset'], 16),
                int(patch['file_offset'], 16) + len(bytes.fromhex(patch['original_hex'])),
            )
            for patch in profile.home_friends['patches']
        ]
        if args.collapse_friends_on_launch else []
    )
    if args.enable_sticker_shop:
        native = profile.sticker_shop['native_routes']
        for patch in (
            profile.sticker_shop, profile.sticker_shop['liff_route'],
            native, native['code_cave'], profile.sticker_shop['coin_entry'],
        ):
            offset = int(patch['file_offset'], 16)
            optional_patch_ranges.append((offset, offset + len(bytes.fromhex(patch['original_hex']))))
    if sdk_patch is not None:
        sdk_offset = int(sdk_patch['sdk_field_offset'], 16)
        if macho_version(struct.unpack_from('<I', modified, sdk_offset)[0]) != sdk_patch['patched_sdk']:
            raise AssertionError('LC_BUILD_VERSION SDK differs from the iPhone Duo mode.')
        optional_patch_ranges.append((sdk_offset, sdk_offset + 4))
    if len(modified) != len(original) or any(
            a != b and not (
                (injection is not None and (16 <= i < 24 or start <= i < end)) or
                profile.patch_offset <= i < profile.patch_offset + 4 or
                any(start <= i < end for start, end in optional_patch_ranges)
            )
            for i, (a, b) in enumerate(zip(original, modified))):
        raise AssertionError('Changed bytes outside documented patch regions')
    # Keep a local binary for inspection; signing this file alone is NOT installation signing.
    if build is not None:
        (build / 'LINE-container-compat').write_bytes(modified)
    manifest = {'status': 'experimental_not_device_tested_requires_resigning',
                'diagnostics': args.diagnostics,
                'entry_only': args.entry_only,
                'login_mode': 'primary' if args.primary_login else 'secondary',
                'secondary_login_patch_applied': not args.primary_login,
                'version': profile.version,
                'build': profile.build,
                'automatic_login_analysis': automatic_analysis,
                'minimum_ios': info['MinimumOSVersion'],
                'keychain_compat': args.keychain_compat,
                'allow_unverified': args.allow_unverified,
                'executable_hash_verified': (
                    digest(original) == profile.executable_sha256
                ),
                'source_bundle_identifier': info['CFBundleIdentifier'],
                'bundle_identifier': DEFAULT_BUNDLE_ID,
                'app_name': DEFAULT_APP_NAME,
                'app_icon': DEFAULT_ICON,
                'icon_picker_enabled': not args.entry_only,
                'icon_count': 0 if args.entry_only else len(app_icon_names(info)[1]),
                'url_schemes_removed': True,
                'source_signing_and_store_metadata_removed': True,
                'message_diagnostics': args.message_diagnostics,
                'remove_ads': args.remove_ads,
                'hide_promotional_tabs': args.hide_promotional_tabs,
                'collapse_friends_on_launch': args.collapse_friends_on_launch,
                'enable_sticker_shop': args.enable_sticker_shop,
                'tab_diagnostics': args.tab_diagnostics,
                'iphone_duo': None,
                'source_ipa_sha256': digest_file(args.input),
                'output_ipa_sha256': digest_file(args.output),
                'source_executable_sha256': digest(original), 'patched_executable_sha256': digest(modified),
                'dylib_sha256': digest(lib_data) if lib_data is not None else None, 'injection': injection,
                'entry_patch_offset': hex(profile.patch_offset),
                'allowed_group_ids': [] if args.entry_only else ['group.com.linecorp.line', 'group.share.com.linecorp.line'],
                'fallback': None if args.entry_only else 'Library/Application Support/LINEContainerCompat/<group ID>',
                'scope': (
                    'Main app only; audited E2EE and exact authentication-store Keychain missing-entitlement errors retry without explicit access group. No cross-extension sharing or push identity.'
                    if args.keychain_compat else
                    'Main app only; private fallback containers are not shared with extensions. '
                    'No Keychain remapping.'
                ),
                'verification': ('All retained archive contents identical except the updated Info.plist '
                                 'and documented Mach-O patches; original main-app signature resources and store metadata, '
                                 'all embedded app extensions and the Watch app were removed; '
                                 'one dylib and verified icon preview assets were added; ZIP CRC passed; '
                                 'dylib ad hoc signature verified.')}
    if args.collapse_friends_on_launch:
        manifest['home_friends'] = {
            'mode': 'friend_tab_default_collapsed',
            'view_model': 'LineHomeTab.FriendTabViewModel',
            'state_field': 'isSectionExpanded',
            'friend_case': 5,
            'patch_offsets': [
                patch['file_offset'] for patch in profile.home_friends['patches']
            ],
            'manual_toggle_preserved': True,
        }
    if args.enable_sticker_shop:
        manifest['sticker_shop'] = {
            **profile.sticker_shop,
            'scope': 'Sticker availability, LIFF/native sticker routes and their shared coin entry checks only; global feature 3, theme/emoji/account guards, login identity, balance, billing, receipts, ownership and server authorization unchanged.',
            'verification': 'Static dispatch, LIFF/native/coin entry and archive checks only for this build; no IAP support added. User-reported 26.17.0 sticker purchases use coins charged in original LINE; other versions still require real-device verification.',
        }
    if args.iphone_duo:
        manifest['iphone_duo'] = {
            'status': 'experimental_requires_real_device_testing',
            'build_version': sdk_patch,
            'info_plist': {
                key: {'original': info.get(key), 'patched': value}
                for key, value in iphone_duo_info_plist_changes(info).items()
            },
            'vertical_bar': 'disabled',
            'vertical_bar_hook': (
                '-[UIViewController preferredVerticalBarBehavior] returns '
                'UIVerticalBarBehaviorDisabled on iOS 27.1 and later.'
            ),
            'scope': (
                'Every iOS 27 device applies iOS 27.1 SDK UIKit behavior to this build, '
                'not only iPhone Duo (for example zero default UIView layout margins). '
                'Two-column layouts remain LINE size-class decisions.'
            ),
            'verification': (
                'Only the LC_BUILD_VERSION SDK field and Info.plist SDK keys changed; '
                'minimum OS unchanged. LINE layout, rotation, keyboard and lifecycle '
                'behavior on iPhone Duo require real-device testing.'
            ),
        }
    if args.remove_ads or args.hide_promotional_tabs:
        manifest['ad_removal'] = {
            'loader_hooks': args.remove_ads,
            'known_ad_view_hiding': args.remove_ads,
            'network_blocking': args.remove_ads,
            'promotional_tab_filter': args.hide_promotional_tabs,
            'home_settings_shortcut': args.hide_promotional_tabs,
            'scope': [
                'GADAdLoader and GADBannerView request entry points',
                'Google IMA request/start entry points',
                'known LINE ad view class families',
                'VOOM, News, Shopping and Discover tab controllers',
            ],
            'verification': (
                'Static hook ABI checks and archive integrity passed; '
                'real-device UI and network behavior still require testing.'
            ),
            'promotional_tab_safety': (
                'Preserves the original controller and tab-item arrays. '
                'Uses a separate native UITabBar with copied non-promotional items '
                'for UIKit-managed widths, hit regions, selection effects and badges. '
                'Hides and disables interaction with the original bar, retaining '
                'its safe-area reservation. Mirrors source bar visibility/geometry '
                'changes and navigation hide-bottom-bar requests without waiting '
                'for user interaction. Scoped selection-setter guards skip '
                'promotional destinations; layout corrects a hidden selection '
                'that bypassed setters. No private button/lens geometry hooks. '
                'Native appearance and LINE swipe behavior require device testing.'
            ),
            'siri_compat': (
                'Returns no INVocabulary instance when the re-signed app lacks '
                'the com.apple.developer.siri entitlement; Siri integrations '
                'remain disabled instead of triggering an iOS 27 exception.'
            ),
        }
        if args.remove_ads:
            domains = load_ad_domains()
            manifest['ad_removal']['blocked_domains'] = domains
            manifest['ad_removal']['blocked_domains_sha256'] = digest(
                AD_DOMAIN_LIST.read_bytes()
            )
            manifest['ad_removal']['network_scope'] = (
                'NSURLProtocol plus NSURLSessionConfiguration injection and '
                'WKWebView top-level navigation blocking. Taboola suffixes are '
                'intentionally broad and can disable LINE News recommendations.'
            )
    if args.entry_only:
        manifest.update({
            'scope': (
                'Secondary-login entry and sticker-shop availability; no injected dylib or container/Keychain hooks.'
                if args.enable_sticker_shop else
                'Secondary-login entry only; no injected dylib or container/Keychain hooks.'
            ),
            'source_ipa': args.input.name,
            'output_ipa': args.output.name,
            'original_executable_sha256': digest(original),
            'patch': {'virtual_address': hex(profile.patch_va), 'file_offset': hex(profile.patch_offset),
                      'original_hex': profile.original.hex(), 'patched_hex': NOP.hex(),
                      'original_instruction': profile.instruction, 'patched_instruction': 'nop'},
            'changed_byte_offsets': [
                hex(i) for i, (a, b) in enumerate(zip(original, modified)) if a != b
            ],
            'verification': 'All other retained ZIP member contents identical; icon picker disabled; ZIP CRC and patch verification passed.',
        })
    elif args.primary_login:
        manifest.update({
            'scope': 'Primary-phone login branch preserved; no iPad secondary-login entry patch applied.',
            'source_ipa': args.input.name,
            'output_ipa': args.output.name,
            'patch': None,
            'verification': (
                'Original login branch preserved; all other documented Mach-O patches, '
                'injected dylib, and ZIP verification passed.'
            ),
        })
    args.output.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


def load_ad_domains(path=AD_DOMAIN_LIST):
    domains = tuple(
        line.strip().lower() for line in path.read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    )
    if not domains or len(domains) != len(set(domains)):
        raise ValueError('Advertising domain list is empty or contains duplicates.')
    if any(not scan_ad_domains.normalized_ad_domain(domain) == domain
           for domain in domains):
        raise ValueError('Advertising domain list contains an unrecognized domain.')
    return domains


def build_compat_dylib(args, info, original, patch_profile):
    build = ROOT / 'build'
    build.mkdir(exist_ok=True)
    build_labels = []
    if args.diagnostics:
        build_labels.append('keychain-compat' if args.keychain_compat else 'diagnostics')
    if args.remove_ads:
        build_labels.append('noads')
    if args.hide_promotional_tabs:
        build_labels.append('no-promotional-tabs')
    if args.tab_diagnostics:
        build_labels.append('tab-diagnostics')
    if args.iphone_duo:
        build_labels.append('iphone-duo')
    if args.primary_login:
        build_labels.append('primary-login')
    if build_labels:
        build = build / '-'.join(build_labels)
        build.mkdir(exist_ok=True)
    lib = build / LIB_NAME
    domain_header = build / 'NEINAdDomains.h'
    if args.remove_ads:
        domains = load_ad_domains()
        domain_header.write_text(scan_ad_domains.render_header(domains), encoding='utf-8')
    if args.keychain_compat:
        (build / 'NEINKeychainProfileData.h').write_text(
            analyze_patch_profile.render_keychain_header(patch_profile.keychain_profile),
            encoding='utf-8',
        )
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    subprocess.run(['xcrun', '--sdk', 'iphoneos', 'clang',
                    '-target', 'arm64-apple-ios' + info['MinimumOSVersion'],
                    '-isysroot', sdk, '-fobjc-arc', '-fblocks', '-O2', '-Wall', '-Wextra',
                    *(['-DNEIN_MULTI_DIAGNOSTICS=1'] if args.diagnostics else []),
                    *(['-DNEIN_MULTI_KEYCHAIN_COMPAT=1', '-framework', 'Security'] if args.keychain_compat else []),
                    *(['-DNEIN_MULTI_MESSAGE_DIAGNOSTICS=1'] if args.message_diagnostics else []),
                    *(['-DNEIN_MULTI_REMOVE_ADS=1']
                      if args.remove_ads else []),
                    *(['-DNEIN_MULTI_HIDE_PROMOTIONAL_TABS=1']
                      if args.hide_promotional_tabs else []),
                    *(['-DNEIN_MULTI_TAB_DIAGNOSTICS=1']
                      if args.tab_diagnostics else []),
                    *(['-DNEIN_MULTI_IPHONE_DUO=1']
                      if args.iphone_duo else []),
                    '-DNEIN_MULTI_ICON_PICKER=1',
                    '-dynamiclib', '-framework', 'Foundation',
                    '-framework', 'UIKit', '-framework', 'CoreGraphics',
                    *(['-framework', 'WebKit'] if args.remove_ads else []),
                    *(['-I', str(build)]
                      if args.remove_ads or args.keychain_compat else []),
                    '-Wl,-install_name,' + LOAD_PATH,
                    str(ROOT / 'hooks' / 'NEINHooks.m'), '-o', str(lib)], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', str(lib)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(lib)], check=True)
    lib_data = lib.read_bytes()
    # The load command requests version 0.0.0, matching the dylib's LC_ID_DYLIB.
    cursor = 32
    identity_checked = False
    for _ in range(struct.unpack_from('<I', lib_data, 16)[0]):
        cmd, size = struct.unpack_from('<II', lib_data, cursor)
        if cmd == 0xd:
            relative, _, current, compatibility = struct.unpack_from('<4I', lib_data, cursor + 8)
            name = lib_data[cursor + relative:cursor + size].split(b'\0')[0].decode()
            if name != LOAD_PATH or current != 0 or compatibility != 0:
                raise ValueError('Dylib identity/version differs from the injected load command')
            identity_checked = True
        cursor += size
    if not identity_checked:
        raise ValueError('Dylib identity command missing')
    return build, lib_data


if __name__ == '__main__':
    main()
