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
)
DEFAULT_BUNDLE_ID = 'kinta.ma.nein'
DEFAULT_APP_NAME = 'NEIN'
DEFAULT_ICON = 'design_simple_banana'
AD_DOMAIN_LIST = ROOT / 'ad_domains.txt'
PATCH_PROFILE_DIR = ROOT / 'patch_profiles'

# LINE 26.14.0 (2026.828.1845), executable UUID
# 0BAB483C-CA85-38CE-8984-0C20C92511E4. FriendTabViewModel initializes its
# isSectionExpanded dictionary with only the friend case set to true. Set that
# initial value to false in both dictionary insertion paths; later user-driven
# updates remain unchanged.
FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS = (0x3392A18, 0x3392A28)
FRIEND_TAB_DEFAULT_EXPANDED_ORIGINAL = bytes.fromhex('e8179f1a')  # cset w8, eq
FRIEND_TAB_COLLAPSED = bytes.fromhex('08008052')  # mov w8, #0


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
    return (
        name.startswith(REMOVED_ARCHIVE_PREFIXES) or
        (name.startswith(APP_ROOT) and '.appex/' in name)
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


def patched_info_plist(info, enable_icon_picker=False):
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


def patch_friend_tab_default_collapsed(binary, verify_hash=True):
    if verify_hash and digest(binary) != (
            '5da134826db5a5b51a20a297fb1b205c2f6f2adcf87e227b6d60f3070cebdd39'):
        raise ValueError('Executable SHA-256 mismatch: expected the known-good NEIN executable.')
    if len(binary) < max(FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS) + 4 or \
            struct.unpack_from('<I', binary)[0] != 0xFEEDFACF:
        raise ValueError('Expected the verified thin ARM64 NEIN executable.')
    result = bytearray(binary)
    for offset in FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS:
        if binary[offset:offset + 4] != FRIEND_TAB_DEFAULT_EXPANDED_ORIGINAL:
            raise ValueError('Expected FriendTabViewModel initial expansion instruction not found.')
        result[offset:offset + 4] = FRIEND_TAB_COLLAPSED
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
                        help='Hide VOOM, News and Shopping tab buttons (verified on 26.14.0; experimental on 26.15.1)')
    parser.add_argument('--tab-diagnostics', action='store_true',
                        help='Add a tab-only JSON export button; requires --hide-promotional-tabs')
    parser.add_argument('--collapse-friends-on-launch', action='store_true',
                        help='Initialize the Friends section as collapsed')
    parser.add_argument('--allow-unverified', action='store_true',
                        help='Allow a different executable hash for a known version/build; still checks the original ARM64 instruction')
    args = parser.parse_args(argv)
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
    output_info = patched_info_plist(info, enable_icon_picker=not args.entry_only)
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
            modified = patch_friend_tab_default_collapsed(modified, verify_hash=False)
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
    # Full round-trip comparison, excluding all embedded app extensions and the
    # Watch app whose bundle IDs cannot remain valid after the main app is re-signed.
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
    if len(modified) != len(original) or any(
            a != b and not (
                (injection is not None and (16 <= i < 24 or start <= i < end)) or
                profile.patch_offset <= i < profile.patch_offset + 4 or
                (args.collapse_friends_on_launch and
                 any(offset <= i < offset + 4
                     for offset in FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS))
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
                'message_diagnostics': args.message_diagnostics,
                'remove_ads': args.remove_ads,
                'hide_promotional_tabs': args.hide_promotional_tabs,
                'collapse_friends_on_launch': args.collapse_friends_on_launch,
                'tab_diagnostics': args.tab_diagnostics,
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
                                 'and documented Mach-O patches; all embedded app extensions and the Watch app were removed; '
                                 'one dylib and verified icon preview assets were added; ZIP CRC passed; '
                                 'dylib ad hoc signature verified.')}
    if args.collapse_friends_on_launch:
        manifest['home_friends'] = {
            'mode': 'friend_tab_default_collapsed',
            'view_model': 'LineHomeTab.FriendTabViewModel',
            'state_field': 'isSectionExpanded',
            'friend_case': 5,
            'patch_offsets': [hex(offset) for offset in FRIEND_TAB_DEFAULT_EXPANDED_OFFSETS],
            'manual_toggle_preserved': True,
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
                'VOOM, News and Shopping tab controllers',
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
            'scope': 'Secondary-login entry only; no injected dylib or container/Keychain hooks.',
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
