#!/usr/bin/env python3
"""Build a version-locked LINE secondary-login IPA.

Includes private App Group fallback unless --entry-only is selected.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zipfile

import analyze_patch_profile
import scan_ad_domains

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = 'Payload/LINE.app/LINE'
PLIST = 'Payload/LINE.app/Info.plist'
NOP = bytes.fromhex('1f2003d5')
LIB_NAME = 'LINEHooks.dylib'
LIB_ENTRY = 'Payload/LINE.app/Frameworks/' + LIB_NAME
LOAD_PATH = '@executable_path/Frameworks/' + LIB_NAME
APP_ROOT = 'Payload/LINE.app/'
REMOVED_ARCHIVE_PREFIXES = (
    'Payload/LINE.app/PlugIns/',
    'Payload/LINE.app/Watch/',
)
DEFAULT_BUNDLE_ID = 'kinta.ma.nein'
DEFAULT_APP_NAME = 'NEIN'
DEFAULT_ICON = 'design_simple_banana'
AD_DOMAIN_LIST = ROOT / 'ad_domains.txt'
PATCH_PROFILE_DIR = ROOT / 'patch_profiles'


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


def patched_info_plist(info, icon):
    result = dict(info)
    result['CFBundleIdentifier'] = DEFAULT_BUNDLE_ID
    result['CFBundleDisplayName'] = DEFAULT_APP_NAME
    result['CFBundleName'] = DEFAULT_APP_NAME
    for key in tuple(result):
        if key.startswith('CFBundleURLTypes'):
            del result[key]
    for key in ('CFBundleIcons', 'CFBundleIcons~ipad'):
        icon_config = info.get(key)
        if not icon_config:
            continue
        result[key] = dict(icon_config)
        primary_icon = icon_config.get('CFBundlePrimaryIcon', {})
        selected_icon = icon_config.get('CFBundleAlternateIcons', {}).get(
            icon, primary_icon if primary_icon.get('CFBundleIconName') == icon else None,
        )
        if not selected_icon:
            raise ValueError(f'Unknown app icon: {icon}')
        result[key]['CFBundlePrimaryIcon'] = dict(selected_icon)
    return plistlib.dumps(result, fmt=plistlib.FMT_XML, sort_keys=False)


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
    parser.add_argument('--icon', default=DEFAULT_ICON,
                        help=f'Use an embedded alternate app icon (default: {DEFAULT_ICON})')
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
    output_info = patched_info_plist(info, args.icon)
    build, lib_data = (
        (None, None) if args.entry_only
        else build_compat_dylib(args, info, original, profile)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.input) as source:
        names = source.namelist()
        if len(names) != len(set(names)) or (lib_data is not None and LIB_ENTRY in names):
            raise ValueError('Unexpected or duplicate archive member')
        entry_patched = (
            original if args.primary_login else
            patched_binary(original, profile, verify_hash=not args.allow_unverified)
        )
        modified, injection = (entry_patched, None) if args.entry_only else add_dylib(entry_patched)
        with zipfile.ZipFile(args.output, 'x') as target:
            target.comment = source.comment
            for entry in source.infolist():
                if is_removed_archive_member(entry.filename):
                    continue
                content = (
                    modified if entry.filename == EXECUTABLE else
                    output_info if entry.filename == PLIST else
                    source.read(entry)
                )
                target.writestr(entry, content)
            if lib_data is not None:
                entry = zipfile.ZipInfo(LIB_ENTRY, (2026, 9, 15, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100755 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(entry, lib_data)
    # Full round-trip comparison, excluding all embedded app extensions and the
    # Watch app whose bundle IDs cannot remain valid after the main app is re-signed.
    with zipfile.ZipFile(args.input) as source, zipfile.ZipFile(args.output) as target:
        retained_names = retained_archive_members(source.namelist())
        if target.namelist() != retained_names + ([LIB_ENTRY] if lib_data is not None else []):
            raise AssertionError('Unexpected member layout')
        for name in retained_names:
            expected = (
                modified if name == EXECUTABLE else
                output_info if name == PLIST else
                source.read(name)
            )
            if target.read(name) != expected:
                raise AssertionError('Unexpected changed member: ' + name)
        if (lib_data is not None and target.read(LIB_ENTRY) != lib_data) or target.testzip() is not None:
            raise AssertionError('Dylib or ZIP verification failed')
    expected_entry = profile.original if args.primary_login else NOP
    if modified[profile.patch_offset:profile.patch_offset + 4] != expected_entry:
        raise AssertionError('Login entry instruction differs from the selected mode.')
    start = int(injection['load_command_offset'], 16) if injection else 0
    end = start + injection['load_command_size'] if injection else 0
    changed = [i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
    allowed = ((injection is not None and (16 <= i < 24 or start <= i < end)) or
               profile.patch_offset <= i < profile.patch_offset + 4
               for i in changed)
    if len(modified) != len(original) or any(
            not allowed_change for allowed_change in allowed):
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
                'app_icon': args.icon,
                'url_schemes_removed': True,
                'message_diagnostics': args.message_diagnostics,
                'remove_ads': args.remove_ads,
                'hide_promotional_tabs': args.hide_promotional_tabs,
                'tab_diagnostics': args.tab_diagnostics,
                'source_ipa_sha256': digest(args.input.read_bytes()),
                'output_ipa_sha256': digest(args.output.read_bytes()),
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
                                 'one dylib was added; ZIP CRC passed; '
                                 'dylib ad hoc signature verified.')}
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
            'changed_byte_offsets': [hex(i) for i in changed],
            'verification': 'All other retained ZIP member contents identical; ZIP CRC and patch verification passed.',
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
    domain_header = build / 'LINEAdDomains.h'
    if args.remove_ads:
        domains = load_ad_domains()
        domain_header.write_text(scan_ad_domains.render_header(domains), encoding='utf-8')
    if args.keychain_compat:
        (build / 'LINEKeychainProfileData.h').write_text(
            analyze_patch_profile.render_keychain_header(patch_profile.keychain_profile),
            encoding='utf-8',
        )
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    subprocess.run(['xcrun', '--sdk', 'iphoneos', 'clang',
                    '-target', 'arm64-apple-ios' + info['MinimumOSVersion'],
                    '-isysroot', sdk, '-fobjc-arc', '-fblocks', '-O2', '-Wall', '-Wextra',
                    *(['-DLINE_MULTI_DIAGNOSTICS=1'] if args.diagnostics else []),
                    *(['-DLINE_MULTI_KEYCHAIN_COMPAT=1', '-framework', 'Security'] if args.keychain_compat else []),
                    *(['-DLINE_MULTI_MESSAGE_DIAGNOSTICS=1'] if args.message_diagnostics else []),
                    *(['-DLINE_MULTI_REMOVE_ADS=1']
                      if args.remove_ads else []),
                    *(['-DLINE_MULTI_HIDE_PROMOTIONAL_TABS=1']
                      if args.hide_promotional_tabs else []),
                    *(['-DLINE_MULTI_TAB_DIAGNOSTICS=1']
                      if args.tab_diagnostics else []),
                    '-dynamiclib', '-framework', 'Foundation',
                    *(['-framework', 'UIKit', '-framework', 'CoreGraphics']
                      if args.remove_ads or args.hide_promotional_tabs else []),
                    *(['-framework', 'WebKit'] if args.remove_ads else []),
                    *(['-I', str(build)]
                      if args.remove_ads or args.keychain_compat else []),
                    '-Wl,-install_name,' + LOAD_PATH,
                    str(ROOT / 'hooks' / 'LINEHooks.m'), '-o', str(lib)], check=True)
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
