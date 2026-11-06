#!/usr/bin/env python3
"""Analyze an IPA and persist one combined LINE patch profile."""
import argparse
import bisect
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import tempfile
import zipfile

EXECUTABLE = 'Payload/LINE.app/LINE'
PLIST = 'Payload/LINE.app/Info.plist'
LOGIN_PROFILE_SCHEMA_VERSION = 1
NOP = 0xD503201F
REFERENCE_BRANCH_INDEX = 12
REFERENCE_WINDOW_START = -12
REFERENCE_WINDOW_END = 17
REFERENCE_WINDOW = (
    0xA90457F6, 0xA9054FF4, 0xA9067BFD, 0x910183FD, 0xAA1403F3,
    0xAA0203F5, 0xAA0103F6, 0xAA0003F7, 0xD2800000, 0x94000000,
    0xAA0003F4, 0x94000000, 0x36000000, 0xD2800000, 0x94000000,
    0x94000000, 0x94000000, 0x94000000, 0xAA0003F8, 0x120002E1,
    0xAA1603E2, 0xAA1503E3, 0xAA1303F4, 0x94000000, 0x90000008,
    0xF9441908, 0xB100051F, 0x54000000, 0x90000000,
)
MIN_MATCH_SCORE = 0.95
MIN_MATCH_MARGIN = 0.12


@dataclass(frozen=True)
class MachOImage:
    image_base: int
    text_address: int
    text_offset: int
    text_size: int
    function_starts: tuple[int, ...]


@dataclass(frozen=True)
class Candidate:
    file_offset: int
    virtual_address: int
    instruction: str
    original_hex: str
    target_address: int
    target_kind: str
    function_start: int
    function_offset: int
    similarity: float
    prefix: tuple[str, ...]
    destination: tuple[str, ...]


def _bounded(data, offset, size, label):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f'Invalid Mach-O {label} range.')
    return data[offset:offset + size]


def _decode_uleb128(data, cursor):
    value = 0
    shift = 0
    while cursor < len(data):
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7
        if shift >= 64:
            break
    raise ValueError('Malformed LC_FUNCTION_STARTS ULEB128 data.')


def parse_arm64_macho(data):
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Expected a thin little-endian 64-bit Mach-O.')

    cpu_type = struct.unpack_from('<I', data, 4)[0]
    if cpu_type != 0x0100000C:
        raise ValueError('Expected an ARM64 Mach-O executable.')

    command_count, command_size = struct.unpack_from('<II', data, 16)
    command_end = 32 + command_size
    if command_end > len(data):
        raise ValueError('Mach-O load commands exceed the executable size.')

    cursor = 32
    image_base = None
    text_section = None
    function_starts_command = None
    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise ValueError('Truncated Mach-O load command.')
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > command_end:
            raise ValueError('Invalid Mach-O load-command size.')
        if command == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise ValueError('Truncated LC_SEGMENT_64 command.')
            section_count = struct.unpack_from('<I', data, cursor + 64)[0]
            expected_size = 72 + section_count * 80
            if expected_size > size:
                raise ValueError('Invalid Mach-O section table.')
            segment_name = data[cursor + 8:cursor + 24].split(b'\0', 1)[0]
            if segment_name == b'__TEXT':
                image_base = struct.unpack_from('<Q', data, cursor + 24)[0]
            section_cursor = cursor + 72
            for _ in range(section_count):
                section_name = data[section_cursor:section_cursor + 16].split(b'\0', 1)[0]
                segment_name = data[section_cursor + 16:section_cursor + 32].split(b'\0', 1)[0]
                address, section_size = struct.unpack_from('<QQ', data, section_cursor + 32)
                file_offset = struct.unpack_from('<I', data, section_cursor + 48)[0]
                if (segment_name, section_name) == (b'__TEXT', b'__text'):
                    text_section = (address, section_size, file_offset)
                section_cursor += 80
        elif command == 0x26:  # LC_FUNCTION_STARTS
            if size < 16:
                raise ValueError('Truncated LC_FUNCTION_STARTS command.')
            function_starts_command = struct.unpack_from('<II', data, cursor + 8)
        cursor += size
    if cursor != command_end:
        raise ValueError('Mach-O load-command size mismatch.')
    if image_base is None or text_section is None or function_starts_command is None:
        raise ValueError('Mach-O is missing __text or LC_FUNCTION_STARTS metadata.')

    text_address, text_size, text_offset = text_section
    _bounded(data, text_offset, text_size, '__text')
    starts_offset, starts_size = function_starts_command
    encoded_starts = _bounded(data, starts_offset, starts_size, 'function starts')
    starts = []
    address = image_base
    cursor = 0
    while cursor < len(encoded_starts):
        delta, cursor = _decode_uleb128(encoded_starts, cursor)
        if delta == 0:
            break
        address += delta
        starts.append(address)
    if not starts:
        raise ValueError('Mach-O has no function-start entries.')
    text_end = text_address + text_size
    if any(start < text_address or start >= text_end for start in starts):
        raise ValueError('LC_FUNCTION_STARTS contains an entry outside __text.')
    if starts != sorted(set(starts)):
        raise ValueError('LC_FUNCTION_STARTS entries are not strictly increasing.')
    return MachOImage(image_base, text_address, text_offset, text_size, tuple(starts))


def _sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def _decode_branch(instruction, address):
    if instruction & 0x7E000000 == 0x34000000:  # CBZ / CBNZ
        is_nonzero = bool(instruction & 0x01000000)
        width = 64 if instruction & 0x80000000 else 32
        register = instruction & 0x1F
        immediate = _sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2
        return (
            f'{"cbnz" if is_nonzero else "cbz"} {("x" if width == 64 else "w")}{register}',
            address + immediate,
            'nonzero' if is_nonzero else 'zero',
        )
    if instruction & 0x7E000000 == 0x36000000:  # TBZ / TBNZ
        is_nonzero = bool(instruction & 0x01000000)
        bit = ((instruction >> 19) & 0x1F) | (((instruction >> 31) & 1) << 5)
        width = 64 if bit >= 32 else 32
        register = instruction & 0x1F
        immediate = _sign_extend((instruction >> 5) & 0x3FFF, 14) << 2
        return (
            f'{"tbnz" if is_nonzero else "tbz"} {("x" if width == 64 else "w")}{register}, #{bit}',
            address + immediate,
            'nonzero' if is_nonzero else 'zero',
        )
    if instruction & 0xFF000010 == 0x54000000:  # B.cond
        condition = (
            'eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
            'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv',
        )[instruction & 0xF]
        immediate = _sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2
        return f'b.{condition}', address + immediate, condition
    return None


def _format_instruction(instruction, address):
    branch = _decode_branch(instruction, address)
    if branch:
        mnemonic, target, _ = branch
        return f'{mnemonic}, 0x{target:x}'
    if instruction == NOP:
        return 'nop'
    if instruction & 0xFC000000 == 0x94000000:  # BL
        immediate = _sign_extend(instruction & 0x03FFFFFF, 26) << 2
        return f'bl 0x{address + immediate:x}'
    if instruction & 0xFC000000 == 0x14000000:  # B
        immediate = _sign_extend(instruction & 0x03FFFFFF, 26) << 2
        return f'b 0x{address + immediate:x}'
    if instruction & 0xFFE0001F == 0xD4200000:  # BRK
        return f'brk #{(instruction >> 5) & 0xFFFF}'
    return f'.word 0x{instruction:08x}'


def _normalize_login_instruction(instruction):
    if instruction & 0xFC000000 in (0x94000000, 0x14000000):  # BL / B
        return instruction & 0xFC000000
    if instruction & 0xFF000010 == 0x54000000:  # B.cond
        return instruction & 0xFF00001F
    if instruction & 0x7E000000 == 0x34000000:  # CBZ / CBNZ
        return instruction & 0xFF00001F
    if instruction & 0x7E000000 == 0x36000000:  # TBZ / TBNZ
        return instruction & 0xFFF8001F
    if instruction & 0x9F000000 in (0x90000000, 0x10000000):  # ADRP / ADR
        return instruction & 0x9F00001F
    return instruction


def locate_login_branch(data, image, context_instructions=4, limit=100):
    text = _bounded(data, image.text_offset, image.text_size, '__text')
    end = image.text_address + image.text_size
    candidates = []
    function_index = 0
    branch_count = 0
    window_before = -REFERENCE_WINDOW_START
    window_after = REFERENCE_WINDOW_END - 1
    for relative in range(0, len(text) - 3, 4):
        instruction = struct.unpack_from('<I', text, relative)[0]
        address = image.text_address + relative
        decoded = _decode_branch(instruction, address)
        if not decoded or decoded[0] != 'tbz w0, #0':
            continue
        branch_count += 1
        mnemonic, target, target_kind = decoded
        while (
            function_index + 1 < len(image.function_starts)
            and image.function_starts[function_index + 1] <= address
        ):
            function_index += 1
        start = image.function_starts[function_index]
        function_end = (
            image.function_starts[function_index + 1]
            if function_index + 1 < len(image.function_starts)
            else end
        )
        if (
            address - window_before * 4 < start or
            address + window_after * 4 >= function_end or
            not start <= target < function_end
        ):
            continue
        target_instruction = struct.unpack_from(
            '<I', data, image.text_offset + target - image.text_address,
        )[0]
        if target_instruction & 0xFFE0001F == 0xD4200000:  # BRK
            continue
        normalized = tuple(
            _normalize_login_instruction(
                struct.unpack_from(
                    '<I', text, relative + index * 4,
                )[0],
            )
            for index in range(REFERENCE_WINDOW_START, REFERENCE_WINDOW_END)
        )
        similarity = SequenceMatcher(
            None, REFERENCE_WINDOW, normalized, autojunk=False,
        ).ratio()
        prefix_start = max(start, address - context_instructions * 4)
        prefix = tuple(
            _format_instruction(
                struct.unpack_from('<I', data, image.text_offset + item - image.text_address)[0],
                item,
            )
            for item in range(prefix_start, address, 4)
        )
        destination = tuple(
            _format_instruction(
                struct.unpack_from('<I', data, image.text_offset + item - image.text_address)[0],
                item,
            )
            for item in range(
                target, min(target + context_instructions * 4, function_end), 4,
            )
        )
        candidates.append(Candidate(
            file_offset=image.text_offset + relative,
            virtual_address=address,
            instruction=mnemonic,
            original_hex=struct.pack('<I', instruction).hex(),
            target_address=target,
            target_kind=target_kind,
            function_start=start,
            function_offset=address - start,
            similarity=similarity,
            prefix=prefix,
            destination=destination,
        ))
    candidates.sort(key=lambda candidate: (-candidate.similarity, candidate.file_offset))
    high_confidence_count = sum(
        candidate.similarity >= MIN_MATCH_SCORE for candidate in candidates
    )
    return branch_count, len(candidates), high_confidence_count, candidates[:limit]


def analyze_login_executable(executable, version=None, build=None, context_instructions=4):
    image = parse_arm64_macho(executable)
    branch_count, candidate_count, high_confidence_count, candidates = locate_login_branch(
        executable, image, context_instructions,
    )
    best = candidates[0] if candidates else None
    next_score = candidates[1].similarity if len(candidates) > 1 else 0.0
    recommended = (
        best is not None and
        best.similarity >= MIN_MATCH_SCORE and
        best.similarity - next_score >= MIN_MATCH_MARGIN
    )
    return {
        'mode': 'analysis_only',
        'version': version,
        'build': build,
        'executable_sha256': hashlib.sha256(executable).hexdigest(),
        'executable_size': len(executable),
        'scanned_tbz_w0_branches': branch_count,
        'structural_candidate_count': candidate_count,
        'high_confidence_candidate_count': high_confidence_count,
        'recommended_patch_offset': (
            hex(best.file_offset) if recommended else None
        ),
        'best_similarity': best.similarity if best else None,
        'best_margin': best.similarity - next_score if best else None,
        'automatic_patch': False,
        'reason': (
            'The analyzer compares a normalized ARM64 instruction window around the '
            'verified 26.14.0 login branch. A unique high-confidence match is a patch '
            'candidate, not proof of runtime behavior; test the resulting app before '
            'using it with an account.'
        ),
        'candidates': [asdict(item) for item in candidates],
    }


def analyze_login_ipa(path, context_instructions=4):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP entry names are not supported.')
        info = plistlib.loads(archive.read(PLIST))
        if info.get('CFBundleIdentifier') != 'jp.naver.line':
            raise ValueError('Expected the original jp.naver.line bundle identifier.')
        executable = archive.read(EXECUTABLE)
    result = analyze_login_executable(
        executable,
        info.get('CFBundleShortVersionString'),
        info.get('CFBundleVersion'),
        context_instructions,
    )
    result['ipa'] = str(path)
    return result


def profile_document(result):
    offset = result.get('recommended_patch_offset')
    if offset is None:
        raise ValueError('No high-confidence login patch candidate to save.')
    candidates = result.get('candidates', ())
    candidate = next(
        (item for item in candidates if item.get('file_offset') == int(offset, 16)),
        None,
    )
    if candidate is None:
        raise ValueError('Recommended candidate is missing from the analysis report.')
    original_hex = candidate.get('original_hex', '')
    if len(bytes.fromhex(original_hex)) != 4:
        raise ValueError('Recommended candidate does not contain one ARM64 instruction.')
    instruction = struct.unpack('<I', bytes.fromhex(original_hex))[0]
    branch = _decode_branch(instruction, candidate['virtual_address'])
    if (
        not branch or branch[0] != candidate['instruction'] or
        branch[1] != candidate['target_address']
    ):
        raise ValueError('Recommended candidate instruction failed profile validation.')
    return {
        'schema_version': LOGIN_PROFILE_SCHEMA_VERSION,
        'bundle_identifier': 'jp.naver.line',
        'version': result['version'],
        'build': result['build'],
        'executable_sha256': result['executable_sha256'],
        'architecture': 'arm64',
        'patch': {
            'kind': 'secondary_login_entry_branch',
            'file_offset': offset,
            'virtual_address': hex(candidate['virtual_address']),
            'target_address': hex(candidate['target_address']),
            'instruction': (
                f"{candidate['instruction']}, "
                f"0x{candidate['target_address']:x}"
            ),
            'original_hex': original_hex,
            'patched_hex': struct.pack('<I', NOP).hex(),
        },
    }



KEYCHAIN_PROFILE_SCHEMA_VERSION = 1
REFERENCE_VERSION = '26.14.0'

OPERATIONS = {
    'add': '_SecItemAdd',
    'copy': '_SecItemCopyMatching',
    'delete': '_SecItemDelete',
    'update': '_SecItemUpdate',
}
AUTHENTICATION_METHODS = {
    'saveToKeychainData:forQuery:': ('add', 'add', 'update'),
    'dataFromKeychainForQuery:errorCode:': ('copy',),
    'deleteFromKeychainWithQuery:': ('delete', 'delete'),
}

# These are used only to bootstrap the checked-in 26.14.0 reference signatures.
REFERENCE_FUNCTION_RANGES = (
    (0x3d63390, 0x3d636fc, ('copy',)),
    (0x3d638b4, 0x3d63b4c, ('delete',)),
    (0x3d63b4c, 0x3d64078, ('update', 'add')),
)
MIN_E2EE_MATCH_SCORE = 0.70
MIN_E2EE_MATCH_MARGIN = 0.15


@dataclass(frozen=True)
class Section:
    segment: str
    name: str
    address: int
    size: int
    file_offset: int
    flags: int
    reserved1: int
    reserved2: int


@dataclass(frozen=True)
class Image:
    data: bytes
    image_base: int
    text_address: int
    text_offset: int
    text_size: int
    function_starts: tuple[int, ...]
    uuid: bytes
    sections: tuple[Section, ...]
    segments: tuple[tuple[int, int, int, int], ...]
    symbol_table: tuple[int, int, int, int]
    indirect_symbol_table: tuple[int, int]

    def file_offset(self, address):
        for vm_address, _, file_offset, file_size in self.segments:
            if vm_address <= address < vm_address + file_size:
                return file_offset + address - vm_address
        raise ValueError(f'Address is not file-backed: {address:#x}')

    def section(self, name, segment=None):
        matches = [
            item for item in self.sections
            if item.name == name and (segment is None or item.segment == segment)
        ]
        if len(matches) != 1:
            raise ValueError(
                f'Expected one {segment or "*"} section named {name}, '
                f'found {len(matches)}.'
            )
        return matches[0]


def parse_image(data):
    parsed = parse_arm64_macho(data)
    command_count, command_size = struct.unpack_from('<II', data, 16)
    command_end = 32 + command_size
    cursor = 32
    uuid = None
    symbol_table = None
    dysymtab = None
    sections = []
    segments = []

    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise ValueError('Truncated Mach-O load command.')
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > command_end:
            raise ValueError('Invalid Mach-O load-command size.')
        if command == 0x1b:  # LC_UUID
            if size < 24:
                raise ValueError('Truncated LC_UUID.')
            uuid = data[cursor + 8:cursor + 24]
        elif command == 0x2:  # LC_SYMTAB
            if size < 24:
                raise ValueError('Truncated LC_SYMTAB.')
            symbol_table = struct.unpack_from('<IIII', data, cursor + 8)
        elif command == 0xb:  # LC_DYSYMTAB
            if size < 80:
                raise ValueError('Truncated LC_DYSYMTAB.')
            fields = struct.unpack_from('<18I', data, cursor + 8)
            dysymtab = (fields[12], fields[13])
        elif command == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise ValueError('Truncated LC_SEGMENT_64.')
            segment_name = data[cursor + 8:cursor + 24].split(b'\0', 1)[0].decode()
            vm_address, vm_size, file_offset, file_size = struct.unpack_from(
                '<QQQQ', data, cursor + 24,
            )
            segments.append((vm_address, vm_size, file_offset, file_size))
            section_count = struct.unpack_from('<I', data, cursor + 64)[0]
            if 72 + section_count * 80 > size:
                raise ValueError('Invalid Mach-O section table.')
            section_cursor = cursor + 72
            for _ in range(section_count):
                section_name = data[section_cursor:section_cursor + 16].split(
                    b'\0', 1,
                )[0].decode()
                section_segment = data[section_cursor + 16:section_cursor + 32].split(
                    b'\0', 1,
                )[0].decode()
                address, section_size = struct.unpack_from(
                    '<QQ', data, section_cursor + 32,
                )
                file_offset, _, _, _, flags, reserved1, reserved2, _ = (
                    struct.unpack_from('<IIIIIIII', data, section_cursor + 48)
                )
                sections.append(Section(
                    section_segment, section_name, address, section_size,
                    file_offset, flags, reserved1, reserved2,
                ))
                section_cursor += 80
        cursor += size

    if (
        uuid is None or symbol_table is None or dysymtab is None or
        cursor != command_end
    ):
        raise ValueError('Mach-O is missing UUID or import symbol metadata.')
    return Image(
        data=data,
        image_base=parsed.image_base,
        text_address=parsed.text_address,
        text_offset=parsed.text_offset,
        text_size=parsed.text_size,
        function_starts=parsed.function_starts,
        uuid=uuid,
        sections=tuple(sections),
        segments=tuple(segments),
        symbol_table=symbol_table,
        indirect_symbol_table=dysymtab,
    )


def _symbol_names(image):
    symbol_offset, symbol_count, string_offset, string_size = image.symbol_table
    indirect_offset, indirect_count = image.indirect_symbol_table
    if (
        symbol_offset + symbol_count * 16 > len(image.data) or
        string_offset + string_size > len(image.data) or
        indirect_offset + indirect_count * 4 > len(image.data)
    ):
        raise ValueError('Mach-O symbol table exceeds the executable size.')
    result = {}
    for section in image.sections:
        if section.name not in ('__stubs', '__got'):
            continue
        entry_size = section.reserved2 if section.name == '__stubs' else 8
        if not entry_size or section.size % entry_size:
            raise ValueError(f'Invalid {section.name} entry size.')
        first = section.reserved1
        count = section.size // entry_size
        if first + count > indirect_count:
            raise ValueError(f'{section.name} indirect symbols exceed the table.')
        for index in range(count):
            symbol_index = struct.unpack_from(
                '<I', image.data, indirect_offset + (first + index) * 4,
            )[0]
            if symbol_index & 0xc0000000:
                continue
            if symbol_index >= symbol_count:
                raise ValueError('Invalid Mach-O indirect symbol index.')
            string_index = struct.unpack_from(
                '<I', image.data, symbol_offset + symbol_index * 16,
            )[0]
            if string_index >= string_size:
                raise ValueError('Invalid Mach-O symbol string index.')
            start = string_offset + string_index
            end = image.data.find(b'\0', start, string_offset + string_size)
            if end < 0:
                raise ValueError('Unterminated Mach-O symbol name.')
            name = image.data[start:end].decode('ascii', 'replace')
            if name in OPERATIONS.values():
                result.setdefault((section.name, name), []).append(
                    section.address + index * entry_size,
                )
    return result


def _resolve_imports(image):
    symbols = _symbol_names(image)
    stubs = {}
    got = {}
    for operation, name in OPERATIONS.items():
        stub_values = symbols.get(('__stubs', name), [])
        got_values = symbols.get(('__got', name), [])
        if len(stub_values) != 1 or len(got_values) != 1:
            raise ValueError(
                f'Expected one stub and GOT slot for {name}, '
                f'found {len(stub_values)} and {len(got_values)}.'
            )
        stubs[operation] = stub_values[0]
        got[operation] = got_values[0]
    ordered = [got[name] for name in ('add', 'copy', 'delete', 'update')]
    if ordered != list(range(ordered[0], ordered[0] + 4 * 8, 8)):
        raise ValueError('SecItem GOT slots are not a contiguous four-entry group.')
    got_section = image.section('__got', '__DATA_CONST')
    if not (
        got_section.address <= ordered[0] and
        ordered[0] + 4 * 8 <= got_section.address + got_section.size
    ):
        raise ValueError('SecItem GOT slots fall outside __DATA_CONST,__got.')
    return stubs, got


def _decode_image_pointer(raw, image):
    # Chained fixups in these arm64 LINE images store image-relative pointers
    # in the low 36 bits; the high bits are tag/authentication metadata.
    relative = raw & ((1 << 36) - 1)
    return image.image_base + relative


def _cstring(address, image):
    offset = image.file_offset(address)
    end = image.data.find(b'\0', offset, min(len(image.data), offset + 1024))
    if end < 0:
        raise ValueError('Unterminated Objective-C string.')
    return image.data[offset:end].decode('utf-8', 'replace')


def _objc_methods(image, target_class='NLAuthenticationManager'):
    classlist = image.section('__objc_classlist', '__DATA_CONST')
    methods = []
    class_count = classlist.size // 8
    if classlist.size % 8:
        raise ValueError('Invalid __objc_classlist size.')
    for index in range(class_count):
        class_offset = classlist.file_offset + index * 8
        raw_class = struct.unpack_from('<Q', image.data, class_offset)[0]
        if raw_class == 0:
            continue
        class_address = _decode_image_pointer(raw_class, image)
        class_offset = image.file_offset(class_address)
        metaclass_raw = struct.unpack_from('<Q', image.data, class_offset)[0]
        if not metaclass_raw:
            continue
        for is_class_method in (False, True):
            object_address = (
                _decode_image_pointer(metaclass_raw, image)
                if is_class_method else class_address
            )
            object_offset = image.file_offset(object_address)
            data_bits = struct.unpack_from('<Q', image.data, object_offset + 32)[0]
            data_address = _decode_image_pointer(data_bits & ~7, image)
            data_offset = image.file_offset(data_address)
            name_raw = struct.unpack_from('<Q', image.data, data_offset + 24)[0]
            class_name = _cstring(_decode_image_pointer(name_raw, image), image)
            if class_name != target_class:
                continue
            method_raw = struct.unpack_from('<Q', image.data, data_offset + 32)[0]
            if not method_raw:
                continue
            method_address = _decode_image_pointer(method_raw, image)
            method_offset = image.file_offset(method_address)
            flags, count = struct.unpack_from('<II', image.data, method_offset)
            entry_size = flags & 0xffff
            if entry_size < 12 or count > 512:
                raise ValueError(f'Invalid {target_class} method list.')
            if method_offset + 8 + count * entry_size > len(image.data):
                raise ValueError('Objective-C method list exceeds the executable.')
            for method_index in range(count):
                entry_address = method_address + 8 + method_index * entry_size
                entry_offset = image.file_offset(entry_address)
                name_relative, _, implementation_relative = struct.unpack_from(
                    '<iii', image.data, entry_offset,
                )
                selector_ref = entry_address + name_relative
                selector_raw = struct.unpack_from(
                    '<Q', image.data, image.file_offset(selector_ref),
                )[0]
                selector = _cstring(_decode_image_pointer(selector_raw, image), image)
                implementation = entry_address + 8 + implementation_relative
                methods.append({
                    'class': class_name,
                    'is_class_method': is_class_method,
                    'selector': selector,
                    'implementation': implementation,
                })
    return methods


def _function_bounds(address, image):
    index = bisect.bisect_right(image.function_starts, address) - 1
    if index < 0:
        raise ValueError(f'No function start for address {address:#x}.')
    start = image.function_starts[index]
    end = (
        image.function_starts[index + 1]
        if index + 1 < len(image.function_starts)
        else image.text_address + image.text_size
    )
    if not start <= address < end:
        raise ValueError(f'Address is outside its function: {address:#x}.')
    return start, end


def _function_calls(image, start, end, stubs):
    calls = []
    begin = image.text_offset + start - image.text_address
    finish = image.text_offset + end - image.text_address
    text = image.data[begin:finish]
    if len(text) % 4:
        raise ValueError('Function size is not ARM64 instruction aligned.')
    for match in re.finditer(rb'[\x94-\x97]', text[3::4]):
        instruction_offset = match.start() * 4
        instruction = struct.unpack_from('<I', text, instruction_offset)[0]
        if instruction & 0xfc000000 != 0x94000000:
            continue
        immediate = instruction & 0x03ffffff
        if immediate & 0x02000000:
            immediate -= 0x04000000
        target = start + instruction_offset + (immediate << 2)
        operation = next(
            (name for name, address in stubs.items()
             if address == target),
            None,
        )
        if operation:
            calls.append({
                'operation': operation,
                'return_offset': hex(
                    start + instruction_offset + 4 - image.image_base
                ),
            })
    return calls


def _authentication_sites(image, stubs):
    method_map = {}
    for method in _objc_methods(image):
        if not method['is_class_method'] or method['selector'] not in AUTHENTICATION_METHODS:
            continue
        selector = method['selector']
        if selector in method_map:
            raise ValueError(f'Duplicate authentication selector: {selector}')
        start, end = _function_bounds(method['implementation'], image)
        calls = _function_calls(image, start, end, stubs)
        operations = tuple(item['operation'] for item in calls)
        if operations != AUTHENTICATION_METHODS[selector]:
            raise ValueError(
                f'Unexpected Keychain operations in {selector}: {operations}'
            )
        method_map[selector] = calls
    if set(method_map) != set(AUTHENTICATION_METHODS):
        missing = sorted(set(AUTHENTICATION_METHODS) - set(method_map))
        raise ValueError(f'Missing authentication Keychain selectors: {missing}')
    return [
        {
            **call,
            'class': 'NLAuthenticationManager',
            'selector': selector,
        }
        for selector in AUTHENTICATION_METHODS
        for call in method_map[selector]
    ]


def _normalize_keychain_instruction(instruction):
    if instruction & 0xfc000000 == 0x94000000:  # BL
        return instruction & 0xfc000000
    if instruction & 0x9f000000 in (0x90000000, 0x10000000):  # ADR / ADRP
        return instruction & 0x9f00001f
    if instruction & 0x7f000000 == 0x11000000:  # ADD / SUB immediate
        return instruction & 0x7f0003ff
    if instruction & 0x3b000000 == 0x39000000:  # Unsigned LDR / STR
        return instruction & 0xffc003ff
    return _normalize_login_instruction(instruction)


def _normalized_function(image, bounds):
    start, end = bounds
    offset = image.text_offset + start - image.text_address
    code = image.data[offset:offset + end - start]
    if not code or len(code) % 4:
        raise ValueError('Invalid E2EE function instruction range.')
    return tuple(
        _normalize_keychain_instruction(word)
        for (word,) in struct.iter_unpack('<I', code)
    )


def _reference_anchors(image, stubs):
    anchors = []
    for start_offset, end_offset, expected_ops in REFERENCE_FUNCTION_RANGES:
        start = image.image_base + start_offset
        end = image.image_base + end_offset
        if start not in image.function_starts:
            raise ValueError(f'Unknown reference E2EE function start: {start:#x}.')
        calls = _function_calls(image, start, end, stubs)
        operations = tuple(item['operation'] for item in calls)
        if operations != expected_ops:
            raise ValueError(
                f'Unexpected Keychain calls in reference E2EE function '
                f'{start_offset:#x}: {operations}'
            )
        anchors.append({
            'operations': list(expected_ops),
            'instructions': list(_normalized_function(image, (start, end))),
        })
    return anchors


def _candidate_e2ee_functions(image, stubs):
    calls_by_function = {}
    for match in re.finditer(rb'[\x94-\x97]', image.data[image.text_offset + 3:
                                                       image.text_offset + image.text_size:4]):
        relative = match.start() * 4
        instruction = struct.unpack_from(
            '<I', image.data, image.text_offset + relative,
        )[0]
        if instruction & 0xfc000000 != 0x94000000:
            continue
        immediate = instruction & 0x03ffffff
        if immediate & 0x02000000:
            immediate -= 0x04000000
        address = image.text_address + relative
        target = address + (immediate << 2)
        operation = next(
            (name for name, stub in stubs.items() if stub == target), None,
        )
        if operation is None:
            continue
        start, end = _function_bounds(address, image)
        key = (start, end)
        calls_by_function.setdefault(key, []).append({
            'operation': operation,
            'return_offset': hex(address + 4 - image.image_base),
        })
    return calls_by_function


def _match_e2ee_anchors(image, stubs, anchors):
    functions = _candidate_e2ee_functions(image, stubs)
    available = {
        bounds: calls
        for bounds, calls in functions.items()
    }
    selected = []
    for anchor in anchors:
        expected_operations = tuple(anchor['operations'])
        reference_instructions = anchor['instructions']
        candidates = []
        for bounds, calls in available.items():
            if tuple(item['operation'] for item in calls) != expected_operations:
                continue
            instructions = _normalized_function(image, bounds)
            score = SequenceMatcher(
                None, reference_instructions, instructions, autojunk=False,
            ).ratio()
            candidates.append((score, bounds, calls))
        candidates.sort(key=lambda item: (-item[0], item[1][0]))
        if not candidates:
            raise ValueError(
                f'No E2EE function matches operations {expected_operations}.'
            )
        best = candidates[0]
        next_score = candidates[1][0] if len(candidates) > 1 else 0.0
        if (
            best[0] < MIN_E2EE_MATCH_SCORE or
            best[0] - next_score < MIN_E2EE_MATCH_MARGIN
        ):
            raise ValueError(
                f'Ambiguous E2EE function match for {expected_operations}; '
                'refusing to create a profile.'
            )
        selected.append(best[2])
        del available[best[1]]
    return [item for group in selected for item in group]


def analyze_keychain_executable(executable, version, build, reference_profile=None):
    image = parse_image(executable)
    stubs, got = _resolve_imports(image)
    authentication_sites = _authentication_sites(image, stubs)
    if image.uuid.hex() == '0bab483cca8538ce89840c20c92511e4':
        anchors = _reference_anchors(image, stubs)
        e2ee_sites = [
            call
            for start, end, _ in REFERENCE_FUNCTION_RANGES
            for call in _function_calls(
                image,
                image.image_base + start,
                image.image_base + end,
                stubs,
            )
        ]
    else:
        if reference_profile is None:
            raise ValueError(
                'No 26.14.0 E2EE reference profile is available for this build.'
            )
        anchors = reference_profile.get('e2ee_reference_signatures')
        if not isinstance(anchors, list) or len(anchors) != len(REFERENCE_FUNCTION_RANGES):
            raise ValueError('The reference profile has no E2EE function signatures.')
        e2ee_sites = _match_e2ee_anchors(image, stubs, anchors)

    got_slot = got['add']
    got_section = image.section('__got', '__DATA_CONST')
    return {
        'schema_version': KEYCHAIN_PROFILE_SCHEMA_VERSION,
        'profile_type': 'line_keychain',
        'bundle_identifier': BUNDLE_IDENTIFIER,
        'version': version,
        'build': build,
        'architecture': 'arm64',
        'executable_sha256': hashlib.sha256(executable).hexdigest(),
        'macho_uuid': image.uuid.hex(),
        'got': {
            'address': hex(got_slot),
            'offset': hex(got_slot - image.image_base),
            'file_offset': hex(image.file_offset(got_slot)),
            'section_address': hex(got_section.address),
            'section_size': hex(got_section.size),
        },
        'imports': {
            operation: {
                'stub_address': hex(stubs[operation]),
                'got_address': hex(got[operation]),
            }
            for operation in OPERATIONS
        },
        'authentication_sites': authentication_sites,
        'e2ee_sites': e2ee_sites,
        'e2ee_reference_signatures': (
            anchors if image.uuid.hex() == '0bab483cca8538ce89840c20c92511e4'
            else None
        ),
    }


def _validate_profile_sites(profile):
    if (
        profile.get('schema_version') != KEYCHAIN_PROFILE_SCHEMA_VERSION or
        profile.get('profile_type') != 'line_keychain' or
        profile.get('bundle_identifier') != BUNDLE_IDENTIFIER or
        profile.get('architecture') != 'arm64' or
        not isinstance(profile.get('version'), str) or
        not isinstance(profile.get('build'), str) or
        not re.fullmatch(r'[0-9a-f]{64}', profile.get('executable_sha256', '')) or
        not re.fullmatch(r'[0-9a-f]{32}', profile.get('macho_uuid', ''))
    ):
        raise ValueError('Invalid Keychain profile identity or schema.')
    imports = profile.get('imports')
    got = profile.get('got')
    if not isinstance(imports, dict) or not isinstance(got, dict):
        raise ValueError('Keychain profile has no import/GOT data.')
    names = ('add', 'copy', 'delete', 'update')
    expected = []
    for name in names:
        item = imports.get(name)
        if not isinstance(item, dict):
            raise ValueError(f'Keychain profile is missing SecItem{name.title()}.')
        expected.append(int(item['got_address'], 16))
    if expected != list(range(expected[0], expected[0] + 32, 8)):
        raise ValueError('Keychain profile SecItem GOT slots are not contiguous.')
    if int(got['address'], 16) != expected[0]:
        raise ValueError('Keychain profile GOT base does not match SecItemAdd.')
    if (
        int(got.get('offset', '0'), 16) <= 0 or
        int(got.get('file_offset', '0'), 16) <= 0
    ):
        raise ValueError('Invalid Keychain profile GOT offsets.')
    for key in ('authentication_sites', 'e2ee_sites'):
        sites = profile.get(key)
        if not isinstance(sites, list) or not sites:
            raise ValueError(f'Keychain profile has no {key}.')
        for site in sites:
            if (
                site.get('operation') not in OPERATIONS or
                int(site.get('return_offset', '0'), 16) <= 0
            ):
                raise ValueError(f'Invalid Keychain profile site in {key}.')
    auth_sites = profile['authentication_sites']
    selectors = {site.get('selector') for site in auth_sites}
    if selectors != set(AUTHENTICATION_METHODS):
        raise ValueError('Authentication profile selectors do not match the audited set.')
    for selector, expected_operations in AUTHENTICATION_METHODS.items():
        operations = tuple(
            site['operation'] for site in auth_sites
            if site.get('selector') == selector
        )
        if operations != expected_operations:
            raise ValueError(f'Unexpected authentication sites for {selector}.')


def _verify_profile_sites(profile, image, stubs):
    text_end = image.text_address + image.text_size
    for key in ('authentication_sites', 'e2ee_sites'):
        for site in profile[key]:
            return_address = image.image_base + int(site['return_offset'], 16)
            call_address = return_address - 4
            if call_address < image.text_address or return_address > text_end:
                raise ValueError(f'Keychain profile call site outside __text: {site}.')
            file_offset = image.text_offset + call_address - image.text_address
            instruction = struct.unpack_from('<I', image.data, file_offset)[0]
            if instruction & 0xfc000000 != 0x94000000:
                raise ValueError(f'Keychain profile site is not a BL: {site}.')
            immediate = instruction & 0x03ffffff
            if immediate & 0x02000000:
                immediate -= 0x04000000
            if call_address + (immediate << 2) != stubs[site['operation']]:
                raise ValueError(f'Keychain profile BL target mismatch: {site}.')


def render_c_header(profile):
    _validate_profile_sites(profile)
    if not re.fullmatch(r'[A-Za-z0-9._-]+', profile.get('version', '')):
        raise ValueError('Invalid LINE version for C profile generation.')
    uuid = bytes.fromhex(profile.get('macho_uuid', ''))
    if len(uuid) != 16:
        raise ValueError('Invalid Mach-O UUID for C profile generation.')
    got = profile['got']
    got_address = int(got['address'], 16)
    got_offset = int(got['offset'], 16)
    imports = profile['imports']
    if [
        int(imports[name]['got_address'], 16)
        for name in ('add', 'copy', 'delete', 'update')
    ] != list(range(got_address, got_address + 32, 8)):
        raise ValueError('Keychain imports do not match the profile GOT base.')
    if len(profile['authentication_sites']) > 64 or len(profile['e2ee_sites']) > 64:
        raise ValueError('Too many Keychain sites for a generated C profile.')
    lines = [
        '#ifndef NEIN_KEYCHAIN_PROFILE_DATA_H',
        '#define NEIN_KEYCHAIN_PROFILE_DATA_H',
        '',
        'static const unsigned char NEINKEmbeddedKeychainUUID[16] = {',
        '    ' + ', '.join(f'0x{byte:02x}' for byte in uuid) + ',',
        '};',
    ]
    for key, array_name in (
        ('authentication_sites', 'NEINKEmbeddedAuthenticationSites'),
        ('e2ee_sites', 'NEINKEmbeddedE2EESites'),
    ):
        lines.append(f'static const NEINKKeychainCallSite {array_name}[] = {{')
        for site in profile[key]:
            operation = site['operation'].upper()
            lines.append(
                f"    {{NEINK_KEYCHAIN_{operation}, "
                f"{int(site['return_offset'], 16):#x}ULL}},"
            )
        lines.append('};')
    lines.extend([
        '',
        'static const NEINKKeychainProfile NEINKEmbeddedKeychainProfile = {',
        f'    {json.dumps(profile["version"])},',
        '    NEINKEmbeddedKeychainUUID,',
        f'    {got_address:#x}ULL,',
        f'    {got_offset:#x}ULL,',
        '    NEINKEmbeddedAuthenticationSites,',
        '    sizeof(NEINKEmbeddedAuthenticationSites) / sizeof(NEINKEmbeddedAuthenticationSites[0]),',
        '    NEINKEmbeddedE2EESites,',
        '    sizeof(NEINKEmbeddedE2EESites) / sizeof(NEINKEmbeddedE2EESites[0]),',
        '};',
        '',
        '#endif',
        '',
    ])
    return '\n'.join(lines)



ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / 'patch_profiles'
EXECUTABLE = 'Payload/LINE.app/LINE'
PLIST = 'Payload/LINE.app/Info.plist'
PROFILE_SCHEMA_VERSION = 2
BUNDLE_IDENTIFIER = 'jp.naver.line'
PROFILE_TYPE = 'line_patch'
FRIEND_TAB_CASE_COMPARE = 0x7100173F
FRIEND_TAB_CASE_RESULT = 0x1A9F17E8
FRIEND_TAB_CASE_COLLAPSED = 0x52800008


def profile_path_for(version, build, executable_sha256, profile_dir=PROFILE_DIR):
    if not isinstance(version, str) or not version:
        raise ValueError('IPA has no LINE version to name the patch profile.')
    if not isinstance(build, str) or not build:
        raise ValueError('IPA has no LINE build to name the patch profile.')
    if not re.fullmatch(r'[0-9a-f]{64}', executable_sha256 or ''):
        raise ValueError('Executable SHA-256 is invalid.')
    safe_version = re.sub(r'[^A-Za-z0-9._-]+', '_', version)
    safe_build = re.sub(r'[^A-Za-z0-9._-]+', '_', build)
    return profile_dir / (
        f'{safe_version}-{safe_build}-{executable_sha256[:12]}.json'
    )


def _decode_e2ee_reference_instructions(signatures):
    if not isinstance(signatures, list):
        raise ValueError('E2EE reference signatures must be a list.')
    decoded = []
    for anchor in signatures:
        if not isinstance(anchor, dict) or not isinstance(
            anchor.get('instructions'), list,
        ):
            raise ValueError('Invalid E2EE reference signature.')
        instructions = []
        for instruction in anchor['instructions']:
            if type(instruction) is int:
                value = instruction
            elif (
                isinstance(instruction, str) and
                re.fullmatch(r'0x[0-9a-fA-F]{1,8}', instruction)
            ):
                value = int(instruction, 16)
            else:
                raise ValueError('E2EE instructions must be 32-bit integers or hex strings.')
            if not 0 <= value <= 0xffffffff:
                raise ValueError('E2EE instruction is outside the 32-bit range.')
            instructions.append(value)
        decoded.append({**anchor, 'instructions': instructions})
    return decoded


def _encode_e2ee_reference_instructions(signatures):
    return [
        {
            **anchor,
            'instructions': [
                f'0x{instruction:08x}'
                for instruction in anchor['instructions']
            ],
        }
        for anchor in _decode_e2ee_reference_instructions(signatures)
    ]


def _canonicalize_profile_reference(profile):
    result = dict(profile)
    keychain = result.get('keychain')
    if not isinstance(keychain, dict):
        return result
    keychain = dict(keychain)
    signatures = keychain.get('e2ee_reference_signatures')
    if signatures is not None:
        keychain['e2ee_reference_signatures'] = (
            _encode_e2ee_reference_instructions(signatures)
        )
    result['keychain'] = keychain
    return result


def _atomic_write(path, serialized):
    descriptor, temporary = tempfile.mkstemp(
        prefix=path.name + '.', suffix='.tmp', dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            output.write(serialized)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _reference_profile(profile_dir):
    for path in sorted(profile_dir.glob('*.json')):
        try:
            document = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            continue
        keychain = document.get('keychain')
        if (
            document.get('profile_type') == PROFILE_TYPE and
            document.get('version') == REFERENCE_VERSION and
            isinstance(keychain, dict) and
            keychain.get('e2ee_reference_signatures')
        ):
            return {
                'e2ee_reference_signatures': (
                    _decode_e2ee_reference_instructions(
                        keychain['e2ee_reference_signatures'],
                    )
                ),
            }

    # Read the previous split reference once during migration; new profiles
    # always carry the reference signatures inside the 26.14.0 profile.
    legacy = profile_dir / 'keychain' / 'references' / (
        'keychain-26.14.0-reference.json'
    )
    if legacy.exists():
        document = json.loads(legacy.read_text(encoding='utf-8'))
        signatures = document.get('e2ee_reference_signatures')
        if signatures:
            return {
                'e2ee_reference_signatures': (
                    _decode_e2ee_reference_instructions(signatures)
                ),
            }
    return None


def _validate_login_section(profile, executable):
    login = profile.get('login_patch')
    if not isinstance(login, dict):
        raise ValueError('Combined patch profile has no login patch.')
    image = parse_arm64_macho(executable)
    try:
        file_offset = int(login['file_offset'], 16)
        patch_va = int(login['virtual_address'], 16)
        target_va = int(login['target_address'], 16)
        original = bytes.fromhex(login['original_hex'])
        patched = bytes.fromhex(login['patched_hex'])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Malformed login patch section.') from error
    expected_offset = image.text_offset + patch_va - image.text_address
    if (
        login.get('kind') != 'secondary_login_entry_branch' or
        file_offset != expected_offset or file_offset < 0 or
        file_offset % 4 or patch_va % 4 or len(original) != 4 or
        patched != NOP.to_bytes(4, 'little') or
        executable[file_offset:file_offset + 4] != original
    ):
        raise ValueError('Combined profile login instruction/layout mismatch.')
    branch = _decode_branch(
        int.from_bytes(original, 'little'), patch_va,
    )
    if not branch or branch[0] != 'tbz w0, #0' or branch[1] != target_va:
        raise ValueError('Combined profile login branch failed validation.')


def analyze_friend_tab_executable(executable):
    image = parse_arm64_macho(executable)
    text = _bounded(
        executable, image.text_offset, image.text_size, '__text',
    )
    result_instruction = struct.pack('<I', FRIEND_TAB_CASE_RESULT)
    matches = []
    cursor = text.find(result_instruction)
    while cursor >= 0:
        start = cursor - 4
        if cursor % 4 == 0 and 0 <= start <= len(text) - 24:
            instructions = struct.unpack_from('<6I', text, start)
            call = instructions[2] & 0xFC000000
            branch = instructions[3] & 0xFC000000
            address = image.text_address + start
            function_index = bisect.bisect_right(
                image.function_starts, address,
            ) - 1
            function_end = (
                image.function_starts[function_index + 1]
                if function_index + 1 < len(image.function_starts)
                else image.text_address + image.text_size
            )
            if (
                instructions[0] == FRIEND_TAB_CASE_COMPARE and
                instructions[1] == FRIEND_TAB_CASE_RESULT and
                call == 0x94000000 and branch == 0x14000000 and
                instructions[4] == FRIEND_TAB_CASE_COMPARE and
                instructions[5] == FRIEND_TAB_CASE_RESULT and
                address >= image.function_starts[function_index] and
                address + 24 <= function_end
            ):
                first_offset = image.text_offset + start + 4
                matches.append((first_offset, first_offset + 16))
        cursor = text.find(result_instruction, cursor + 1)

    if len(matches) != 1:
        return None
    offsets = matches[0]
    replacement = struct.pack('<I', FRIEND_TAB_CASE_COLLAPSED).hex()
    return {
        'kind': 'friend_tab_default_collapsed',
        'view_model': 'LineHomeTab.FriendTabViewModel',
        'state_field': 'isSectionExpanded',
        'friend_case': 5,
        'manual_toggle_preserved': True,
        'patches': [
            {
                'file_offset': hex(offset),
                'original_hex': struct.pack('<I', FRIEND_TAB_CASE_RESULT).hex(),
                'patched_hex': replacement,
            }
            for offset in offsets
        ],
    }


def _validate_home_friends_section(profile, executable):
    home_friends = profile.get('home_friends')
    if home_friends is None:
        return
    if (
        not isinstance(home_friends, dict) or
        home_friends.get('kind') != 'friend_tab_default_collapsed' or
        home_friends.get('view_model') != 'LineHomeTab.FriendTabViewModel' or
        home_friends.get('state_field') != 'isSectionExpanded' or
        home_friends.get('friend_case') != 5 or
        home_friends.get('manual_toggle_preserved') is not True or
        not isinstance(home_friends.get('patches'), list) or
        len(home_friends['patches']) != 2
    ):
        raise ValueError('Malformed combined profile Friends section.')
    try:
        offsets = [
            int(patch['file_offset'], 16)
            for patch in home_friends['patches']
        ]
        originals = [
            bytes.fromhex(patch['original_hex'])
            for patch in home_friends['patches']
        ]
        replacements = [
            bytes.fromhex(patch['patched_hex'])
            for patch in home_friends['patches']
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Malformed combined profile Friends patch sites.') from error

    image = parse_arm64_macho(executable)
    expected_original = struct.pack('<I', FRIEND_TAB_CASE_RESULT)
    expected_replacement = struct.pack('<I', FRIEND_TAB_CASE_COLLAPSED)
    if (
        offsets != sorted(set(offsets)) or offsets[1] - offsets[0] != 16 or
        any(
            offset % 4 or
            offset < image.text_offset or
            offset + 4 > image.text_offset + image.text_size or
            original != expected_original or
            replacement != expected_replacement or
            executable[offset:offset + 4] != original
            for offset, original, replacement in zip(
                offsets, originals, replacements,
            )
        )
    ):
        raise ValueError('Combined profile Friends instruction/layout mismatch.')

    signature_offset = offsets[0] - 4
    signature = struct.unpack_from('<6I', executable, signature_offset)
    if (
        signature[0] != FRIEND_TAB_CASE_COMPARE or
        signature[1] != FRIEND_TAB_CASE_RESULT or
        signature[2] & 0xFC000000 != 0x94000000 or
        signature[3] & 0xFC000000 != 0x14000000 or
        signature[4] != FRIEND_TAB_CASE_COMPARE or
        signature[5] != FRIEND_TAB_CASE_RESULT or
        analyze_friend_tab_executable(executable) != home_friends
    ):
        raise ValueError(
            'Combined profile Friends signature is not a unique analyzed match.'
        )


def _branch26(source, target, link=False):
    delta = target - source
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError('Shop patch branch is out of range.')
    return (0x94000000 if link else 0x14000000) | ((delta >> 2) & 0x3FFFFFF)


def sticker_shop_native_code(native):
    cave = int(native['code_cave']['address'], 16)
    success = int(native['guard_address'], 16) + 4
    deny = int(native['deny_address'], 16)
    kind = int(native['kind_resolver_address'], 16)
    command = int(native['command_resolver_address'], 16)
    # Preserve the normal result; secondary devices only reach valid sticker routes.
    words = (
        0x36000055, _branch26(cave + 4, success),
        0xA9BF7BFD, 0xAA1303E0, _branch26(cave + 16, kind, link=True),
        0x350000E0, 0xAA1303E0, _branch26(cave + 28, command, link=True),
        0x7100241F, 0x54000062, 0xA8C17BFD, _branch26(cave + 44, success),
        0xA8C17BFD, _branch26(cave + 52, deny),
    )
    return struct.pack('<14I', *words)


def _analyze_native_sticker_routes(executable, image, liff_route):
    def words(address, count):
        return struct.unpack(
            f'<{count}I', _bounded(executable, image.file_offset(address), count * 4, 'native shop'),
        )

    def call(address):
        instruction, = words(address, 1)
        if instruction & 0xFC000000 != 0x94000000:
            raise ValueError('Expected native shop call.')
        return address + (_sign_extend(instruction & 0x3FFFFFF, 26) << 2)

    def cases(resolver):
        adrp, add = words(resolver + 20, 2)
        if adrp & 0x9F00001F != 0x90000000 or add & 0xFFC003FF != 0x91000000:
            raise ValueError('Expected shop string-switch table.')
        immediate = ((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)
        address = ((resolver + 20) & ~0xFFF) + (_sign_extend(immediate, 21) << 12) + ((add >> 10) & 0xFFF)
        offset = image.file_offset(address)
        count, = struct.unpack('<Q', _bounded(executable, offset + 16, 8, 'shop cases'))
        if count not in (4, 10):
            raise ValueError('Unexpected shop string-switch size.')
        result = []
        for index in range(count):
            raw, length, flags = struct.unpack(
                '<QQQ', _bounded(executable, offset + 32 + index * 24, 24, 'shop case'),
            )
            value = _cstring(_decode_image_pointer(raw, image), image)
            if len(value) != length or flags != 2:
                raise ValueError('Invalid shop string-switch case.')
            result.append(value)
        return result

    try:
        matcher = int(liff_route['matcher_address'], 16)
        _, matcher_end = _function_bounds(matcher, image)
        candidates = [
            address for address in range(matcher_end, matcher_end + 0x400, 4)
            if words(address, 1)[0] & 0xFC000000 == 0x94000000 and call(address) == matcher
        ]
        if len(candidates) != 1:
            return None
        site = candidates[0]
        signature = words(site, 16)
        if (
            signature[1] != 0x360003A0 or
            signature[4] != 0x9102C2C1 or
            signature[6] != 0xA9405295 or
            signature[8:10] != (0xD63F02A0, 0xAA0003F5) or
            signature[11:14] != (0x36000315, 0xF94072D4, 0xAA1303E0) or
            signature[15] != 0x36000420
        ):
            return None
        helper = call(site + 56)
        helper_words = words(helper + 56, 7)
        if (
            helper_words[0] != 0xAA1303E0 or
            helper_words[2:4] != (0x12001C16, 0xAA1303E0) or
            helper_words[5:7] != (0x35000476, 0x12001C08)
        ):
            return None
        kind = call(helper + 60)
        command = call(helper + 72)
        if (
            call(kind + 16) != call(command + 16) or
            words(kind + 52, 2) != (0x12001C00, 0x7100101F) or
            words(kind + 72, 1) != (0x52800000,) or
            words(command + 56, 2) != (0x12001C00, 0x7100281F) or
            words(command + 76, 1) != (0x52800120,) or
            cases(call(kind + 48)) != ['sticker', 'emoji', 'theme', 'accountRegist'] or
            cases(call(command + 52)) != [
                'new', 'hot', 'event', 'category', 'author', 'detail',
                'premium', 'download', 'preview', 'invalid',
            ]
        ):
            return None

        cave_offset = image.text_offset - 0x100
        cave_address = image.text_address - 0x100
        command_end = 32 + struct.unpack_from('<I', executable, 20)[0]
        if (
            cave_offset % 4 or command_end + 72 > cave_offset or
            any(_bounded(executable, cave_offset, 0x100, 'shop code cave'))
        ):
            return None
        cursor = 32
        executable_header = False
        while cursor < command_end:
            cmd, size = struct.unpack_from('<II', executable, cursor)
            if size < 8 or cursor + size > command_end:
                return None
            if cmd == 0x19 and executable[cursor + 8:cursor + 24].rstrip(b'\0') == b'__TEXT':
                file_offset, = struct.unpack_from('<Q', executable, cursor + 40)
                protection, = struct.unpack_from('<I', executable, cursor + 60)
                executable_header = file_offset == 0 and protection == 5
            cursor += size
        if not executable_header or cursor != command_end:
            return None
        guard = site + 44
        deny = guard + 0x60
        native = {
            'kind': 'native_sticker_routes',
            'guard_address': hex(guard),
            'deny_address': hex(deny),
            'kind_resolver_address': hex(kind),
            'command_resolver_address': hex(command),
            'file_offset': hex(image.file_offset(guard)),
            'original_hex': '15030036',
            'patched_hex': struct.pack('<I', _branch26(guard, cave_address)).hex(),
            'code_cave': {'address': hex(cave_address), 'file_offset': hex(cave_offset)},
        }
        code = sticker_shop_native_code(native)
        native['code_cave'].update(original_hex=bytes(len(code)).hex(), patched_hex=code.hex())
        return native
    except (KeyError, TypeError, ValueError, struct.error):
        return None


def _analyze_sticker_liff_route(executable, image):
    signature = bytes.fromhex('9600003777000037160080520b000014')
    text = _bounded(executable, image.text_offset, image.text_size, '__text')
    cursor = text.find(signature)
    if cursor < 0 or cursor % 4 or text.find(signature, cursor + 1) >= 0:
        return None
    offset = image.text_offset + cursor
    address = image.text_address + cursor
    start, end = _function_bounds(address, image)
    if address - 136 < start or address + 132 > end:
        return None

    def words(at, count):
        return struct.unpack(
            f'<{count}I', _bounded(executable, image.file_offset(at), count * 4, 'shop matcher'),
        )

    def call_target(at):
        word, = words(at, 1)
        if word & 0xFC000000 != 0x94000000:
            raise ValueError('Expected shop matcher call.')
        return at + (_sign_extend(word & 0x3FFFFFF, 26) << 2)

    def page_address(at, register):
        adrp, add = words(at, 2)
        if (
            adrp & 0x9F00001F != 0x90000000 | register or
            add & 0xFFC003FF != 0x91000000 | register << 5 | register
        ):
            raise ValueError('Expected shop matcher address.')
        immediate = ((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)
        return (at & ~0xFFF) + (_sign_extend(immediate, 21) << 12) + ((add >> 10) & 0xFFF)

    # The first app-ID match is sticker-only; retain the theme and shop matches.
    delta = 0 if words(address + 120, 2) == (0x2A160268, 0x12000100) else 4
    before = words(address - 132 - delta, 11)
    if (
        before[:4] != (0x528E0C37, 0x72A00E17, 0xD2FC6018, 0xA9026017) or
        before[5:7] != (0xA9400008, 0xA9030288) or
        (before[8] != 0xAA1403E0 if delta == 0 else before[8] & 0xFC000000 != 0x94000000) or
        before[10] != 0xAA0003F6 or
        words(address - 44 - delta, 6) != (
            0xA9026017, 0xD1008108, 0xB2410108,
            0xD2800269, 0xF2FA0009, 0xA9032009,
        ) or
        words(address + 84, 4) != (
            0x528D0E68, 0x72AE0DE8, 0xD2FC8009, 0xA9022408,
        ) or
        words(address + 120 + delta, 2) != (0x2A160268, 0x12000100)
    ):
        return None
    try:
        if not (
            call_target(address - 96 - delta) ==
            call_target(address - 20) ==
            call_target(address + 100 + delta)
        ):
            return None
        getter = call_target(address - 116 - delta)
        if words(getter + 8, 1) != (0xD65F03C0,):
            return None
        string_address = page_address(getter, 0)
        length, raw = struct.unpack(
            '<QQ', _bounded(executable, image.file_offset(string_address), 16, 'sticker LIFF ID'),
        )
        sticker_id = _cstring(_decode_image_pointer(raw, image) + 32, image)
        theme_id = _cstring(page_address(address - 52 - delta, 8), image)
        if length != 0xD000000000000013 or sticker_id != '1359301715-JKd7Y7j1' or theme_id != '1359301715-lw9jxjqV':
            return None
    except ValueError:
        return None
    return {
        'kind': 'sticker_liff_fallback',
        'scheme': 'LineShopScheme',
        'liff_id': sticker_id,
        'theme_liff_id': theme_id,
        'matcher_address': hex(start),
        'file_offset': hex(offset),
        'original_hex': signature[:4].hex(),
        'patched_hex': NOP.to_bytes(4, 'little').hex(),
    }


def _analyze_coin_entry(executable, image, gate):
    text = _bounded(executable, image.text_offset, image.text_size, '__text')
    original = bytes.fromhex('60008052')
    matches = []
    cursor = text.find(original)
    expected = (
        0xB24403BD, 0xD10083FF, 0xA9017BFD, 0xF90007F6, 0x910043FD,
        0xF9400AC0, 0x94000000, 0xD2800000, 0x94000000, 0xAA0003F4,
        0x52800060, 0x94000000, 0xF94006C1, 0x12000000, 0xD2800014,
        0xA9417BFD, 0x9243FBBD, 0x910083FF, 0xD61F0020,
    )
    while cursor >= 0:
        address = image.text_address + cursor
        if cursor % 4 == 0 and cursor >= 40 and cursor + 36 <= len(text):
            start, end = _function_bounds(address, image)
            words = struct.unpack_from('<19I', text, cursor - 40)
            masked = tuple(
                word & 0xFC000000 if index in (6, 8, 11) else word
                for index, word in enumerate(words)
            )
            if (
                start == address - 40 and end == start + 76 and masked == expected and
                start + 44 + (_sign_extend(words[11] & 0x3FFFFFF, 26) << 2) == gate
            ):
                accessor = start + 32 + (_sign_extend(words[8] & 0x3FFFFFF, 26) << 2)
                try:
                    accessor_bounds = _function_bounds(accessor, image)
                    metadata = struct.unpack(
                        '<8I', _bounded(executable, image.file_offset(accessor), 32, 'coin metadata accessor'),
                    )
                    if (
                        accessor_bounds == (accessor, accessor + 32) and
                        metadata[:2] == (0xA9BF7BFD, 0x910003FD) and
                        metadata[2] & 0x9F00001F == 0x90000000 and
                        metadata[3] & 0xFFC003FF == 0x91000000 and
                        metadata[4] & 0xFC000000 == 0x94000000 and
                        metadata[5:] == (0xD2800001, 0xA8C17BFD, 0xD65F03C0)
                    ):
                        matches.append((start, image.text_offset + cursor))
                except ValueError:
                    pass
        cursor = text.find(original, cursor + 1)
    if len(matches) != 1:
        return None
    callback, offset = matches[0]
    return {
        'kind': 'coin_entry_uses_sticker_feature',
        'side_effects': ['CanUseCoinFeatureSideEffect', 'CanUseLineCoinFeatureSideEffect'],
        'original_feature': 3,
        'enabled_feature': 0,
        'callback_address': hex(callback),
        'file_offset': hex(offset),
        'original_hex': original.hex(),
        'patched_hex': '00008052',
    }


def analyze_sticker_shop_executable(executable):
    """Locate audited sticker routes and their shared coin-entry gate."""
    image = parse_image(executable)
    methods = [
        method for method in _objc_methods(image, 'UniversalFeatureController')
        if method['is_class_method'] and method['selector'] == 'canUseFeature:'
    ]
    if len(methods) != 1:
        return None
    start, end = _function_bounds(methods[0]['implementation'], image)
    calls = []
    for address in range(start, end, 4):
        word = struct.unpack_from('<I', executable, image.file_offset(address))[0]
        if word & 0xFC000000 == 0x94000000:
            calls.append(address + (_sign_extend(word & 0x3FFFFFF, 26) << 2))
    if len(calls) != 2:
        return None
    gate = calls[-1]
    offset = image.file_offset(gate)
    words = struct.unpack('<21I', _bounded(executable, offset, 84, 'feature gate'))
    # Keep w0=1 from before the switch and enter the existing return path.
    # The named sticker-shop side effects pass feature 0 in the audited builds.
    if (
        words[6:8] != (0xAA0003E8, 0xF100D81F) or
        words[8] & 0xFF00001F != 0x54000008 or
        words[9] != 0x52800020 or
        words[10] & 0x9F00001F != 0x90000009 or
        words[11] & 0xFFC003FF != 0x91000129 or
        words[12:16] != (0x1000000A, 0xB8A8792B, 0x8B0B014A, 0xD61F0140) or
        words[16] & 0xFC000000 != 0x94000000 or
        words[17] != 0xAA0003F4 or
        words[18] & 0xFC000000 != 0x94000000 or
        words[19] != 0x12000000 or
        not (words[20] & 0xFC000000 == 0x14000000 or words[20] == 0xA9447BFD)
    ):
        return None
    immediate = ((words[10] >> 5) & 0x7FFFF) << 2 | ((words[10] >> 29) & 3)
    table = (
        ((gate + 40) & ~0xFFF) + (_sign_extend(immediate, 21) << 12) +
        ((words[11] >> 10) & 0xFFF)
    )
    table_offset = image.file_offset(table)
    if (
        table % 4 or table < gate + 84 or
        table + 55 * 4 > image.text_address + image.text_size or
        _bounded(executable, table_offset, 4, 'feature dispatch') != b'\x10\0\0\0'
    ):
        return None
    liff_route = _analyze_sticker_liff_route(executable, image)
    if liff_route is None:
        return None
    native_routes = _analyze_native_sticker_routes(executable, image, liff_route)
    if native_routes is None:
        return None
    coin_entry = _analyze_coin_entry(executable, image, gate)
    if coin_entry is None:
        return None
    return {
        'kind': 'sticker_shop_feature_gate',
        'controller': 'UniversalFeatureController',
        'selector': 'canUseFeature:',
        'feature': 0,
        'gate_address': hex(gate),
        'file_offset': hex(table_offset),
        'original_hex': '10000000',
        'patched_hex': '20000000',
        'liff_route': liff_route,
        'native_routes': native_routes,
        'coin_entry': coin_entry,
    }


def _validate_sticker_shop_section(profile, executable):
    sticker_shop = profile.get('sticker_shop')
    if sticker_shop is not None and (
        not isinstance(sticker_shop, dict) or
        analyze_sticker_shop_executable(executable) != sticker_shop
    ):
        raise ValueError('Combined profile sticker-shop dispatch mismatch.')


def _validate_keychain_section(profile, executable):
    keychain = profile.get('keychain')
    if not isinstance(keychain, dict):
        raise ValueError('Combined patch profile has no Keychain section.')
    if (
        keychain.get('version') != profile.get('version') or
        keychain.get('build') != profile.get('build') or
        keychain.get('executable_sha256') != profile.get('executable_sha256') or
        keychain.get('bundle_identifier') != BUNDLE_IDENTIFIER or
        keychain.get('architecture') != 'arm64'
    ):
        raise ValueError('Combined profile identity differs from its Keychain section.')
    image = parse_image(executable)
    if keychain.get('macho_uuid') != image.uuid.hex():
        raise ValueError('Combined profile Mach-O UUID does not match the IPA.')
    _validate_profile_sites(keychain)
    stubs, got = _resolve_imports(image)
    if (
        int(keychain['got']['address'], 16) != got['add'] or
        int(keychain['got']['offset'], 16) != got['add'] - image.image_base or
        int(keychain['got']['file_offset'], 16) != image.file_offset(got['add'])
    ):
        raise ValueError('Combined profile GOT does not match the IPA imports.')
    if any(
        int(keychain['imports'][operation]['stub_address'], 16) != stubs[operation] or
        int(keychain['imports'][operation]['got_address'], 16) != got[operation]
        for operation in OPERATIONS
    ):
        raise ValueError('Combined profile Security imports do not match the IPA.')
    _verify_profile_sites(keychain, image, stubs)


def validate_profile(profile, info, executable, allow_unverified=False):
    executable_sha256 = hashlib.sha256(executable).hexdigest()
    if (
        profile.get('schema_version') != PROFILE_SCHEMA_VERSION or
        profile.get('profile_type') != PROFILE_TYPE or
        profile.get('bundle_identifier') != BUNDLE_IDENTIFIER or
        profile.get('architecture') != 'arm64' or
        profile.get('version') != info.get('CFBundleShortVersionString') or
        profile.get('build') != info.get('CFBundleVersion') or
        (
            not allow_unverified and
            profile.get('executable_sha256') != executable_sha256
        )
    ):
        raise ValueError('Combined patch profile does not exactly match this IPA.')
    _validate_login_section(profile, executable)
    _validate_home_friends_section(profile, executable)
    _validate_sticker_shop_section(profile, executable)
    _validate_keychain_section(profile, executable)


def render_keychain_header(profile):
    return render_c_header(profile)


def _analyze(info, executable, profile_dir):
    version = info.get('CFBundleShortVersionString')
    build = info.get('CFBundleVersion')
    login_result = analyze_login_executable(
        executable, version=version, build=build,
    )
    login_document = profile_document(login_result)
    keychain_result = analyze_keychain_executable(
        executable,
        version,
        build,
        _reference_profile(profile_dir),
    )
    if keychain_result.get('e2ee_reference_signatures') is not None:
        keychain_result['e2ee_reference_signatures'] = (
            _encode_e2ee_reference_instructions(
                keychain_result['e2ee_reference_signatures'],
            )
        )
    profile = {
        'schema_version': PROFILE_SCHEMA_VERSION,
        'profile_type': PROFILE_TYPE,
        'bundle_identifier': BUNDLE_IDENTIFIER,
        'version': version,
        'build': build,
        'architecture': 'arm64',
        'executable_sha256': hashlib.sha256(executable).hexdigest(),
        'login_patch': login_document['patch'],
        'keychain': keychain_result,
    }
    home_friends = analyze_friend_tab_executable(executable)
    if home_friends is not None:
        profile['home_friends'] = home_friends
    validate_profile(profile, info, executable)
    return profile


def _write_profile(path, profile):
    profile = _canonicalize_profile_reference(profile)
    serialized = json.dumps(profile, indent=2, sort_keys=True) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing_text = path.read_text(encoding='utf-8')
        existing = json.loads(existing_text)
        if existing.get('profile_type') == PROFILE_TYPE:
            canonical_existing = _canonicalize_profile_reference(existing)
            if canonical_existing != profile:
                upgraded = dict(canonical_existing)
                if 'home_friends' in upgraded or 'home_friends' not in profile:
                    raise ValueError(
                        f'Combined patch profile already exists with different contents: {path}'
                    )
                upgraded['home_friends'] = profile['home_friends']
                if upgraded != profile:
                    raise ValueError(
                        f'Combined patch profile already exists with different contents: {path}'
                    )
            if existing_text != serialized:
                _atomic_write(path, serialized)
            return path
        expected = {
            'version': profile['version'],
            'build': profile['build'],
            'executable_sha256': profile['executable_sha256'],
            'bundle_identifier': BUNDLE_IDENTIFIER,
        }
        if any(existing.get(key) != value for key, value in expected.items()):
            raise ValueError(f'Refusing to replace unrelated patch profile: {path}')
        if existing.get('patch') != profile['login_patch']:
            raise ValueError(f'Legacy login patch differs from analyzed patch: {path}')
        _atomic_write(path, serialized)
        return path
    try:
        with path.open('x', encoding='utf-8') as output:
            output.write(serialized)
    except FileExistsError:
        if path.read_text(encoding='utf-8') != serialized:
            raise ValueError(f'Patch profile was concurrently changed: {path}')
    return path


def load_or_create_profile(
    info, executable, profile_dir=PROFILE_DIR, allow_unverified=False,
):
    if info.get('CFBundleIdentifier') != BUNDLE_IDENTIFIER:
        raise ValueError('Expected the original jp.naver.line bundle identifier.')
    version = info.get('CFBundleShortVersionString')
    build = info.get('CFBundleVersion')
    executable_sha256 = hashlib.sha256(executable).hexdigest()
    path = profile_path_for(version, build, executable_sha256, profile_dir)

    if path.exists():
        existing = json.loads(path.read_text(encoding='utf-8'))
        if existing.get('profile_type') == PROFILE_TYPE:
            existing = _canonicalize_profile_reference(existing)
            validate_profile(existing, info, executable)
            if 'home_friends' not in existing:
                home_friends = analyze_friend_tab_executable(executable)
                if home_friends is not None:
                    existing['home_friends'] = home_friends
                    validate_profile(existing, info, executable)
            _write_profile(path, existing)
            return existing, False
    if allow_unverified:
        matches = []
        for candidate in sorted(profile_dir.glob('*.json')):
            document = json.loads(candidate.read_text(encoding='utf-8'))
            if (
                document.get('profile_type') == PROFILE_TYPE and
                document.get('version') == version and
                document.get('build') == build
            ):
                matches.append(_canonicalize_profile_reference(document))
        if len(matches) > 1:
            raise ValueError(
                'Multiple combined profiles match this version/build; refusing to patch.'
            )
        if matches:
            validate_profile(matches[0], info, executable, allow_unverified=True)
            return matches[0], False

    profile = _analyze(info, executable, profile_dir)
    _write_profile(path, profile)
    return profile, True


def save_profile_from_ipa(ipa, profile_dir=PROFILE_DIR):
    with zipfile.ZipFile(ipa) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError('Duplicate ZIP entry names are not supported.')
        info = plistlib.loads(archive.read(PLIST))
        executable = archive.read(EXECUTABLE)
    profile, _ = load_or_create_profile(info, executable, profile_dir)
    return profile_path_for(
        profile['version'], profile['build'], profile['executable_sha256'],
        profile_dir,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    parser.add_argument('--profile-dir', type=Path, default=PROFILE_DIR)
    args = parser.parse_args(argv)
    path = save_profile_from_ipa(args.ipa, args.profile_dir)
    print(path)


if __name__ == '__main__':
    main()
