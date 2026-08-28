from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Protocol
from .foundation import SOURCE_OVERLAY_TOKEN_RE, require, sha256_bytes

"""Classic compiler algorithms: source proofs."""

class _SourceOverlayTokenSession(Protocol):
    def significant_tokens(self, data: bytes) -> tuple[tuple[str, int, int], ...]: ...


def iter_source_overlay_tokens(
    data: bytes,
    *,
    session: _SourceOverlayTokenSession | None = None,
) -> Iterator[tuple[str, int, int]]:
    """Yield C/C++ significant tokens with stable byte spans.

    Latin-1 provides a one-to-one byte/character mapping.  Comments never
    participate in anchor authority; string and character literals remain
    single exact tokens.  The streaming form avoids retaining one Python
    object per token when conservatively scanning large compiler-readable
    namespaces.  Raw source bytes are never retained by a module-global
    cache.  Repeated callers may supply one bounded invocation-local overlay
    render session.
    """
    if session is not None:
        yield from session.significant_tokens(data)
        return
    text = data.decode('latin1')
    for match in SOURCE_OVERLAY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith(('//', '/*')):
            continue
        yield token, match.start(), match.end()


def source_overlay_tokens(
    data: bytes,
    *,
    session: _SourceOverlayTokenSession | None = None,
) -> tuple[tuple[str, int, int], ...]:
    """Lex C/C++ significant tokens into an immutable random-access tuple."""
    return tuple(iter_source_overlay_tokens(data, session=session))

def source_overlay_token_sha256(tokens: list[str]) -> str:
    return sha256_bytes('\x00'.join(tokens).encode('latin1'))

def source_overlay_significant_sha256(data: bytes) -> str:
    return source_overlay_token_sha256([token for token, _, _ in source_overlay_tokens(data)])

def require_source_overlay_range_pin(data: bytes, expected: dict, context: str) -> dict:
    """Authenticate one already-resolved clean-input byte range."""
    actual = {'actual_removed_range_sha256': sha256_bytes(data), 'actual_removed_range_size': len(data), 'actual_removed_range_line_count': data.count(b'\n'), 'actual_removed_range_significant_token_sha256': source_overlay_significant_sha256(data)}
    require(actual['actual_removed_range_sha256'] == expected['baseline_sha256'] and actual['actual_removed_range_size'] == expected['baseline_size'] and (actual['actual_removed_range_line_count'] == expected['baseline_line_count']) and (actual['actual_removed_range_significant_token_sha256'] == expected['baseline_significant_token_sha256']), f'{context} differs from its authenticated input-range pins')
    return actual

def require_target_source_range_identity(
    seed_source: bytes,
    donor_source: bytes,
    proof: dict,
    context: str,
) -> dict:
    """Prove that a target-only donor leaves the selected source unchanged.

    The caller supplies two independently rendered, content-pinned source
    files.  Unique literal markers select the target range and the range pin
    authenticates its exact bytes and significant-token stream.  This proof
    deliberately grants no authority over bytes outside the selected range.
    """
    require(
        isinstance(seed_source, bytes) and isinstance(donor_source, bytes),
        f'{context} source renderings are missing',
    )

    def selected(data: bytes, role: str) -> bytes:
        start_marker = proof['start_marker'].encode('ascii')
        end_marker = proof['end_marker'].encode('ascii')
        require(
            data.count(start_marker) == 1,
            f'{context} {role} start marker is not unique',
        )
        require(
            data.count(end_marker) == 1,
            f'{context} {role} end marker is not unique',
        )
        start = data.index(start_marker)
        end = data.index(end_marker)
        require(start < end, f'{context} {role} source markers are reversed')
        return data[start:end]

    seed_range = selected(seed_source, 'seed')
    donor_range = selected(donor_source, 'donor')
    require_source_overlay_range_pin(
        seed_range,
        proof['range_pin'],
        context + ' seed target range',
    )
    require(
        donor_range == seed_range,
        f'{context} donor changes the target source range',
    )
    require_source_overlay_range_pin(
        donor_range,
        proof['range_pin'],
        context + ' donor target range',
    )
    return {
        'target_source_size': len(seed_range),
        'target_source_sha256': sha256_bytes(seed_range),
    }
SAME_TU_TEMPLATE_INSTANTIATION_IDENTITY_KIND = 'same_tu_template_instantiation_source_identity_v1'
GENERATED_DECLARATION_LINE = re.compile(b'^(?:class|struct)[ ]+[A-Za-z_][A-Za-z0-9_]*[0-9]{2,};$|^extern[ ]int[ ]+[A-Za-z_][A-Za-z0-9_]*[0-9]{2,};$')

def require_declaration_carrier_seat_complement(seed_source: bytes, donor_source: bytes, context: str) -> tuple[int, int]:
    """Prove one rendering is the seed plus two generated declaration blocks.

    `render_same_tu_declaration_carrier` writes a forward-declaration block at
    offset zero and an extern block directly after the last `#include` line,
    and changes nothing else.  This inverts that rule structurally: the donor
    must split into a generated prefix block, the seed's own lines up to and
    including its last `#include`, a generated block, and the seed's remaining
    lines -- every inserted line matching the closed generated grammar.  The
    seed's own lines are compared literally, so a declaration the seed already
    carries can never be masked.
    """
    seed_lines = seed_source.split(b'\n')
    include_rows = [index for index, line in enumerate(seed_lines) if line.startswith(b'#include')]
    require(include_rows, f'{context} seed lacks an include seat')
    insert_at = include_rows[-1] + 1
    head, tail = (seed_lines[:insert_at], seed_lines[insert_at:])
    require(head and tail, f'{context} seed include seat is degenerate')
    donor_lines = donor_source.split(b'\n')
    require(len(donor_lines) > len(tail) and donor_lines[len(donor_lines) - len(tail):] == tail, f'{context} rendering does not retain the seed tail')
    rest = donor_lines[:len(donor_lines) - len(tail)]
    splits = [index for index in range(len(rest) - len(head) + 1) if rest[index:index + len(head)] == head and all((GENERATED_DECLARATION_LINE.match(line) for line in rest[:index])) and all((GENERATED_DECLARATION_LINE.match(line) for line in rest[index + len(head):]))]
    require(len(splits) == 1, f'{context} rendering is not the seed plus two carrier blocks')
    index = splits[0]
    return (index, len(rest) - index - len(head))

def require_forward_run_placement_complement(seed_source: bytes, donor_source: bytes, context: str) -> int:
    """Prove one rendering is the seed plus one seated generated run.

    `render_forward_run_with_shape_carrier` writes a forward-declaration run
    either at offset zero or as whole appended lines, and changes nothing
    else.  This inverts that rule structurally: the donor must be the seed's
    own lines, in order and contiguous, with one block of generated
    declaration lines at exactly one end.  The seed's lines are compared
    literally, so a declaration the seed already carries is never masked.
    """
    seed_lines = seed_source.split(b'\n')
    donor_lines = donor_source.split(b'\n')
    require(len(donor_lines) > len(seed_lines), f'{context} rendering carries no seated run')
    extra = len(donor_lines) - len(seed_lines)
    prefix_seated = donor_lines[extra:] == seed_lines and all((GENERATED_DECLARATION_LINE.match(line) for line in donor_lines[:extra]))
    suffix_seated = donor_lines[:len(seed_lines)] == seed_lines and all((GENERATED_DECLARATION_LINE.match(line) for line in donor_lines[len(seed_lines):]))
    require(prefix_seated or suffix_seated, f'{context} rendering is not the seed plus one seated run')
    return extra

def select_same_tu_source_identity_window(data: bytes, proof: dict, context: str) -> bytes:
    """Select one function through the LF terminating its closing-brace line."""
    marker = proof['start_marker'].encode('ascii')
    require(data.count(marker) == 1, f'{context} start marker is not unique')
    start = data.index(marker)
    tokens = [item for item in source_overlay_tokens(data) if item[1] >= start]
    opening = next((index for index, item in enumerate(tokens) if item[0] == '{'), None)
    require(opening is not None, f'{context} function body is missing')
    depth = 0
    close = None
    for token, _, token_end in tokens[opening:]:
        if token == '{':
            depth += 1
        elif token == '}':
            depth -= 1
            require(depth >= 0, f'{context} braces are unbalanced')
            if depth == 0:
                close = token_end
                break
    require(close is not None and close < len(data) and (data[close] == 10), f'{context} closing brace lacks one physical LF')
    return data[start:close + 1]

def require_same_tu_source_identity(seed_source: bytes, target_donor_source: bytes, instruction_donor_source: bytes, proof: dict, context: str) -> dict:
    """Prove both declaration-carrier donors retain the target source."""
    require(all((isinstance(item, bytes) for item in (seed_source, target_donor_source, instruction_donor_source))), f'{context} source renderings are missing')
    if proof.get('kind') == SAME_TU_TEMPLATE_INSTANTIATION_IDENTITY_KIND:
        layout = proof['carrier_layout']
        for data, role in ((target_donor_source, 'target donor'), (instruction_donor_source, 'instruction donor')):
            if layout == 'declaration_carrier_seats_v1':
                blocks = sum(require_declaration_carrier_seat_complement(seed_source, data, f'{context} {role}'))
            else:
                blocks = require_forward_run_placement_complement(seed_source, data, f'{context} {role}')
            require(blocks > 0, f'{context} {role} carries no declaration carrier')
        selected = [seed_source, seed_source, seed_source]
    else:
        selected = [select_same_tu_source_identity_window(data, proof, context + role) for data, role in ((seed_source, ' seed'), (target_donor_source, ' target donor'), (instruction_donor_source, ' instruction donor'))]
    for role, data in zip(('seed', 'target donor', 'instruction donor'), selected):
        require_source_overlay_range_pin(data, proof['range_pin'], f'{context} {role} target range')
    require(selected[0] == selected[1] == selected[2], f'{context} target source differs between same-TU donors')
    return {'target_source_size': len(selected[0]), 'target_source_sha256': sha256_bytes(selected[0])}

def select_source_permutation_window(data: bytes, proof: dict, context: str) -> bytes:
    """Select the complete source window authenticated by a proof."""
    start_marker = proof['start_marker'].encode('ascii')
    require(data.count(start_marker) == 1, f'{context} start marker is not unique')
    start = data.index(start_marker)
    if proof['kind'] == 'single_evaluation_bindings_v1':
        end_marker = proof['end_marker'].encode('ascii')
        require(data.count(end_marker) == 1, f'{context} end marker is not unique')
        end = data.index(end_marker)
        require(start < end, f'{context} source markers are reversed')
        return data[start:end]
    require(proof['kind'] in {'for_initializer_declaration_reseat_v1', 'captured_pointer_tail_return_v1', 'fixed_array_fill_loop_v1', 'fixed_array_shuffle_pointer_countdown_v1', 'inclusive_extent_assignment_v1', 'discarded_postfix_increment_v1', 'constructor_allocation_lift_v1'} and proof['selector'] == 'brace_balanced_function_after_marker_v1', f'{context} source selector differs')
    tokens = [item for item in source_overlay_tokens(data) if item[1] >= start]
    opening = next((index for index, item in enumerate(tokens) if item[0] == '{'), None)
    require(opening is not None, f'{context} function body is missing')
    depth = 0
    end = None
    for token, _, token_end in tokens[opening:]:
        if token == '{':
            depth += 1
        elif token == '}':
            depth -= 1
            if depth == 0:
                end = token_end
                break
    require(end is not None, f'{context} function body is unbalanced')
    if data[end:end + 1] == b'\n':
        end += 1
    return data[start:end]

def require_target_source_refactor_identity(seed_source: bytes, donor_source: bytes, proof: dict, context: str) -> dict:
    """Pin both complete target ranges before a refactor donor is composed."""
    require(isinstance(seed_source, bytes) and isinstance(donor_source, bytes), f'{context} source renderings are missing')
    seed_range = select_source_permutation_window(seed_source, proof, context + ' seed')
    donor_range = select_source_permutation_window(donor_source, proof, context + ' donor')
    require_source_overlay_range_pin(seed_range, proof['seed_range_pin'], context + ' seed target range')
    require_source_overlay_range_pin(donor_range, proof['donor_range_pin'], context + ' donor target range')
    require(seed_range != donor_range, f'{context} donor does not contain its declared source refactor')
    return {'seed_target_source_size': len(seed_range), 'seed_target_source_sha256': sha256_bytes(seed_range), 'donor_target_source_size': len(donor_range), 'donor_target_source_sha256': sha256_bytes(donor_range)}
