from __future__ import annotations

import re

from reprobit.binary import require

from .foundation import FORBIDDEN_CONVENIENCE_OPTIONS

"""Classic compiler algorithms: arguments."""

def _argument_text(value: str) -> str:
    return value

def raw_argument_token_errors(arguments: list[str]) -> list[str]:
    errors = []
    for index, value in enumerate(arguments):
        if not isinstance(value, str) or not value or '\x00' in value:
            errors.append(f'compiler argv token {index} is empty or invalid')
            continue
        if '"' in value or "'" in value:
            errors.append(f'compiler argv token {index} contains literal wrapping/escape quotes')
    return errors
ADMITTED_NO_OPERAND_OPTIONS = {'/nologo', '-nologo', '/W3', '-W3', '/WX', '-WX', '/GX', '-GX', '/Zi', '-Zi', '/O1', '-O1', '/O2', '-O2', '/Od', '-Od', '/Ox', '-Ox', '/Ob0', '-Ob0', '/Ob1', '-Ob1', '/Ob2', '-Ob2', '/Oy', '-Oy', '/Oy-', '-Oy-', '/Gm', '-Gm', '/Gm-', '-Gm-', '/GR', '-GR', '/GR-', '-GR-', '/c', '-c', '/TC', '-TC', '/TP', '-TP', '/MD', '-MD', '/MDd', '-MDd', '/MT', '-MT', '/MTd', '-MTd'}

def _admitted_warning_option(token: str) -> bool:
    return re.fullmatch('[/-](?:W[0-4]|WX|w[devo]?[0-9]+)', token) is not None

def lex_compile_arguments(arguments: list[str]) -> dict:
    """Classify every token before the attested final source by role.

    Only `/D`, `/U`, and `/I` intentionally admit a separate operand.  The
    output and force-include options are collected even in their forbidden
    separated form so pre-gate cleanup can use the same lexer as semantic
    validation.  An unknown option or any earlier positional token is fatal.
    """
    valued: dict[str, list[tuple[int, str, bool]]] = {'Fo': [], 'Fd': [], 'FI': [], 'D': [], 'U': [], 'I': []}
    role_operands = []
    compile_only = []
    compile_only_indices = []
    debug_format = []
    language_modes = []
    roles = [{'index': 0, 'role': 'compiler', 'token': arguments[0]}] if arguments else []
    errors = []
    errors.extend(raw_argument_token_errors(arguments))
    if len(arguments) < 2 or not _argument_text(arguments[-1]):
        errors.append('compiler command has no final positional source')
        final_source = ''
        limit = len(arguments)
    else:
        final_source = _argument_text(arguments[-1])
        limit = len(arguments) - 1
    index = 1
    while index < limit:
        token = _argument_text(arguments[index])
        matched = False
        for option in ('FI', 'Fd', 'Fo'):
            for sigil in ('/', '-'):
                prefix = sigil + option
                if token == prefix:
                    if index + 1 < limit and _argument_text(arguments[index + 1]):
                        value = _argument_text(arguments[index + 1])
                        valued[option].append((index, value, True))
                        role_operands.append((option, value))
                        roles.append({'index': index, 'role': option, 'token': token, 'value': value, 'separate': True})
                        errors.append(f'/{option} value must be attached to its exact option token')
                        index += 2
                    else:
                        errors.append(f'missing value after {token}')
                        index += 1
                    matched = True
                    break
                if token.startswith(prefix):
                    value = token[len(prefix):]
                    if value:
                        valued[option].append((index, value, False))
                        role_operands.append((option, value))
                        roles.append({'index': index, 'role': option, 'token': token, 'value': value, 'separate': False})
                    else:
                        errors.append(f'missing value after {prefix}')
                    index += 1
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue
        for option in ('D', 'U', 'I'):
            for sigil in ('/', '-'):
                prefix = sigil + option
                if token == prefix:
                    if index + 1 < limit and _argument_text(arguments[index + 1]):
                        value = _argument_text(arguments[index + 1])
                        valued[option].append((index, value, True))
                        role_operands.append((option, value))
                        roles.append({'index': index, 'role': option, 'token': token, 'value': value, 'separate': True})
                        index += 2
                    else:
                        errors.append(f'missing value after {token}')
                        index += 1
                    matched = True
                    break
                if token.startswith(prefix):
                    value = token[len(prefix):]
                    if value:
                        valued[option].append((index, value, False))
                        role_operands.append((option, value))
                        roles.append({'index': index, 'role': option, 'token': token, 'value': value, 'separate': False})
                    else:
                        errors.append(f'missing value after {prefix}')
                    index += 1
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue
        if token in ADMITTED_NO_OPERAND_OPTIONS or _admitted_warning_option(token):
            roles.append({'index': index, 'role': 'flag', 'token': token})
            if token in ('/c', '-c'):
                compile_only.append(token)
                compile_only_indices.append(index)
            elif token in ('/Zi', '-Zi'):
                debug_format.append(token)
            elif token in ('/TC', '-TC'):
                language_modes.append('C')
            elif token in ('/TP', '-TP'):
                language_modes.append('CXX')
            index += 1
            continue
        folded = token.casefold()
        if folded in ('/c', '-c'):
            errors.append('compile-only mode must use exact lowercase /c or -c')
        elif folded in ('/zi', '-zi'):
            errors.append('debug format must use exact /Zi or -Zi')
        elif any((folded.startswith((sigil + option).casefold()) for option in ('FI', 'Fd', 'Fo') for sigil in ('/', '-'))):
            errors.append(f'compiler option collides with exact output grammar: {token}')
        elif folded.startswith(('/y', '-y')):
            errors.append(f'the complete /Y compiler state family is forbidden: {token}')
        elif re.match('^[/-]b(?:$|1|2|x)', token, re.IGNORECASE):
            errors.append('compiler component/pass override options are forbidden')
        elif folded in FORBIDDEN_CONVENIENCE_OPTIONS:
            errors.append(f'preprocess compiler convenience mode is forbidden: {token}')
        elif folded in ('/link', '-link') or folded.startswith(('/link:', '-link:')):
            errors.append('compiler link-tail mode is forbidden')
        elif folded.startswith(('/fi', '-fi', '/fr', '-fr', '/fp', '-fp', '/fc', '-fc', '/fs', '-fs', '/fu', '-fu', '/fx', '-fx', '/fe', '-fe', '/fm', '-fm', '/fa', '-fa', '/tc', '-tc', '/tp', '-tp', '/ld', '-ld', '/zs', '-zs', '/gl', '-gl', '/z7', '-z7', '/ai', '-ai', '/doc', '-doc', '/analyze', '-analyze', '/ifc', '-ifc', '/interface', '-interface', '/internalpartition', '-internalpartition', '/exportheader', '-exportheader', '/headerunit', '-headerunit', '/reference', '-reference', '/sourcedependencies', '-sourcedependencies', '/scandependencies', '-scandependencies', '/clr', '-clr', '/zw', '-zw')):
            errors.append(f'unsupported compiler input/output/link mode: {token}')
        elif token.startswith(('/', '-')):
            errors.append(f'unsupported compiler option: {token}')
        else:
            errors.append(f'extra positional compiler input before final source: {token}')
        index += 1
    if len(valued['Fo']) != 1:
        errors.append(f"expected one exact /Fo, found {len(valued['Fo'])}")
    if len(valued['Fd']) != 1:
        errors.append(f"expected one exact /Fd, found {len(valued['Fd'])}")
    if len(compile_only) != 1:
        errors.append(f'expected one exact /c or -c, found {len(compile_only)}')
    if len(debug_format) != 1:
        errors.append(f'expected one exact /Zi or -Zi, found {len(debug_format)}')
    if len(language_modes) > 1:
        errors.append(f'expected at most one exact /TC or /TP, found {len(language_modes)}')
    if len(valued['Fo']) == 1 and len(valued['Fd']) == 1 and (len(compile_only_indices) == 1):
        if valued['Fo'][0][0] != len(arguments) - 4 or valued['Fo'][0][2] or valued['Fd'][0][0] != len(arguments) - 3 or valued['Fd'][0][2] or (compile_only_indices[0] != len(arguments) - 2):
            errors.append('compiler command must end with attached /Fo, attached /Fd, exact -c, and the configured source')
    return {'valued': valued, 'role_operands': role_operands, 'compile_only': compile_only, 'compile_only_indices': compile_only_indices, 'debug_format': debug_format, 'language_modes': language_modes, 'roles': [*roles, {'index': len(arguments) - 1, 'role': 'source', 'token': final_source} if final_source else {}] if final_source else roles, 'source_token': final_source, 'errors': errors}

def validate_compile_arguments(arguments: list[str]) -> dict:
    """Enforce the closed, case-aware VC4.2 compiler argv grammar."""
    parsed = lex_compile_arguments(arguments)
    require(not parsed['errors'], '; '.join(parsed['errors']))
    valued = parsed['valued']
    return {'Fo': valued['Fo'][0], 'Fd': valued['Fd'][0], 'force_includes': valued['FI'], 'definitions': valued['D'], 'undefinitions': valued['U'], 'include_paths': valued['I'], 'role_operands': parsed['role_operands'], 'source_token': parsed['source_token'], 'compile_only': parsed['compile_only'][0], 'debug_format': parsed['debug_format'][0], 'language_mode': parsed['language_modes'][0] if parsed['language_modes'] else None, 'roles': parsed['roles']}
