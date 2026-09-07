#!/usr/bin/env python3
"""Offline authenticated Hexagon musl headers; never configure/build a libc.

Extraction is a separate non-executing stage. Installation runs only the pinned
Makefile's install-headers dependency closure in a new private output directory.
Neither stage activates a profile or relaxes the model-generator gate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile


class SetupError(ValueError):
    """An input or retained header receipt is not the exact supported source."""


PIN = {
    'commit_sha1': '6d7621470acf277cbb00550655ed7140d3e4cff9',
    'tree_sha1': 'bb4f49744f8862407ae88046d3f5228175d3068f',
    'archive_sha256': '0e481938549bdabd255240b44b8f442c2e4fbd3fc19981dcf44c09ffa8488c1f',
    'archive_root': 'musl-6d7621470acf277cbb00550655ed7140d3e4cff9',
    'file_count': 2658, 'directory_count': 229, 'file_bytes': 3592282,
}
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
TOOL_PATHS = ('/usr/bin/make', '/bin/sh', '/usr/bin/mkdir', '/usr/bin/sed',
              '/usr/bin/cp', '/usr/bin/cat', '/usr/bin/chmod', '/usr/bin/mv', '/usr/bin/rm')
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_MEMBERS = 10000


def require(condition, message):
    if not condition:
        raise SetupError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':'))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def path_checked(value, *, exists=True, directory=False):
    raw = os.fspath(value)
    require(isinstance(raw, str) and re.fullmatch(r'[A-Za-z0-9_./-]+', raw) is not None,
            'Paths must have no whitespace or make/shell metacharacters')
    require('//' not in raw and all(part not in ('.', '..') for part in raw.split('/') if part),
            'Noncanonical path alias')
    path = Path(os.path.abspath(raw))
    for component in (path, *path.parents):
        require(not component.is_symlink(), 'Symlink path component: ' + str(component))
    if exists:
        require(path.is_dir() if directory else path.is_file(), 'Missing input: ' + str(path))
    else:
        require(not os.path.lexists(path), 'Output already exists; choose a new path')
        require(path.parent.is_dir(), 'Output parent must already exist')
    return path


def read_regular(path, *, limit=MAX_FILE):
    try:
        return _read_regular(path, limit=limit)
    except OSError as exc:
        raise SetupError('Cannot read regular retained input: ' + str(path)) from exc


def _read_regular(path, *, limit):
    path = Path(path)
    require(not path.is_symlink(), 'Unexpected file symlink: ' + str(path))
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Nonregular or oversized file')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode), 'Opened input is not regular')
        data = stream.read(limit + 1)
        final = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(data) <= limit and all(identity(s) == identity(before) for s in (opened, final, path.stat())),
            'Input changed during bounded read')
    return data


def write_new(path, data, permissions=0o644):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(permissions)


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2) + '\n').encode())


def record(path):
    return {'absolute_path': str(path), 'sha256': sha256(read_regular(path, limit=MAX_TOTAL))}


def file_row(data, executable=False):
    return {'kind': 'file', 'mode': '100755' if executable else '100644',
            'permissions': '0755' if executable else '0644', 'size': len(data),
            'sha256': sha256(data), 'blob_sha1': git_hash('blob', data)}


def tree_hash(manifest):
    def directory(name):
        children = []
        for path, row in manifest.items():
            if not path or str(PurePosixPath(path).parent) not in (name or '.',):
                continue
            child = PurePosixPath(path).name
            if row['kind'] == 'directory':
                mode, digest, suffix = '40000', directory(path), b'/'
            else:
                mode, digest, suffix = row['mode'], row['blob_sha1'], b''
            children.append((child.encode() + suffix, mode.encode() + b' ' + child.encode() + b'\0' + bytes.fromhex(digest)))
        return git_hash('tree', b''.join(body for _, body in sorted(children)))
    return directory('')


def authenticate(archive, commit_raw):
    archive, commit_raw = path_checked(archive), path_checked(commit_raw)
    archive_bytes = read_regular(archive, limit=MAX_ARCHIVE)
    commit = read_regular(commit_raw, limit=65536)
    require(sha256(archive_bytes) == PIN['archive_sha256'], 'Pinned archive SHA256 mismatch')
    require(git_hash('commit', commit) == PIN['commit_sha1'], 'Pinned raw Git commit mismatch')
    require(commit.split(b'\n', 1)[0] == b'tree ' + PIN['tree_sha1'].encode(), 'Commit root tree mismatch')
    manifest, contents, modes = {}, {}, {}
    total = 0
    # Read the already-hashed bytes, not a second mutable path snapshot.
    import io
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as source:
        for member in source:
            require(len(manifest) < MAX_MEMBERS, 'Archive member limit exceeded')
            name = member.name
            require(name and re.fullmatch(r'[A-Za-z0-9_./+-]+', name) is not None and not name.startswith('/'),
                    'Invalid archive path')
            parts = name.split('/')
            if parts[-1] == '' and member.isdir():
                parts.pop()
            require(all(part not in ('', '.', '..') for part in parts) and parts[0] == PIN['archive_root'],
                    'Archive path/root alias')
            relative = '/'.join(parts[1:])
            require(relative not in manifest, 'Duplicate archive member')
            require(member.isdir() or member.isfile(), 'Links/special archive members are unsupported')
            require(not member.linkname and not member.issparse(), 'Archive link/sparse metadata unsupported')
            require(set(member.pax_headers) <= {'comment'} and
                    all(value == PIN['commit_sha1'] for value in member.pax_headers.values()), 'Unexpected PAX metadata')
            modes[relative] = member.mode
            if member.isdir():
                require(member.mode in (0o755, 0o775) and member.size == 0, 'Unexpected archive directory mode/size')
                manifest[relative] = {'kind': 'directory', 'mode': '40000', 'permissions': '0755'}
            else:
                require(relative and member.mode in (0o644, 0o664, 0o755, 0o775), 'Unexpected archive file mode')
                require(0 <= member.size <= MAX_FILE, 'Oversized archive member')
                total += member.size
                require(total <= MAX_TOTAL, 'Archive byte limit exceeded')
                data = source.extractfile(member).read(MAX_FILE + 1)
                require(len(data) == member.size, 'Truncated archive member')
                contents[relative] = data
                manifest[relative] = file_row(data, bool(member.mode & 0o111))
    require(manifest.get('', {}).get('kind') == 'directory', 'Archive root missing')
    for name in manifest:
        if name:
            parent = str(PurePosixPath(name).parent)
            require(manifest.get('' if parent == '.' else parent, {}).get('kind') == 'directory', 'Missing or conflicting archive parent')
    require(len(contents) == PIN['file_count'] and len(manifest) - len(contents) == PIN['directory_count'] and
            total == PIN['file_bytes'], 'Archive source inventory differs')
    require(tree_hash(manifest) == PIN['tree_sha1'], 'Archive recursive Git tree mismatch')
    return {'manifest': dict(sorted(manifest.items())), 'contents': contents,
            'archive_modes': dict(sorted(modes.items())), 'archive_bytes': archive_bytes, 'commit_bytes': commit}


def source_manifest(source):
    source = path_checked(source, directory=True)
    rows = {}
    total = 0

    def visit(path, depth=0):
        nonlocal total
        require(len(rows) < MAX_MEMBERS and depth <= 64, 'Source inventory exceeds bounded limits')
        require(not path.is_symlink(), 'Unexpected source symlink')
        name = path.relative_to(source).as_posix()
        name = '' if name == '.' else name
        permissions = stat.S_IMODE(path.stat().st_mode)
        if path.is_dir():
            require(permissions == 0o755, 'Source directory permissions changed')
            rows[name] = {'kind': 'directory', 'mode': '40000', 'permissions': '0755'}
            for child in sorted(path.iterdir()):
                visit(child, depth + 1)
        else:
            require(permissions in (0o644, 0o755), 'Source file permissions changed')
            data = read_regular(path)
            total += len(data)
            require(total <= MAX_TOTAL, 'Source bytes exceed bounded limit')
            rows[name] = file_row(data, permissions == 0o755)
    visit(source)
    return dict(sorted(rows.items()))


def extraction_receipt(output, authenticated):
    return {'schema_version': 1, 'kind': 'hexagon-musl-source', 'status': 'extracted',
            'source_identity': dict(PIN), 'output': str(output), 'source_path': str(output / 'source'),
            'archive': record(output / 'archive.tar.gz'), 'commit_raw': record(output / 'commit.raw'),
            'source_manifest': authenticated['manifest'], 'archive_modes': authenticated['archive_modes'],
            'source_tree_sha1': PIN['tree_sha1'], 'provider': record(Path(__file__).resolve()),
            'boundary': {'network': False, 'source_code_executed': False, 'compiler': False,
                         'libc_objects': False, 'profile_activated': False}}


def extract(archive, commit_raw, output):
    authenticated = authenticate(archive, commit_raw)
    output = path_checked(output, exists=False)
    output.mkdir(mode=0o700)
    require(stat.S_IMODE(output.stat().st_mode) == 0o700, 'Output is not private')
    source = output / 'source'
    for name, row in authenticated['manifest'].items():
        if row['kind'] == 'directory':
            path = source / name
            path.mkdir(mode=0o755)
            path.chmod(0o755)
    for name, data in authenticated['contents'].items():
        write_new(source / name, data, int(authenticated['manifest'][name]['permissions'], 8))
    write_new(output / 'archive.tar.gz', authenticated['archive_bytes'])
    write_new(output / 'commit.raw', authenticated['commit_bytes'])
    require(source_manifest(source) == authenticated['manifest'], 'Extracted source readback differs')
    receipt = extraction_receipt(output, authenticated)
    write_json(output / 'extraction.json', receipt)
    return receipt


def verify_extracted(extracted):
    output = path_checked(extracted, directory=True)
    require(stat.S_IMODE(output.stat().st_mode) == 0o700, 'Extracted output is not private')
    require({path.name for path in output.iterdir()} == {'source', 'archive.tar.gz', 'commit.raw', 'extraction.json'},
            'Unexpected extraction artifacts')
    authenticated = authenticate(output / 'archive.tar.gz', output / 'commit.raw')
    require(source_manifest(output / 'source') == authenticated['manifest'], 'Retained source manifest drift')
    receipt = json_file(output / 'extraction.json')
    require(canonical(receipt) == canonical(extraction_receipt(output, authenticated)), 'Extraction receipt mismatch')
    return receipt


def json_file(path):
    try:
        return json.loads(read_regular(path))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SetupError('Malformed retained JSON: ' + str(path)) from exc


def expected_generated(authenticated):
    """Independently read back the pinned sed rules; not a build substitute."""
    files = authenticated['contents']
    rendered = []
    for source in ('arch/hexagon/bits/alltypes.h.in', 'include/alltypes.h.in'):
        for line in files[source].decode().splitlines(keepends=True):
            plain = line.removesuffix('\n')
            match = re.fullmatch(r'TYPEDEF (.*) ([^ ]*);', plain)
            if match:
                body, name = match.groups()
                rendered.append(f'#if defined(__NEED_{name}) && !defined(__DEFINED_{name})\ntypedef {body} {name};\n#define __DEFINED_{name}\n#endif\n\n')
                continue
            match = re.fullmatch(r'(STRUCT|UNION) * ([^ ]*) (.*);', plain)
            if match:
                kind, name, body = match.groups()
                kind = kind.lower()
                rendered.append(f'#if defined(__NEED_{kind}_{name}) && !defined(__DEFINED_{kind}_{name})\n{kind} {name} {body};\n#define __DEFINED_{kind}_{name}\n#endif\n\n')
                continue
            require(not plain.startswith(('TYPEDEF', 'STRUCT', 'UNION')), 'Unhandled alltypes template form')
            rendered.append(line)
    syscall = files['arch/hexagon/bits/syscall.h.in']
    aliases = b''.join(line.replace(b'__NR_', b'SYS_', 1) for line in syscall.splitlines(keepends=True) if b'__NR_' in line)
    return {'obj/include/bits/alltypes.h': ''.join(rendered).encode(),
            'obj/include/bits/syscall.h': syscall + aliases}


def expected_headers(authenticated, generated):
    files = authenticated['contents']
    chosen = {}
    for name in sorted(files):
        parts = name.split('/')
        if parts[0] == 'include' and len(parts) in (2, 3) and name.endswith('.h'):
            chosen[name] = name
    # Match the genuine Makefile's architecture-before-generic rule order.
    for base in ('arch/generic/bits/', 'arch/hexagon/bits/'):
        for name in sorted(files):
            if name.startswith(base) and '/' not in name[len(base):] and name.endswith('.h'):
                chosen['include/bits/' + name[len(base):]] = name
    for name in generated:
        chosen.setdefault(name.removeprefix('obj/'), name)
    content = {target: files[origin] if origin in files else generated[origin] for target, origin in chosen.items()}
    require(content, 'Empty installed header inventory')
    return dict(sorted(chosen.items())), content


def allowed_generated_directories(authenticated):
    """Only directories attributable to the genuine Makefile's OBJ_DIRS."""
    files = authenticated['contents']
    src_dirs = {name for name in authenticated['manifest'] if name.startswith('src/') and name.count('/') == 1}
    src_dirs |= {'src/malloc/mallocng', 'crt', 'ldso'}
    base, arch = set(), set()
    for name in files:
        parent = str(PurePosixPath(name).parent)
        if parent in src_dirs and name.endswith('.c'):
            base.add(name[:-2])
        if parent.endswith('/hexagon') and parent.removesuffix('/hexagon') in src_dirs and name.endswith(('.c', '.s', '.S')):
            arch.add(name[:-2])
    objects = (base | arch) - {name.replace('/hexagon/', '/') for name in arch}
    directories = {'lib', 'obj', 'obj/include', 'obj/include/bits', 'obj/src/internal'}
    directories |= {'obj/' + str(PurePosixPath(name).parent) for name in objects}
    for name in list(directories):
        directories |= {str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.'}
    return directories


def tool_records():
    records = []
    for name in TOOL_PATHS:
        path = Path(name)
        resolved = path.resolve(strict=True)
        data = read_regular(resolved, limit=MAX_TOTAL)
        require(os.access(path, os.X_OK) and path.resolve(strict=True) == resolved, 'Tool executable alias changed')
        row = {'path': name, 'resolved_path': str(resolved), 'sha256': sha256(data)}
        if path.is_symlink():
            row['symlink_target'] = os.readlink(path)
        records.append(row)
    return records


def make_command(output):
    return ['/usr/bin/make', '--no-builtin-rules', '--no-builtin-variables', '-f', 'Makefile',
            'ARCH=hexagon', 'SHELL=/bin/sh', 'prefix=' + str(output), 'install-headers']


def installed_receipt(output, authenticated, command):
    expected_command = make_command(output)
    require(command.get('argv') == expected_command and command.get('cwd') == str(output / 'source') and
            canonical(command.get('environment')) == canonical(ENVIRONMENT), 'Installed command context differs')
    require(type(command.get('returncode')) is int and command['returncode'] == 0 and command.get('umask') == '0022',
            'Header make did not succeed under its expected umask')
    for name in ('stdout', 'stderr'):
        require(command.get(name) == record(output / ('install.' + name)), 'Command stream binding differs')
    require(not read_regular(output / 'install.stderr'), 'Unexpected header-install stderr')
    tools = tool_records()
    require(canonical(command.get('tools_before')) == canonical(tools) and
            canonical(command.get('tools_after')) == canonical(tools), 'Header tool identity changed')
    generated = expected_generated(authenticated)
    sources = source_manifest(output / 'source')
    for name, expected in authenticated['manifest'].items():
        require(sources.get(name) == expected, 'Genuine source changed during installation: ' + name)
    allowed_dirs = allowed_generated_directories(authenticated)
    for name, row in sources.items():
        if name in authenticated['manifest']:
            continue
        require((row['kind'] == 'directory' and name in allowed_dirs) or
                (name in generated and row == file_row(generated[name])), 'Unexpected generated source artifact: ' + name)
    generated_rows = {}
    for name, data in generated.items():
        require(sources.get(name) == file_row(data), 'Generated header differs from genuine templates: ' + name)
        generated_rows[name] = sources[name]
    header_sources, headers = expected_headers(authenticated, generated)
    include_rows = source_manifest(output / 'include')
    actual_headers = {'include/' + name: row for name, row in include_rows.items() if row['kind'] == 'file'}
    require(actual_headers == {name: file_row(data) for name, data in headers.items()}, 'Installed headers differ from source/generator inventory')
    wanted_dirs = {''}
    for name in headers:
        wanted_dirs |= {'' if str(parent) == 'include' else str(parent).removeprefix('include/')
                        for parent in PurePosixPath(name).parents if str(parent) != '.'}
    require({name for name, row in include_rows.items() if row['kind'] == 'directory'} == wanted_dirs,
            'Unexpected installed header directory')
    extraction = json_file(output / 'extraction.json')
    require(canonical(extraction) == canonical(extraction_receipt(output, authenticated)), 'Installed extraction receipt differs')
    require({path.name for path in output.iterdir()} <= {'source', 'include', 'archive.tar.gz', 'commit.raw',
            'extraction.json', 'install.stdout', 'install.stderr', 'install-command.json', 'fragma-sysroot.json'}, 'Unexpected sysroot artifact')
    require(stat.S_IMODE(output.stat().st_mode) == 0o700, 'Installed output is not private')
    return {'schema_version': 1, 'kind': 'hexagon-musl-headers', 'status': 'headers-installed',
            'libc': 'musl', 'architecture': 'hexagon', 'source_identity': dict(PIN), 'output': str(output),
            'extraction_receipt': record(output / 'extraction.json'), 'archive': record(output / 'archive.tar.gz'),
            'commit_raw': record(output / 'commit.raw'), 'provider': record(Path(__file__).resolve()),
            'source_manifest': authenticated['manifest'], 'generated_manifest': generated_rows,
            'generated_directories': sorted(name for name, row in sources.items() if row['kind'] == 'directory' and name not in authenticated['manifest']),
            'header_manifest': actual_headers, 'header_sources': header_sources,
            'command': command, 'command_receipt': record(output / 'install-command.json'),
            'scope': 'Generator-only genuine Hexagon musl headers; no libc objects/runtime, compiler-derived model, kernel ABI substitution or profile activation.',
            'boundary': {'network': False, 'configure': False, 'compiler': False, 'libc_objects': False,
                         'source_header_install_script_executed': True, 'profile_activated': False}}


def install(extracted, output):
    verified = verify_extracted(extracted)
    extracted = path_checked(extracted, directory=True)
    # Validate the complete source/header transform route before creating output
    # or executing the reviewed Makefile. No arbitrary make arguments are accepted.
    authenticated = authenticate(extracted / 'archive.tar.gz', extracted / 'commit.raw')
    expected_headers(authenticated, expected_generated(authenticated))
    require('config.mak' not in authenticated['manifest'] and 'arch/hexagon/arch.mak' not in authenticated['manifest'],
            'Unreviewed make include')
    output = path_checked(output, exists=False)
    before = tool_records()
    extract(extracted / 'archive.tar.gz', extracted / 'commit.raw', output)
    require(verify_extracted(extracted) == verified, 'Extraction inputs changed before installation')
    command = {'argv': make_command(output), 'cwd': str(output / 'source'),
               'environment': dict(ENVIRONMENT), 'umask': '0022', 'tools_before': before,
               'started_at': datetime.now(timezone.utc).isoformat()}
    try:
        run = subprocess.run(command['argv'], cwd=command['cwd'], env=dict(ENVIRONMENT),
                             capture_output=True, text=True, timeout=180, check=False,
                             stdin=subprocess.DEVNULL, umask=0o022)
        stdout, stderr = run.stdout, run.stderr
        command['returncode'] = run.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout = getattr(exc, 'stdout', '') or ''
        stderr = getattr(exc, 'stderr', '') or ''
        stdout = stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout
        stderr = stderr.decode(errors='replace') if isinstance(stderr, bytes) else stderr
        command.update(returncode=None, error=str(exc))
    write_new(output / 'install.stdout', stdout.encode())
    write_new(output / 'install.stderr', stderr.encode())
    command.update(completed_at=datetime.now(timezone.utc).isoformat(), tools_after=tool_records(),
                   stdout=record(output / 'install.stdout'), stderr=record(output / 'install.stderr'))
    write_json(output / 'install-command.json', command)
    receipt = installed_receipt(output, authenticated, command)
    require(verify_extracted(extracted) == verified, 'Original extraction changed during installation')
    write_json(output / 'fragma-sysroot.json', receipt)
    return receipt


def verify_sysroot(output):
    output = path_checked(output, directory=True)
    authenticated = authenticate(output / 'archive.tar.gz', output / 'commit.raw')
    command = json_file(output / 'install-command.json')
    receipt = json_file(output / 'fragma-sysroot.json')
    expected = installed_receipt(output, authenticated, command)
    require(canonical(receipt) == canonical(expected), 'Sysroot receipt differs from actual input/output closure')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--extract-only', action='store_true')
    mode.add_argument('--install-headers', action='store_true')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--commit-raw', type=Path)
    parser.add_argument('--extracted', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.extract_only:
        if args.archive is None or args.commit_raw is None or args.extracted is not None:
            parser.error('--extract-only requires --archive and --commit-raw, not --extracted')
        result = extract(args.archive, args.commit_raw, args.output)
    else:
        if args.extracted is None or args.archive is not None or args.commit_raw is not None:
            parser.error('--install-headers requires only --extracted and --output')
        result = install(args.extracted, args.output)
    print(json.dumps({'status': result['status'], 'output': result['output'],
                      'source_files': result['source_identity']['file_count'],
                      'headers': len(result.get('header_manifest', {})),
                      'receipt': str(args.output / ('extraction.json' if args.extract_only else 'fragma-sysroot.json'))}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
