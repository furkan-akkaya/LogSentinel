"""Reject private/local files in release archives and require source essentials."""

from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile


def check(path):
    if path.suffix == '.whl':
        with zipfile.ZipFile(path) as archive:
            names = [n for n in archive.namelist() if not n.endswith('/')]
        assert 'logsentinel/static/index.html' in names
        assert 'logsentinel/static/lab.js' in names
        assert 'logsentinel/static/guides/docs/INDEX.html' in names
    else:
        with tarfile.open(path) as archive:
            names = [n.name.split('/', 1)[1] for n in archive.getmembers() if n.isfile()]
        for required in ['LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'requirements.txt',
                         'tests/test_lab_notebooks.py', 'tools/release_smoke.py',
                         'tools/build_guides.py', 'docs/diagrams/pipeline.svg', 'samples/linux-auth.log']:
            assert required in names, f'Missing source file: {required}'
    for name in names:
        rel = PurePosixPath(name)
        assert not rel.is_absolute() and '..' not in rel.parts
        assert not set(rel.parts) & {'data', '.git', '.venv', 'node_modules', '.pytest_cache', '__pycache__'}
        assert rel.suffix not in {'.db', '.sqlite', '.sqlite3', '.pcap', '.pcapng', '.pem', '.key', '.pyc'}
        assert rel.name != '.env'
        if rel.suffix == '.log':
            assert name.startswith(('samples/', 'logsentinel/demo/')), f'Unexpected raw log: {name}'
    print(f'PASS: {path.name}, {len(names)} shareable members')


if __name__ == '__main__':
    for item in sys.argv[1:]:
        check(Path(item))
