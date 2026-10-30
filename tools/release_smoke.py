"""Run with a clean wheel environment: python -I tools/release_smoke.py VERSION.

Uses only the standard library plus the installed application runtime. The
server runs outside the checkout with a disposable database, never user data.
"""

from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from logsentinel import __version__
import logsentinel


def main(expected):
    assert __version__ == version('logsentinel') == expected
    installed = Path(logsentinel.__file__).resolve()
    assert 'site-packages' in installed.parts, f'Expected installed wheel: {installed}'
    with tempfile.TemporaryDirectory(prefix='logessential-wheel-') as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        env['LOGSENTINEL_DB'] = str(Path(temp) / 'events.db')
        with open(Path(temp) / 'server.log', 'w+') as log:
            server = subprocess.Popen([sys.executable, '-I', '-m', 'uvicorn', 'logsentinel.app:app',
                                       '--host', '127.0.0.1', '--port', str(port)],
                                      cwd=temp, env=env, stdout=log, stderr=log)
            def request(path, method='GET', body=None):
                req = urllib.request.Request(f'http://127.0.0.1:{port}' + path, method=method,
                      data=json.dumps(body or {}).encode() if method != 'GET' else None,
                      headers={'Content-Type': 'application/json'})
                return urllib.request.urlopen(req, timeout=5).read()
            def api(path, method='GET', body=None):
                return json.loads(request('/api' + path, method, body))
            try:
                for _ in range(100):
                    try:
                        assert api('/health')['version'] == expected
                        break
                    except OSError:
                        if server.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        time.sleep(0.1)
                else:
                    raise RuntimeError('Wheel server did not start')
                assert b'LogEssential' in request('/')
                for path in ['/static/app.js', '/static/lab.js', '/static/style.css', '/static/guide.css']:
                    assert request(path)
                assert b'LogEssential project guide' in request('/static/guides/docs/INDEX.html')
                assert api('/demo', 'POST')['inserted'] == 85
                assert api('/demo', 'POST')['inserted'] == 0
                assert api('/stats')['alerts'] == 5
                settings = api('/settings')
                lab = api('/lab/replay', 'POST', {'scenario': 'window_edge',
                          'settings': {**settings['settings'], 'window_seconds': 299}})
                assert lab['alerts'] == []
                assert api('/stats')['events'] == 85 and api('/settings') == settings
                alert = api('/alerts')['items'][0]['id']
                saved = api('/alerts/' + alert + '/notebook', 'PUT', {'observation': 'Synthetic wheel check'})
                assert api('/notebooks/' + alert) == saved
                print(f'PASS: installed {expected}, outside checkout, health/UI/guides/assets, 85 events, 5 alerts, dedup, isolated lab, saved notes')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == '__main__':
    main(sys.argv[1])
