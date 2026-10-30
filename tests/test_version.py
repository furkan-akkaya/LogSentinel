"""The installed metadata, Python module, OpenAPI and health must agree."""

from importlib.metadata import version

from logsentinel import __version__


def test_installed_and_reported_versions_agree(client):
    assert version('logsentinel') == __version__
    assert client.get('/api/health').json()['version'] == __version__
    schema = client.get('/openapi.json').json()
    assert schema['info']['version'] == __version__
    assert schema['info']['title'] == 'LogEssential'
