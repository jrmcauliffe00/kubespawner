import json
from unittest.mock import MagicMock, patch

import pytest

from kubespawner.vault import (
    annotations_for_secret,
    build_vault_inject_annotations,
    default_template_for,
    filter_secrets_for_form,
    list_kv_secrets,
    normalize_secret,
    normalize_secrets,
    resolve_selected_secrets,
    sanitize_annotation_name,
)


def test_sanitize_annotation_name():
    assert sanitize_annotation_name('App Config') == 'app-config'
    assert sanitize_annotation_name('ssh_key') == 'ssh_key'
    with pytest.raises(ValueError):
        sanitize_annotation_name('!!!')


def test_normalize_secret_engines():
    kv2 = normalize_secret(
        {'id': 'cfg', 'path': 'secret/data/x', 'engine': 'kv-v2'}
    )
    assert kv2['engine'] == 'kv2'
    assert kv2['file'] == 'cfg'

    ssh = normalize_secret({'name': 'bastion', 'path': 'ssh/creds/r', 'engine': 'ssh'})
    assert ssh['id'] == 'bastion'
    assert ssh['file'] == 'id_rsa'
    assert ssh['file_permission'] == '0600'


def test_normalize_secrets_duplicate_id():
    with pytest.raises(ValueError, match='Duplicate'):
        normalize_secrets(
            [
                {'id': 'a', 'path': 'p1', 'engine': 'kv2'},
                {'id': 'a', 'path': 'p2', 'engine': 'kv2'},
            ]
        )


def test_annotations_for_kv2_and_ssh():
    kv = normalize_secret(
        {
            'id': 'cfg',
            'path': 'secret/data/app',
            'engine': 'kv2',
            'file': 'app.env',
        }
    )
    kv_ann = annotations_for_secret(kv)
    assert kv_ann['vault.hashicorp.com/agent-inject-secret-cfg'] == 'secret/data/app'
    assert kv_ann['vault.hashicorp.com/agent-inject-file-cfg'] == 'app.env'
    assert '.Data.data' in kv_ann['vault.hashicorp.com/agent-inject-template-cfg']

    ssh = normalize_secret({'id': 'ssh', 'path': 'ssh/creds/role', 'engine': 'ssh'})
    ssh_ann = annotations_for_secret(ssh)
    assert ssh_ann['vault.hashicorp.com/agent-inject-file-ssh'] == 'id_rsa'
    assert (
        ssh_ann['vault.hashicorp.com/agent-inject-file-permission-ssh'] == '0600'
    )
    assert 'private_key' in ssh_ann['vault.hashicorp.com/agent-inject-template-ssh']


def test_build_vault_inject_annotations():
    secrets = normalize_secrets(
        [{'id': 'cfg', 'path': 'secret/data/app', 'engine': 'kv2'}]
    )
    ann = build_vault_inject_annotations(
        secrets=secrets,
        role='jupyter',
        auth_path='auth/kubernetes',
        auth_type='kubernetes',
        static_annotations={'vault.hashicorp.com/agent-pre-populate-only': 'true'},
    )
    assert ann['vault.hashicorp.com/agent-inject'] == 'true'
    assert ann['vault.hashicorp.com/role'] == 'jupyter'
    assert ann['vault.hashicorp.com/auth-path'] == 'auth/kubernetes'
    assert ann['vault.hashicorp.com/agent-pre-populate-only'] == 'true'
    assert 'vault.hashicorp.com/agent-inject-secret-cfg' in ann


def test_build_vault_inject_annotations_skips_empty_selection():
    ann = build_vault_inject_annotations(
        secrets=[],
        role='jupyter',
        static_annotations={'vault.hashicorp.com/agent-pre-populate-only': 'true'},
    )
    assert ann == {'vault.hashicorp.com/agent-pre-populate-only': 'true'}
    assert 'vault.hashicorp.com/agent-inject' not in ann


def test_kv_key_field_for_ssh_private_key():
    secret = normalize_secret(
        {
            'id': 'git-ssh',
            'path': 'secret/data/jupyter/ssh',
            'engine': 'kv2',
            'key_field': 'private_key',
        }
    )
    assert secret['file'] == 'private_key'
    assert secret['file_permission'] == '0600'
    ann = annotations_for_secret(secret)
    tmpl = ann['vault.hashicorp.com/agent-inject-template-git-ssh']
    assert 'private_key' in tmpl
    assert '.Data.data' in tmpl


def test_filter_secrets_for_form():
    catalog = normalize_secrets(
        [
            {'id': 'a', 'path': 'p/a', 'engine': 'kv2'},
            {'id': 'b', 'path': 'p/b', 'engine': 'kv2'},
        ]
    )
    assert [s['id'] for s in filter_secrets_for_form(catalog, id_whitelist=['b'])] == [
        'b'
    ]
    assert [
        s['id'] for s in filter_secrets_for_form(catalog, path_whitelist=['p/a'])
    ] == ['a']


def test_normalize_secrets_keep_first():
    secrets = normalize_secrets(
        [
            {'id': 'a', 'path': 'static/path', 'engine': 'kv2', 'display_name': 'Static'},
            {'id': 'a', 'path': 'listed/path', 'engine': 'kv2', 'display_name': 'Listed'},
        ],
        on_duplicate='keep_first',
    )
    assert len(secrets) == 1
    assert secrets[0]['path'] == 'static/path'


def test_resolve_selected_secrets_form_and_defaults():
    catalog = normalize_secrets(
        [
            {'id': 'a', 'path': 'p/a', 'engine': 'kv2', 'default': True},
            {'id': 'b', 'path': 'p/b', 'engine': 'kv2'},
        ]
    )
    selected = resolve_selected_secrets(
        catalog, ['b'], form_enabled=True, id_whitelist=['a', 'b']
    )
    assert [s['id'] for s in selected] == ['b']

    defaults = resolve_selected_secrets(catalog, None, form_enabled=False)
    assert [s['id'] for s in defaults] == ['a']

    no_defaults_catalog = normalize_secrets(
        [{'id': 'b', 'path': 'p/b', 'engine': 'kv2'}]
    )
    assert resolve_selected_secrets(no_defaults_catalog, None, form_enabled=False) == []

    with pytest.raises(ValueError, match='Unknown'):
        resolve_selected_secrets(catalog, ['nope'], form_enabled=True)


def test_default_template_for_kv1():
    tmpl = default_template_for('kv', 'secret/foo')
    assert 'secret/foo' in tmpl
    assert '.Data.data' not in tmpl
    assert '.Data' in tmpl


def test_list_kv_secrets():
    payload = json.dumps({'data': {'keys': ['db', 'folder/', 'ssh']}}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = payload
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False

    with patch('kubespawner.vault.urlopen', return_value=mock_resp) as urlopen:
        secrets = list_kv_secrets(
            addr='https://vault.example.com',
            token='s.token',
            list_path='secret/metadata/jupyter/alice',
            engine='kv2',
        )

    assert urlopen.called
    ids = {s['id'] for s in secrets}
    assert len(secrets) == 2
    assert all(s['engine'] == 'kv2' for s in secrets)
    paths = {s['path'] for s in secrets}
    assert 'secret/data/jupyter/alice/db' in paths
    assert 'secret/data/jupyter/alice/ssh' in paths
    assert not any(p.endswith('folder') for p in paths)
    assert ids  # non-empty sanitized ids
