"""
HashiCorp Vault Agent Injector helpers for KubeSpawner.

Builds pod annotations consumed by the Vault Agent Injector (vault-k8s) so
selected secrets are rendered into the user pod via the Kubernetes auth method.
Supports KV (v1/v2) and SSH secrets engines.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SUPPORTED_ENGINES = frozenset({"kv", "kv2", "ssh"})

_ANNOTATION_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")

# Default Agent templates. KV v2 nests values under .Data.data; KV v1 uses .Data.
_DEFAULT_KV2_TEMPLATE = """\
{{- with secret "%(path)s" -}}
{{- range $k, $v := .Data.data -}}
{{ $k }}={{ $v }}
{{ end -}}
{{- end -}}
"""

_DEFAULT_KV_TEMPLATE = """\
{{- with secret "%(path)s" -}}
{{- range $k, $v := .Data -}}
{{ $k }}={{ $v }}
{{ end -}}
{{- end -}}
"""

# SSH secrets engine dynamic credentials (ssh/creds/<role>)
_DEFAULT_SSH_TEMPLATE = """\
{{- with secret "%(path)s" -}}
{{ .Data.private_key }}
{{- end -}}
"""

# Single field from KV v2 (e.g. a private key stored as secret data)
_DEFAULT_KV2_FIELD_TEMPLATE = """\
{{- with secret "%(path)s" -}}
{{ index .Data.data "%(field)s" }}
{{- end -}}
"""

_DEFAULT_KV_FIELD_TEMPLATE = """\
{{- with secret "%(path)s" -}}
{{ index .Data "%(field)s" }}
{{- end -}}
"""


def sanitize_annotation_name(name: str) -> str:
    """Return a Vault Agent Injector-safe unique annotation suffix."""
    cleaned = _ANNOTATION_NAME_RE.sub("-", (name or "").strip()).strip("-._")
    if not cleaned:
        raise ValueError("Vault secret id/name must contain alphanumeric characters")
    return cleaned.lower()


def normalize_secret(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a vault_secrets catalog entry.

    Required keys: id (or name), path, engine ("kv" | "kv2" | "ssh").
    """
    if not isinstance(entry, dict):
        raise ValueError(f"Vault secret entry must be a dict, got {type(entry)!r}")

    secret_id = entry.get("id") or entry.get("name")
    if not secret_id:
        raise ValueError("Vault secret entry requires 'id' (or 'name')")

    path = entry.get("path")
    if not path:
        raise ValueError(f"Vault secret {secret_id!r} requires 'path'")

    engine = (entry.get("engine") or "kv2").lower()
    if engine in ("kv-v1", "kvv1", "kv1"):
        engine = "kv"
    elif engine in ("kv-v2", "kvv2", "kv-v2"):
        engine = "kv2"
    elif engine in ("ssh-keys", "ssh_key", "ssh-key"):
        engine = "ssh"

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(
            f"Vault secret {secret_id!r} has unsupported engine {engine!r}; "
            f"supported: {', '.join(sorted(SUPPORTED_ENGINES))}"
        )

    annotation_name = sanitize_annotation_name(entry.get("annotation_name") or secret_id)
    display_name = entry.get("display_name") or str(secret_id)
    key_field = entry.get("key_field")

    default_file = annotation_name
    default_permission = None
    if engine == "ssh":
        default_file = entry.get("file") or "id_rsa"
        default_permission = "0600"
    elif key_field:
        # Common for SSH private keys (or other single sensitive values) stored in KV
        default_file = entry.get("file") or str(key_field)
        default_permission = entry.get("file_permission") or "0600"

    normalized = {
        "id": str(secret_id),
        "path": str(path),
        "engine": engine,
        "display_name": display_name,
        "description": entry.get("description") or "",
        "annotation_name": annotation_name,
        "file": entry.get("file") or default_file,
        "file_permission": entry.get("file_permission") or default_permission,
        "mount_path": entry.get("mount_path"),
        "template": entry.get("template"),
        "key_field": key_field,
        "default": bool(entry.get("default", False)),
    }
    return normalized


def normalize_secrets(
    entries: Optional[Iterable[Dict[str, Any]]],
    *,
    on_duplicate: str = "error",
) -> List[Dict[str, Any]]:
    """
    Normalize a catalog of vault secrets by id.

    on_duplicate:
      - "error": raise on duplicate ids (default)
      - "keep_first": ignore later duplicates (used when merging LIST results)
    """
    if not entries:
        return []
    if on_duplicate not in ("error", "keep_first"):
        raise ValueError(f"Invalid on_duplicate: {on_duplicate!r}")
    seen = set()
    normalized = []
    for entry in entries:
        secret = normalize_secret(entry)
        if secret["id"] in seen:
            if on_duplicate == "keep_first":
                continue
            raise ValueError(f"Duplicate Vault secret id: {secret['id']!r}")
        seen.add(secret["id"])
        normalized.append(secret)
    return normalized


def filter_secrets_for_form(
    catalog: Sequence[Dict[str, Any]],
    *,
    id_whitelist: Optional[Sequence[str]] = None,
    path_whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Return catalog entries visible in the spawn form after allowlist filters."""
    filtered = []
    id_allowed = set(id_whitelist) if id_whitelist else None
    path_allowed = set(path_whitelist) if path_whitelist else None
    for secret in catalog:
        if id_allowed is not None and secret["id"] not in id_allowed:
            continue
        if path_allowed is not None and secret["path"] not in path_allowed:
            continue
        filtered.append(secret)
    return filtered


def default_template_for(
    engine: str, path: str, key_field: Optional[str] = None
) -> str:
    if key_field:
        if engine == "kv2":
            return _DEFAULT_KV2_FIELD_TEMPLATE % {"path": path, "field": key_field}
        if engine == "kv":
            return _DEFAULT_KV_FIELD_TEMPLATE % {"path": path, "field": key_field}
    if engine == "kv2":
        return _DEFAULT_KV2_TEMPLATE % {"path": path}
    if engine == "kv":
        return _DEFAULT_KV_TEMPLATE % {"path": path}
    if engine == "ssh":
        return _DEFAULT_SSH_TEMPLATE % {"path": path}
    raise ValueError(f"Unsupported Vault engine: {engine!r}")


def annotations_for_secret(secret: Dict[str, Any]) -> Dict[str, str]:
    """Build Agent Injector annotations for a single normalized secret."""
    name = secret["annotation_name"]
    path = secret["path"]
    template = secret.get("template") or default_template_for(
        secret["engine"], path, key_field=secret.get("key_field")
    )

    annotations = {
        f"vault.hashicorp.com/agent-inject-secret-{name}": path,
        f"vault.hashicorp.com/agent-inject-template-{name}": template,
    }
    if secret.get("file"):
        annotations[f"vault.hashicorp.com/agent-inject-file-{name}"] = secret["file"]
    if secret.get("file_permission"):
        annotations[
            f"vault.hashicorp.com/agent-inject-file-permission-{name}"
        ] = secret["file_permission"]
    if secret.get("mount_path"):
        annotations[f"vault.hashicorp.com/secret-volume-path-{name}"] = secret[
            "mount_path"
        ]
    return annotations


def build_vault_inject_annotations(
    *,
    secrets: Sequence[Dict[str, Any]],
    role: str,
    auth_path: str = "auth/kubernetes",
    auth_type: str = "kubernetes",
    static_annotations: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Build Vault Agent Injector annotations for selected secrets.

    Skips enabling the injector when there are no secrets and no static
    inject-secret annotations, so an empty form selection does not attach a
    sidecar.
    """
    annotations: Dict[str, str] = {}
    if static_annotations:
        annotations.update({str(k): str(v) for k, v in static_annotations.items()})

    has_secret_annotations = any(
        k.startswith("vault.hashicorp.com/agent-inject-secret") for k in annotations
    )
    if not secrets and not has_secret_annotations:
        # Keep any purely static non-secret vault annotations (rare), but do not
        # force agent-inject on with nothing to render.
        return annotations

    annotations.setdefault("vault.hashicorp.com/agent-inject", "true")
    if role:
        annotations.setdefault("vault.hashicorp.com/role", role)
    if auth_type:
        annotations.setdefault("vault.hashicorp.com/auth-type", auth_type)
    if auth_path:
        annotations.setdefault("vault.hashicorp.com/auth-path", auth_path)

    for secret in secrets:
        annotations.update(annotations_for_secret(secret))

    return annotations


def resolve_selected_secrets(
    catalog: Sequence[Dict[str, Any]],
    selected_ids: Optional[Sequence[str]],
    *,
    form_enabled: bool,
    id_whitelist: Optional[Sequence[str]] = None,
    path_whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Resolve which catalog secrets should be injected.

    - form_enabled: use selected_ids (must be a subset of the catalog)
    - form disabled: inject only catalog entries marked ``default=True``
    """
    by_id = {s["id"]: s for s in catalog}

    if form_enabled:
        ids = list(selected_ids or [])
    else:
        # Without the spawn form, only auto-inject secrets explicitly marked default
        ids = [s["id"] for s in catalog if s.get("default")]

    if id_whitelist:
        allowed = set(id_whitelist)
        for secret_id in ids:
            if secret_id not in allowed:
                raise ValueError(
                    f"Selected Vault secret {secret_id!r} is not in vault_secret_whitelist"
                )

    resolved = []
    for secret_id in ids:
        if secret_id not in by_id:
            raise ValueError(
                f"Unknown Vault secret {secret_id!r}. "
                f"Options include: {', '.join(by_id) or '(none)'}"
            )
        secret = by_id[secret_id]
        if path_whitelist and secret["path"] not in path_whitelist:
            raise ValueError(
                f"Selected Vault secret path {secret['path']!r} is not allowed"
            )
        resolved.append(secret)
    return resolved


def list_kv_secrets(
    *,
    addr: str,
    token: str,
    list_path: str,
    engine: str = "kv2",
    namespace: Optional[str] = None,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    """
    LIST keys under a Vault path and return catalog entries.

    For KV v2, ``list_path`` should typically be the metadata path, e.g.
    ``secret/metadata/jupyter/alice``. Returned secret paths use ``secret/data/...``
    when engine is kv2 and the list path contains ``/metadata/``.
    """
    if not addr or not token or not list_path:
        return []

    base = addr.rstrip("/")
    # Vault LIST is requested as GET with ?list=true
    api_path = list_path.lstrip("/")
    url = f"{base}/v1/{quote(api_path, safe='/')}?list=true"
    headers = {"X-Vault-Token": token}
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        raise ValueError(
            f"Vault LIST failed for {list_path!r}: HTTP {e.code}"
        ) from e
    except URLError as e:
        raise ValueError(f"Vault LIST failed for {list_path!r}: {e.reason}") from e

    keys = payload.get("data", {}).get("keys") or []
    secrets = []
    for key in keys:
        # Skip "folders"
        if str(key).endswith("/"):
            continue
        read_path = _list_path_to_read_path(list_path, key, engine)
        secret_id = f"{api_path.rstrip('/').replace('/', '-')}-{key}"
        secrets.append(
            {
                "id": sanitize_annotation_name(secret_id),
                "display_name": str(key),
                "path": read_path,
                "engine": engine,
            }
        )
    return secrets


def _list_path_to_read_path(list_path: str, key: str, engine: str) -> str:
    base = list_path.rstrip("/")
    child = f"{base}/{key}"
    if engine == "kv2" and "/metadata/" in child:
        return child.replace("/metadata/", "/data/", 1)
    return child


def resolve_vault_token(explicit_token: str = "", env_var: str = "VAULT_TOKEN") -> str:
    """Return an explicit token or one from the environment."""
    if explicit_token:
        return explicit_token
    if env_var:
        return os.environ.get(env_var, "")
    return ""
