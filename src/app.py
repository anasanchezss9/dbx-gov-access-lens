"""
Access Lens — visao centralizada de acessos por usuario e por grupo.

Le dados REAIS do workspace:
  - Unity Catalog: system.information_schema.*_privileges (com inherited_from)
  - Objetos de workspace: /api/2.0/permissions/{type}/{id} (com inherited_from_object)
  - Identidade: SHOW GROUPS WITH USER|GROUP (directGroup=false => grupo aninhado)

Navegacao em dois niveis, por performance: primeiro o resumo por container
(catalogo / tipo de recurso), e so ao abrir um container e que os privilegios dos
assets de dentro sao consultados. As views de privilegios cobrem o metastore inteiro
(~2.650 catalogos aqui) e nao terminam sem esse recorte.

Auth: on-behalf-of-user (OBO) via X-Forwarded-Access-Token, com fallback pro SP do app.
"""

from __future__ import annotations

import concurrent.futures
import os
import time
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

APP_DIR = os.path.dirname(os.path.abspath(__file__))
# Sem default: cada ambiente injeta o seu (o setup.py preenche o app.yaml). Um default
# fixo de outro workspace so mascara erro de configuracao com um 404 confuso.
WAREHOUSE_ID = os.getenv("DATABRICKS_WAREHOUSE_ID", "")
# Genie Space de governanca (opcional). Se vazio, a aba de chat some da UI. O setup.py
# provisiona a space e grava o id aqui.
GENIE_SPACE_ID = os.getenv("GENIE_SPACE_ID", "")

# Views de privilegios do UC dentro de um catalogo. Colunas validadas no workspace.
UC_IN_CATALOG = [
    ("SCHEMA", "schema_privileges", "catalog_name", "schema_name", None),
    ("TABLE", "table_privileges", "table_catalog", "table_schema", "table_name"),
    ("VOLUME", "volume_privileges", "volume_catalog", "volume_schema", "volume_name"),
    ("FUNCTION", "routine_privileges", "routine_catalog", "routine_schema", "routine_name"),
]

# Objetos de workspace: (tipo na Permissions API, rotulo, path de listagem, chave da
# lista, campo de id, campo de nome). A Permissions API responde por objeto, entao a
# varredura e feita sob demanda, um tipo por vez.
WS_TYPES: dict[str, tuple[str, str, str, str, str | None]] = {
    "warehouses": ("SQL Warehouse", "/api/2.0/sql/warehouses", "warehouses", "id", "name"),
    "clusters": ("Cluster", "/api/2.0/clusters/list", "clusters", "cluster_id", "cluster_name"),
    "jobs": ("Job", "/api/2.2/jobs/list", "jobs", "job_id", None),
    "pipelines": ("Pipeline", "/api/2.0/pipelines", "statuses", "pipeline_id", "name"),
    "genie": ("Genie Space", "/api/2.0/genie/spaces", "spaces", "space_id", "title"),
    "apps": ("App", "/api/2.0/apps", "apps", "name", "name"),
    "dashboards": ("Dashboard", "/api/2.0/lakeview/dashboards", "dashboards", "dashboard_id", "display_name"),
    # serving e vector-search exigem o UUID interno (`id`); passar o nome da 400.
    "serving-endpoints": ("Serving Endpoint", "/api/2.0/serving-endpoints", "endpoints", "id", "name"),
    "vector-search-endpoints": ("Vector Search Endpoint", "/api/2.0/vector-search/endpoints", "endpoints", "id", "name"),
    "instance-pools": ("Instance Pool", "/api/2.0/instance-pools/list", "instance_pools", "instance_pool_id", "instance_pool_name"),
    "cluster-policies": ("Cluster Policy", "/api/2.0/policies/clusters/list", "policies", "policy_id", "name"),
}

app = FastAPI(title="Access Lens")


@app.middleware("http")
async def _init_identity(request: Request, call_next):
    """Pre-cria o set de identidades: a varredura de workspace usa threads."""
    request.state.identity_used = set()
    return await call_next(request)


# ---------------------------------------------------------------- auth / http


def _host() -> str:
    h = os.getenv("DATABRICKS_HOST", "")
    if h and not h.startswith("http"):
        h = f"https://{h}"
    return h.rstrip("/")


def _token(request: Request, force_sp: bool = False) -> str:
    """Token do usuario logado (OBO); cai pro SP do app se nao houver."""
    user_token = request.headers.get("X-Forwarded-Access-Token")
    if user_token and not force_sp:
        return user_token

    cid = os.getenv("DATABRICKS_CLIENT_ID")
    secret = os.getenv("DATABRICKS_CLIENT_SECRET")
    if not (cid and secret):
        raise HTTPException(500, "Sem credencial: nem OBO nem service principal.")

    cache = app.state.__dict__.setdefault("_sp_cache", {})
    if cache.get("exp", 0) > time.time() + 60:
        return cache["token"]

    resp = requests.post(
        f"{_host()}/oidc/v1/token",
        auth=(cid, secret),
        data={"grant_type": "client_credentials", "scope": "all-apis"},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()
    cache["token"] = payload["access_token"]
    cache["exp"] = time.time() + payload.get("expires_in", 3600)
    return cache["token"]


def _api(request: Request, method: str, path: str, force_sp: bool = False, **kw) -> dict[str, Any]:
    """
    Chamada a API do workspace.

    Databricks Apps so permite pedir o scope `sql` no consentimento OBO — SCIM e a
    Permissions API nao tem scope OBO correspondente. Por isso, num 401/403 de scope
    a chamada e repetida com o service principal do app, e a UI avisa na tela.
    """
    timeout = kw.pop("timeout", 60)

    def _call(sp: bool):
        return requests.request(
            method,
            f"{_host()}{path}",
            headers={"Authorization": f"Bearer {_token(request, force_sp=sp)}"},
            timeout=timeout,
            **kw,
        )

    r = _call(force_sp)
    if r.status_code in (401, 403) and not force_sp and os.getenv("DATABRICKS_CLIENT_ID"):
        r = _call(True)
        force_sp = True

    # set.add e atomico sob o GIL; a varredura paralela pode gravar daqui.
    getattr(request.state, "identity_used", set()).add(
        "service_principal" if force_sp else "user"
    )

    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"{path}: {r.text[:300]}")
    return r.json() if r.text else {}


def _sql(request: Request, statement: str, timeout_s: int = 110) -> list[list[Any]]:
    """Executa SQL e faz polling. A identidade usada (usuario ou SP) e resolvida em _api."""
    if not WAREHOUSE_ID:
        raise HTTPException(
            500,
            "DATABRICKS_WAREHOUSE_ID nao configurado. Rode o setup do acelerador ou "
            "defina o warehouse no app.yaml.",
        )
    out = _api(
        request,
        "POST",
        "/api/2.0/sql/statements",
        json={
            "warehouse_id": WAREHOUSE_ID,
            "statement": statement,
            "wait_timeout": "30s",
            "disposition": "INLINE",
            "format": "JSON_ARRAY",
        },
    )
    deadline = time.time() + timeout_s
    while out.get("status", {}).get("state") in ("PENDING", "RUNNING"):
        if time.time() > deadline:
            raise HTTPException(504, "Consulta de privilegios excedeu o tempo limite.")
        time.sleep(2)
        out = _api(request, "GET", f"/api/2.0/sql/statements/{out['statement_id']}")

    state = out.get("status", {}).get("state")
    if state != "SUCCEEDED":
        msg = out.get("status", {}).get("error", {}).get("message", state)
        raise HTTPException(400, f"SQL falhou: {msg[:300]}")
    return out.get("result", {}).get("data_array") or []


def _q(value: str) -> str:
    return value.replace("'", "''")


def _member_kind(member: dict) -> str:
    """
    Tipo de um membro do SCIM: 'group' | 'sp' | 'user'.

    O `$ref` vem SEM barra inicial ("Groups/1234"), entao testar por "/Groups/" nunca casa
    e todo subgrupo era classificado como usuario. Normalizado aqui num lugar so.
    """
    ref = (member.get("$ref") or "").strip("/")
    head = ref.split("/")[0].lower() if ref else ""
    if head == "groups":
        return "group"
    if head == "serviceprincipals":
        return "sp"
    return "user"


def _identity_label(request: Request) -> str:
    """Com que identidade os dados desta requisicao foram lidos."""
    used = getattr(request.state, "identity_used", set()) or set()
    if used == {"user"}:
        return "usuario logado"
    if used == {"service_principal"}:
        return "service principal do app"
    if used:
        return "usuario logado + service principal do app"
    return "desconhecida"


# ------------------------------------------------------------------ identidade


_GROUPS_TTL = 120  # segundos


def _principal_groups(request: Request, principal: str) -> list[dict[str, str]]:
    """
    Grupos de um usuario/grupo, com type=direct|indirect.

    Usa `SHOW GROUPS WITH USER|GROUP`, que resolve nested groups e devolve
    directGroup=false pros herdados — e isso que responde "esse acesso vem de qual
    grupo?". Em SQL de proposito: o escopo OBO `sql` cobre, enquanto o SCIM exigiria
    privilegio de admin e esconderia membros de nao-admins.

    Cache de TTL curto por principal: cada clique de drill-down (abrir catalogo, aba de
    recursos, etc.) e uma requisicao HTTP nova que reexecuta esta consulta. Em ambientes
    com MUITOS grupos por usuario (o caso do cliente), `SHOW GROUPS WITH USER` fica mais
    caro, entao vale evitar refaze-lo a cada navegacao. A membership muda devagar; 120s
    e um teto seguro.
    """
    cache = app.state.__dict__.setdefault("_groups_cache", {})
    hit = cache.get(principal)
    if hit and hit["exp"] > time.time():
        return hit["groups"]

    ident = principal.replace("`", "")
    groups: list[dict[str, str]] = []
    for keyword in ("USER", "GROUP"):
        try:
            rows = _sql(request, f"SHOW GROUPS WITH {keyword} `{ident}`", timeout_s=45)
        except HTTPException:
            continue
        if rows:
            groups = [
                {"name": r[0], "type": "direct" if str(r[1]).lower() == "true" else "indirect"}
                for r in rows
                if r and r[0]
            ]
            break

    cache[principal] = {"groups": groups, "exp": time.time() + _GROUPS_TTL}
    return groups


def _identity_map(groups: list[dict[str, str]], principal: str) -> dict[str, dict[str, Any]]:
    """Nome do grantee -> como esse acesso chega ate o principal."""
    out = {principal: {"via": "Direto", "group_type": None}}
    for g in groups:
        if g["name"]:
            out[g["name"]] = {"via": f"Grupo: {g['name']}", "group_type": g["type"]}
    return out


def _origin(identity_of: dict[str, dict[str, Any]], grantee: str) -> dict[str, Any]:
    return identity_of.get(grantee, {"via": "Direto", "group_type": None})


def _level(inherited: Any) -> str:
    return "No proprio objeto" if inherited in (None, "NONE", "") else f"Herdado de {inherited}"


# --------------------------------------------------------------------- rotas


@app.get("/api/me")
def me(request: Request):
    """Quem esta logado — pelos headers do Apps, pra nao cair na identidade do SP."""
    email = request.headers.get("X-Forwarded-Email") or request.headers.get(
        "X-Forwarded-Preferred-Username"
    )
    if email and "@" in email:
        return {"userName": email, "displayName": email}

    who = _api(request, "GET", "/api/2.0/preview/scim/v2/Me")
    return {"userName": who.get("userName"), "displayName": who.get("displayName")}


@app.get("/api/workspaces")
def workspaces(request: Request):
    """
    Workspaces do metastore, so pra contexto.

    A Permissions API e o token sao presos ao workspace do host (token de um workspace
    devolve 'Invalid Token' em outro), entao a aba de objetos de workspace sempre reflete
    o workspace atual. Os privilegios de UC, ao contrario, sao do metastore e valem pra
    todos os workspaces que o compartilham.
    """
    current = ""
    host = _host()
    if "adb-" in host:
        current = host.split("adb-")[1].split(".")[0]

    items: list[dict[str, Any]] = []
    try:
        rows = _sql(
            request,
            "SELECT workspace_id, workspace_name FROM system.access.workspaces_latest "
            "WHERE status = 'RUNNING' ORDER BY workspace_name LIMIT 2000",
            timeout_s=60,
        )
        items = [{"id": r[0], "name": r[1] or r[0]} for r in rows if r and r[0]]
    except HTTPException:
        pass

    name = next((w["name"] for w in items if w["id"] == current), current or "atual")
    if current and not any(w["id"] == current for w in items):
        items.insert(0, {"id": current, "name": name})

    return {
        "current_workspace_id": current,
        "current_workspace_name": name,
        "workspaces": items,
        "note": (
            f"Privilégios de Unity Catalog são do metastore: valem igualmente nos {len(items)} "
            "workspaces desta conta. Permissões em clusters, jobs, warehouses e afins são "
            "locais, e as credenciais do app só valem no workspace onde ele está publicado "
            "(o service principal recebe 'invalid_client' ao tentar autenticar em outro). "
            "Ao escolher outro workspace, o app mostra os privilégios de UC e explica que a "
            "aba de recursos exige uma instância publicada lá."
        ),
    }


@app.get("/api/principals")
def principals(request: Request, q: str = Query("", min_length=0), kind: str = "users"):
    """Busca usuarios ou grupos pro seletor. SHOW USERS/GROUPS roda com o escopo `sql`."""
    stmt = "SHOW GROUPS" if kind == "groups" else "SHOW USERS"
    if q:
        stmt += f" LIKE '*{_q(q)}*'"

    try:
        rows = _sql(request, stmt, timeout_s=45)
    except HTTPException:
        return {"items": [], "total": 0}

    items = [{"name": r[0]} for r in rows if r and r[0]]
    items.sort(key=lambda i: i["name"].lower())
    return {"items": items[:200], "total": len(items)}


@app.get("/api/overview")
def overview(request: Request, principal: str):
    """
    NIVEL 1 — o resumo. Nao consulta asset nenhum.

    Devolve os grupos do principal, os catalogos onde ele tem privilegio (agregado a
    partir de catalog_privileges + schema_privileges) e a lista de tipos de recurso de
    workspace disponiveis. Os detalhes vem depois, quando a pessoa abre um container.
    """
    groups = _principal_groups(request, principal)
    identity_of = _identity_map(groups, principal)
    grantees = ", ".join(f"'{_q(n)}'" for n in identity_of)

    # Agregado por catalogo: grants EXPLICITOS no catalogo OU num schema dele.
    #
    # Filtramos `inherited_from` para contar so o grant onde ele foi de fato concedido, nao
    # as copias herdadas: um grant no catalogo se propaga para cada schema como uma linha
    # `inherited_from='CATALOG'` em schema_privileges. Sem o filtro, esse mesmo grant era
    # contado uma vez no catalogo + uma vez por schema (aqui, ~75% das linhas eram herdadas),
    # inflando o total e pesando no shuffle do GROUP BY.
    #
    # A ORIGEM continua correta: quem concede acesso ao catalogo aparece em
    # catalog_privileges, entao o grantee (e portanto o caminho direto/grupo/aninhado) e
    # preservado — nenhum catalogo some ao filtrar (validado). O numero passa a significar
    # "grants explicitos", que e a leitura honesta para uma revisao de acesso.
    rows = _sql(
        request,
        f"""
        SELECT catalog_name,
               SUM(n) AS total,
               array_join(array_distinct(flatten(collect_list(grantees))), ',') AS grantees,
               MAX(has_catalog_grant) AS has_catalog_grant
        FROM (
          SELECT catalog_name, COUNT(*) n, collect_set(grantee) grantees, 1 has_catalog_grant
          FROM system.information_schema.catalog_privileges
          WHERE grantee IN ({grantees})
            AND (inherited_from IS NULL OR inherited_from = 'NONE')
          GROUP BY catalog_name
          UNION ALL
          SELECT catalog_name, COUNT(*) n, collect_set(grantee) grantees, 0 has_catalog_grant
          FROM system.information_schema.schema_privileges
          WHERE grantee IN ({grantees})
            AND (inherited_from IS NULL OR inherited_from = 'NONE')
          GROUP BY catalog_name
        )
        GROUP BY catalog_name
        ORDER BY total DESC, catalog_name
        LIMIT 500
        """,
        timeout_s=110,
    )

    catalogs = []
    for name, total, grantee_csv, has_cat in rows:
        names = [g for g in (grantee_csv or "").split(",") if g]
        vias = {_origin(identity_of, g)["via"] for g in names}
        nested = any(_origin(identity_of, g)["group_type"] == "indirect" for g in names)
        catalogs.append({
            "catalog": name,
            "privileges": int(total),
            "direct": principal in names,
            "via_groups": sorted(v.replace("Grupo: ", "") for v in vias if v != "Direto"),
            "has_nested": nested,
            "catalog_level_grant": bool(int(has_cat)),
        })

    return {
        "principal": principal,
        "groups": groups,
        "catalogs": catalogs,
        "resource_types": [
            {"key": k, "label": v[0]} for k, v in sorted(WS_TYPES.items(), key=lambda i: i[1][0])
        ],
        "queried_as": _identity_label(request),
    }


@app.get("/api/group/{group_name}/members")
def group_members(
    request: Request,
    group_name: str,
    q: str = Query("", description="Filtra membros por nome."),
    limit: int = Query(60, ge=1, le=300),
):
    """
    Membros de um grupo: usuarios, service principals e subgrupos.

    Nao existe sintaxe SQL pra isso (`SHOW USERS IN GROUP` e variantes dao parse error),
    entao aqui e SCIM — que exige admin (nao-admin recebe members vazio, sem erro).
    Grupos grandes sao reais: `account users` tem ~21 mil membros, por isso o filtro
    server-side e o teto.
    """
    data = _api(
        request,
        "GET",
        "/api/2.0/preview/scim/v2/Groups",
        params={"filter": f'displayName eq "{_q(group_name)}"'},
        timeout=90,
    )
    hits = data.get("Resources") or []
    if not hits:
        raise HTTPException(404, f"Grupo '{group_name}' não encontrado.")

    members = hits[0].get("members") or []
    users, sps, subgroups = [], [], []
    for m in members:
        kind = _member_kind(m)
        entry = {"display": m.get("display") or m.get("value") or "", "id": m.get("value")}
        if kind == "group":
            subgroups.append(entry)
        elif kind == "sp":
            sps.append(entry)
        else:
            users.append(entry)

    def pick(seq: list[dict]) -> list[dict]:
        ql = q.lower()
        found = [e for e in seq if not ql or ql in (e["display"] or "").lower()]
        return sorted(found, key=lambda e: (e["display"] or "").lower())[:limit]

    shown_users = pick(users)

    # SCIM devolve so o id numerico do membro; os grants usam userName (e-mail). Sem
    # resolver, clicar num membro analisaria um nome que nao existe como grantee.
    # Resolvido apenas para os membros exibidos, em paralelo.
    def resolve(entry: dict) -> dict:
        if not entry.get("id"):
            return entry
        try:
            u = _api(
                request,
                "GET",
                f"/api/2.0/preview/scim/v2/Users/{entry['id']}",
                params={"attributes": "userName,displayName"},
                timeout=20,
            )
        except HTTPException:
            return entry
        return {
            "display": u.get("displayName") or entry["display"],
            "principal": u.get("userName"),
            "id": entry["id"],
        }

    if shown_users:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            shown_users = list(pool.map(resolve, shown_users))

    return {
        "group": group_name,
        "totals": {
            "members": len(members),
            "users": len(users),
            "service_principals": len(sps),
            "subgroups": len(subgroups),
        },
        "users": shown_users,
        "service_principals": pick(sps),
        "subgroups": pick(subgroups),
        "parents": [
            {"name": g.get("display"), "type": g.get("type", "direct")}
            for g in hits[0].get("groups") or []
        ],
        "filtered": bool(q),
        "limit": limit,
        "queried_as": _identity_label(request),
    }


@app.get("/api/catalog/{catalog}")
def catalog_detail(request: Request, catalog: str, principal: str):
    """NIVEL 2 (UC) — privilegios nos assets DENTRO de um catalogo."""
    groups = _principal_groups(request, principal)
    identity_of = _identity_map(groups, principal)
    grantees = ", ".join(f"'{_q(n)}'" for n in identity_of)
    cat = _q(catalog)

    selects = [
        f"SELECT 'CATALOG' AS k, grantee, CAST(NULL AS STRING) AS obj, privilege_type, inherited_from "
        f"FROM system.information_schema.catalog_privileges "
        f"WHERE grantee IN ({grantees}) AND catalog_name = '{cat}'"
    ]
    for kind, view, c_col, s_col, n_col in UC_IN_CATALOG:
        obj = f"concat({s_col}, '.', {n_col})" if n_col else s_col
        selects.append(
            f"SELECT '{kind}', grantee, {obj}, privilege_type, inherited_from "
            f"FROM system.information_schema.{view} "
            f"WHERE grantee IN ({grantees}) AND {c_col} = '{cat}'"
        )

    rows = _sql(request, " UNION ALL ".join(selects) + " LIMIT 5000", timeout_s=110)

    items = []
    for kind, grantee, obj, priv, inherited in rows:
        origin = _origin(identity_of, grantee)
        items.append({
            "securable_type": kind,
            "object": f"{catalog}.{obj}" if obj else catalog,
            "privilege": priv,
            "grant_level": _level(inherited),
            "granted_to": grantee,
            "via": origin["via"],
            "group_type": origin["group_type"],
        })
    items.sort(key=lambda r: (r["securable_type"], r["object"], r["privilege"] or ""))
    return {
        "catalog": catalog,
        "count": len(items),
        "truncated": len(rows) >= 5000,
        "items": items,
        "queried_as": _identity_label(request),
    }


@app.get("/api/resource/{resource_type}")
def resource_detail(
    request: Request,
    resource_type: str,
    principal: str,
    limit: int = Query(60, ge=1, le=400),
):
    """
    NIVEL 2 (workspace) — permissoes dos objetos de UM tipo de recurso.

    A Permissions API responde por objeto, entao isso e uma varredura: lista os objetos
    do tipo e consulta a ACL de cada um em paralelo. Por isso e sob demanda, um tipo por vez.
    """
    if resource_type not in WS_TYPES:
        raise HTTPException(400, f"Tipo invalido. Use um de: {', '.join(sorted(WS_TYPES))}")
    label, path, key, id_field, name_field = WS_TYPES[resource_type]

    groups = _principal_groups(request, principal)
    identity_of = _identity_map(groups, principal)
    lookup = {k.lower(): v for k, v in identity_of.items()}

    try:
        data = _api(request, "GET", path, params={"page_size": 100}, timeout=45)
    except HTTPException:
        data = {}
    objects = data.get(key) or []
    if not isinstance(objects, list):
        objects = []
    scanned = objects[:limit]

    def check(item: dict) -> list[dict]:
        oid = item.get(id_field)
        if oid is None:
            return []
        display = (item.get(name_field) if name_field else None) or item.get(
            "settings", {}
        ).get("name") or str(oid)
        try:
            acl = _api(request, "GET", f"/api/2.0/permissions/{resource_type}/{oid}", timeout=30)
        except HTTPException:
            return []
        found = []
        for entry in acl.get("access_control_list") or []:
            who = (
                entry.get("user_name")
                or entry.get("group_name")
                or entry.get("service_principal_name")
                or ""
            )
            origin = lookup.get(who.lower())
            if origin is None:
                continue
            for perm in entry.get("all_permissions") or []:
                src = perm.get("inherited_from_object") or []
                found.append({
                    "object_type": label,
                    "object": display,
                    "permission": perm.get("permission_level"),
                    "grant_level": (
                        f"Herdado de {', '.join(src)}" if perm.get("inherited")
                        else "No proprio objeto"
                    ),
                    "granted_to": who,
                    "via": origin["via"],
                    "group_type": origin["group_type"],
                })
        return found

    items: list[dict] = []
    if scanned:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            for chunk in pool.map(check, scanned):
                items.extend(chunk)

    items.sort(key=lambda r: (r["object"], r["permission"] or ""))
    return {
        "resource_type": resource_type,
        "label": label,
        "count": len(items),
        "objects_scanned": len(scanned),
        "objects_total": len(objects),
        "items": items,
        "queried_as": _identity_label(request),
    }


@app.get("/api/resource/{resource_type}/objects")
def resource_objects(
    request: Request,
    resource_type: str,
    q: str = Query("", description="Filtra por nome do objeto."),
    limit: int = Query(200, ge=1, le=1000),
):
    """
    Lista os objetos de um tipo, para escolher UM e inspecionar.

    Entrada da visao inversa: em vez de "o que esta pessoa acessa", permite
    "quem acessa ESTE cluster".
    """
    if resource_type not in WS_TYPES:
        raise HTTPException(400, f"Tipo invalido. Use um de: {', '.join(sorted(WS_TYPES))}")
    label, path, key, id_field, name_field = WS_TYPES[resource_type]

    try:
        data = _api(request, "GET", path, params={"page_size": 100}, timeout=45)
    except HTTPException:
        data = {}
    objects = data.get(key) or []
    if not isinstance(objects, list):
        objects = []

    ql = q.lower()
    items = []
    for item in objects:
        oid = item.get(id_field)
        if oid is None:
            continue
        display = (item.get(name_field) if name_field else None) or item.get(
            "settings", {}
        ).get("name") or str(oid)
        if ql and ql not in str(display).lower():
            continue
        items.append({"id": str(oid), "name": display})

    items.sort(key=lambda i: i["name"].lower())
    return {
        "resource_type": resource_type,
        "label": label,
        "total": len(objects),
        "count": len(items),
        "items": items[:limit],
        "supports_usage": resource_type in ("warehouses", "clusters"),
    }


@app.get("/api/resource/{resource_type}/{object_id}/who")
def resource_who(request: Request, resource_type: str, object_id: str, name: str = ""):
    """
    VISAO INVERSA — quem tem acesso a ESTE objeto e com qual permissao.

    Diferente do resto do app: nao parte de um principal. Lista a ACL inteira e, para
    cada entrada, diz se e usuario, grupo ou service principal, e se a permissao foi dada
    no objeto ou herdada do container.
    """
    if resource_type not in WS_TYPES:
        raise HTTPException(400, f"Tipo invalido. Use um de: {', '.join(sorted(WS_TYPES))}")
    label = WS_TYPES[resource_type][0]

    acl = _api(request, "GET", f"/api/2.0/permissions/{resource_type}/{object_id}", timeout=45)

    items = []
    for entry in acl.get("access_control_list") or []:
        if entry.get("group_name"):
            who, kind = entry["group_name"], "grupo"
        elif entry.get("service_principal_name"):
            who = entry.get("display_name") or entry["service_principal_name"]
            kind = "service principal"
        else:
            who, kind = entry.get("user_name") or entry.get("display_name") or "", "usuário"
        for perm in entry.get("all_permissions") or []:
            src = perm.get("inherited_from_object") or []
            items.append({
                "principal": who,
                "kind": kind,
                "permission": perm.get("permission_level"),
                "grant_level": (
                    f"Herdado de {', '.join(src)}" if perm.get("inherited")
                    else "No proprio objeto"
                ),
            })

    order = {"grupo": 0, "usuário": 1, "service principal": 2}
    items.sort(key=lambda r: (order.get(r["kind"], 9), r["principal"].lower()))
    return {
        "resource_type": resource_type,
        "label": label,
        "object_id": object_id,
        "object_name": name or object_id,
        "count": len(items),
        "groups": sum(1 for i in items if i["kind"] == "grupo"),
        "users": sum(1 for i in items if i["kind"] == "usuário"),
        "service_principals": sum(1 for i in items if i["kind"] == "service principal"),
        "items": items,
        "queried_as": _identity_label(request),
    }


@app.get("/api/resource/{resource_type}/{object_id}/impact")
def resource_impact(request: Request, resource_type: str, object_id: str, days: int = 30):
    """
    IMPACTO DE REMOVER um recurso computacional.

    "Quem tem permissao" nao e a mesma pergunta que "quem seria afetado". Aqui vem o USO
    REAL nos ultimos N dias:
      - warehouse → system.query.history (quem rodou query e quando)
      - cluster   → system.billing.usage (quem rodou e quanto DBU)
    Um recurso com permissao ampla e uso zero e candidato a remocao; um com poucos
    usuarios mas uso diario, nao.
    """
    if resource_type not in ("warehouses", "clusters"):
        raise HTTPException(
            400,
            "Uso real disponivel apenas para warehouses (query.history) e clusters "
            "(billing.usage). Outros tipos: use a aba de quem tem acesso.",
        )

    oid = _q(object_id)
    if resource_type == "warehouses":
        stmt = f"""
            SELECT executed_by AS principal, COUNT(*) AS acoes,
                   CAST(MAX(start_time) AS STRING) AS ultimo_uso
            FROM system.query.history
            WHERE compute.warehouse_id = '{oid}'
              AND start_time >= current_timestamp() - INTERVAL {int(days)} DAYS
            GROUP BY 1 ORDER BY acoes DESC LIMIT 100
        """
        unit = "queries"
    else:
        stmt = f"""
            SELECT identity_metadata.run_as AS principal,
                   CAST(ROUND(SUM(usage_quantity), 1) AS STRING) AS acoes,
                   CAST(MAX(usage_date) AS STRING) AS ultimo_uso
            FROM system.billing.usage
            WHERE usage_metadata.cluster_id = '{oid}'
              AND usage_date >= current_date() - {int(days)}
            GROUP BY 1 ORDER BY SUM(usage_quantity) DESC LIMIT 100
        """
        unit = "DBUs"

    rows = _sql(request, stmt, timeout_s=110)
    users = [
        {"principal": r[0] or "(não identificado)", "amount": r[1], "last_use": (r[2] or "")[:10]}
        for r in rows
    ]
    return {
        "resource_type": resource_type,
        "object_id": object_id,
        "days": days,
        "unit": unit,
        "active_principals": len(users),
        "items": users,
        "verdict": (
            "Sem uso registrado na janela — provavelmente seguro remover."
            if not users
            else f"{len(users)} identidade(s) usaram este recurso nos últimos {days} dias."
        ),
        "queried_as": _identity_label(request),
    }


@app.get("/api/object/impact")
def object_impact(request: Request, full_name: str, days: int = 90):
    """
    IMPACTO DE REMOVER uma tabela/view: o que quebra a jusante.

    Usa system.access.table_lineage: tabelas derivadas + os jobs, notebooks e dashboards
    que leem o objeto. Responde "se eu apagar isso, o que para de funcionar?".
    """
    fq = _q(full_name)
    downstream = _sql(
        request,
        f"""
        SELECT target_table_full_name, MAX(target_type) AS tipo, COUNT(*) AS eventos
        FROM system.access.table_lineage
        WHERE source_table_full_name = '{fq}'
          AND target_table_full_name IS NOT NULL
          AND target_table_full_name <> '{fq}'
          AND event_date >= current_date() - {int(days)}
        GROUP BY 1 ORDER BY eventos DESC LIMIT 200
        """,
        timeout_s=110,
    )
    consumers = _sql(
        request,
        f"""
        SELECT entity_type, entity_id, COUNT(*) AS eventos,
               CAST(MAX(event_date) AS STRING) AS ultimo
        FROM system.access.table_lineage
        WHERE source_table_full_name = '{fq}'
          AND entity_type IS NOT NULL
          AND event_date >= current_date() - {int(days)}
        GROUP BY 1, 2 ORDER BY eventos DESC LIMIT 200
        """,
        timeout_s=110,
    )
    upstream = _sql(
        request,
        f"""
        SELECT source_table_full_name, COUNT(*) AS eventos
        FROM system.access.table_lineage
        WHERE target_table_full_name = '{fq}'
          AND source_table_full_name IS NOT NULL
          AND source_table_full_name <> '{fq}'
          AND event_date >= current_date() - {int(days)}
        GROUP BY 1 ORDER BY eventos DESC LIMIT 100
        """,
        timeout_s=110,
    )

    down = [{"object": r[0], "type": r[1] or "TABLE", "events": r[2]} for r in downstream]
    cons = [
        {"entity_type": r[0], "entity_id": r[1], "events": r[2], "last": r[3]}
        for r in consumers
    ]
    up = [{"object": r[0], "events": r[1]} for r in upstream]

    risk = "baixo" if not down and not cons else ("alto" if len(down) + len(cons) > 5 else "médio")
    return {
        "object": full_name,
        "days": days,
        "downstream": down,
        "consumers": cons,
        "upstream": up,
        "risk": risk,
        "verdict": (
            f"Nenhuma dependência registrada nos últimos {days} dias — "
            "atenção: linhagem só cobre o que foi executado nessa janela."
            if not down and not cons
            else f"{len(down)} objeto(s) derivado(s) e {len(cons)} consumidor(es) "
                 f"(jobs, notebooks, dashboards) dependem deste objeto."
        ),
        "queried_as": _identity_label(request),
    }


@app.get("/api/group/{group_name}/tree")
def group_tree(request: Request, group_name: str, depth: int = Query(2, ge=1, le=3)):
    """
    GRUPOS DENTRO DE GRUPOS — a arvore de nesting, para baixo e para cima.

    SCIM devolve `members` (para baixo) e `groups` (para cima). Grupos aninhados existem
    de verdade: `users-clone-...` contem 961 subgrupos. Expande em profundidade limitada
    para nao explodir.

    ATENCAO: usar `attributes=displayName,members` no SCIM remove o `$ref` de cada membro,
    e sem `$ref` nao ha como distinguir subgrupo de usuario — os subgrupos ficam invisiveis.
    Por isso aqui NAO se filtra atributos.
    """

    def fetch(name: str) -> dict | None:
        try:
            data = _api(
                request,
                "GET",
                "/api/2.0/preview/scim/v2/Groups",
                params={"filter": f'displayName eq "{_q(name)}"'},
                timeout=90,
            )
        except HTTPException:
            return None
        hits = data.get("Resources") or []
        return hits[0] if hits else None

    root = fetch(group_name)
    if not root:
        raise HTTPException(404, f"Grupo '{group_name}' não encontrado.")

    def split(node: dict) -> dict:
        subs, users, sps = [], 0, 0
        for m in node.get("members") or []:
            kind = _member_kind(m)
            if kind == "group":
                subs.append(m.get("display") or m.get("value"))
            elif kind == "sp":
                sps += 1
            else:
                users += 1
        return {"subgroups": [s for s in subs if s], "users": users, "sps": sps}

    def build(name: str, node: dict, level: int) -> dict:
        info = split(node)
        out = {
            "name": name,
            "users": info["users"],
            "service_principals": info["sps"],
            "subgroup_count": len(info["subgroups"]),
            "children": [],
        }
        if level < depth and info["subgroups"]:
            # Expandir uma amostra: 961 subgrupos x N niveis nao cabe numa requisicao.
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                fetched = list(pool.map(fetch, info["subgroups"][:25]))
            for child_name, child in zip(info["subgroups"][:25], fetched):
                out["children"].append(
                    build(child_name, child, level + 1)
                    if child
                    else {"name": child_name, "users": 0, "service_principals": 0,
                          "subgroup_count": 0, "children": [], "unresolved": True}
                )
            out["children_truncated"] = max(0, len(info["subgroups"]) - 25)
        return out

    tree = build(group_name, root, 0)
    tree["parents"] = [
        {"name": g.get("display"), "type": g.get("type", "direct")}
        for g in root.get("groups") or []
    ]
    tree["depth"] = depth
    tree["queried_as"] = _identity_label(request)
    return tree


@app.get("/api/object/who")
def object_who(request: Request, securable_type: str, full_name: str):
    """Visao inversa: dado um objeto UC, quem tem acesso e por qual caminho."""
    kind = securable_type.upper()
    if kind == "CATALOG":
        view, cols = "catalog_privileges", ["catalog_name"]
    else:
        spec = {s[0]: s for s in UC_IN_CATALOG}.get(kind)
        if not spec:
            raise HTTPException(
                400, "Tipo invalido. Use CATALOG, SCHEMA, TABLE, VOLUME ou FUNCTION."
            )
        _, view, c_col, s_col, n_col = spec
        cols = [c for c in (c_col, s_col, n_col) if c]

    parts = full_name.split(".")
    where = [f"{c} = '{_q(p)}'" for c, p in zip(cols, parts)]
    rows = _sql(
        request,
        f"SELECT grantee, privilege_type, inherited_from, grantor "
        f"FROM system.information_schema.{view} WHERE " + " AND ".join(where) + " LIMIT 2000",
    )
    return {
        "object": full_name,
        "securable_type": kind,
        "items": [
            {
                "grantee": g,
                "privilege": p,
                "grant_level": _level(i),
                "grantor": gr,
            }
            for g, p, i, gr in rows
        ],
        "queried_as": _identity_label(request),
    }


@app.get("/api/scope-note")
def scope_note():
    """O que o app cobre e o que e limitacao da plataforma — honestidade na demo."""
    return {
        "fontes": [
            "Unity Catalog: system.information_schema.{catalog,schema,table,volume,routine}_privileges "
            "— a coluna inherited_from separa grant no objeto de grant herdado do pai",
            "Objetos de workspace: /api/2.0/permissions/{tipo}/{id} "
            "— traz group_name e inherited_from_object",
            "Identidade e grupos aninhados: SHOW GROUPS WITH USER|GROUP (directGroup=false = aninhado)",
        ],
        "limitacoes": [
            "Nao existe system table de grants unificada nem de identidade: system.access nao tem "
            "tabela de privilegios nem de usuarios/grupos.",
            "As views de privilegios cobrem o metastore inteiro e nao terminam sem recorte — por isso "
            "a navegacao e em dois niveis (resumo por container, detalhe sob demanda).",
            "A Permissions API responde por objeto: nao existe consulta 'todos os acessos do usuario X', "
            "e preciso varrer objeto por objeto.",
            "Permissoes de workspace sao locais ao workspace do app: o token de um workspace nao vale "
            "em outro. Privilegios de UC, por serem do metastore, valem para todos.",
            "O consentimento OBO do Databricks Apps so oferece o escopo `sql`; SCIM e a Permissions API "
            "nao tem escopo OBO, entao essas leituras usam o service principal do app.",
        ],
    }


# ------------------------------------------------------------- Genie (chat)


def _genie_message(request: Request, conv_id: str, msg_id: str) -> dict[str, Any]:
    """
    Poll de uma mensagem do Genie ate ela sair de PENDING/EXECUTING_QUERY.

    Diferente do SQL statements API, o Genie tem varios estados intermediarios
    (SUBMITTED, FILTERING_CONTEXT, ASKING_AI, EXECUTING_QUERY...). So COMPLETED,
    FAILED e CANCELLED sao terminais.
    """
    base = f"/api/2.0/genie/spaces/{GENIE_SPACE_ID}/conversations/{conv_id}/messages/{msg_id}"
    deadline = time.time() + 120
    while True:
        msg = _api(request, "GET", base, timeout=30)
        status = msg.get("status")
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            return msg
        if time.time() > deadline:
            raise HTTPException(504, "Genie excedeu o tempo limite ao responder.")
        time.sleep(2)


def _genie_answer(request: Request, conv_id: str, msg: dict[str, Any]) -> dict[str, Any]:
    """Normaliza a resposta do Genie: texto, SQL gerado e (se houver) as linhas."""
    if msg.get("status") != "COMPLETED":
        detail = (msg.get("error") or {}).get("message") or msg.get("status")
        raise HTTPException(400, f"Genie: {str(detail)[:300]}")

    text, sql, table = "", "", None
    for att in msg.get("attachments") or []:
        if att.get("text"):
            text = att["text"].get("content", "")
        if att.get("query"):
            q = att["query"]
            sql = q.get("query", "")
            att_id = att.get("attachment_id")
            # Resultado vem por endpoint separado; so buscamos se houver query.
            if att_id:
                try:
                    res = _api(
                        request,
                        "GET",
                        f"/api/2.0/genie/spaces/{GENIE_SPACE_ID}/conversations/{conv_id}"
                        f"/messages/{msg['id']}/query-result/{att_id}",
                        timeout=60,
                    )
                    sr = (res.get("statement_response") or {})
                    cols = [
                        c.get("name")
                        for c in sr.get("manifest", {}).get("schema", {}).get("columns", [])
                    ]
                    data = (sr.get("result") or {}).get("data_array") or []
                    table = {"columns": cols, "rows": data[:100], "truncated": len(data) > 100}
                except HTTPException:
                    table = None
    return {
        "conversation_id": conv_id,
        "message_id": msg.get("id"),
        "text": text,
        "sql": sql,
        "table": table,
        "queried_as": _identity_label(request),
    }


@app.get("/api/genie/config")
def genie_config():
    """A UI usa isto para decidir se mostra a aba de chat."""
    return {"enabled": bool(GENIE_SPACE_ID), "space_id": GENIE_SPACE_ID}


@app.post("/api/genie/ask")
async def genie_ask(request: Request):
    """
    Pergunta em linguagem natural sobre acessos/ambiente.

    Sem conversation_id => inicia conversa; com => e follow-up (mantem contexto).
    O escopo OBO `sql` do Apps nao cobre a Genie API, entao na pratica isso cai no
    service principal do app — a resposta reflete o acesso do SP, e a UI avisa.
    """
    if not GENIE_SPACE_ID:
        raise HTTPException(400, "Genie Space nao configurada neste ambiente.")
    body = await request.json()
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(400, "Pergunta vazia.")
    conv_id = body.get("conversation_id")

    if conv_id:
        started = _api(
            request,
            "POST",
            f"/api/2.0/genie/spaces/{GENIE_SPACE_ID}/conversations/{conv_id}/messages",
            json={"content": content},
            timeout=60,
        )
        msg_id = started.get("id") or started.get("message_id")
    else:
        started = _api(
            request,
            "POST",
            f"/api/2.0/genie/spaces/{GENIE_SPACE_ID}/start-conversation",
            json={"content": content},
            timeout=60,
        )
        conv_id = (started.get("conversation") or {}).get("id") or started.get("conversation_id")
        msg = started.get("message") or {}
        msg_id = msg.get("id") or started.get("message_id")

    if not (conv_id and msg_id):
        raise HTTPException(500, "Genie nao retornou ids de conversa/mensagem.")
    final = _genie_message(request, conv_id, msg_id)
    return _genie_answer(request, conv_id, final)


app.mount("/", StaticFiles(directory=os.path.join(APP_DIR, "static"), html=True), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(APP_DIR, "static", "index.html"))
