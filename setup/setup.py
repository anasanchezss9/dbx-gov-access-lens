#!/usr/bin/env python3
"""
Setup one-shot do acelerador Access Lens.

Roda NO AMBIENTE DO CLIENTE, uma vez, antes (ou depois) do `databricks bundle deploy`.
E idempotente: rodar de novo nao duplica nada.

O que faz:
  1. Valida a config (host, warehouse, service principal do app).
  2. Garante que o service principal do app seja admin do workspace — a Permissions API,
     o SCIM e `SHOW GROUPS WITH USER` so enxergam acesso de terceiros com admin. Se nao
     tiver permissao para conceder, explica exatamente o que o cliente precisa fazer.
  3. Provisiona uma Genie Space de governanca apontada para as system tables (audit,
     linhagem, consumo, privilegios) com instrucoes e perguntas de exemplo.
  4. Grava GENIE_SPACE_ID e DATABRICKS_WAREHOUSE_ID no app.yaml, para o app subir pronto.

Uso:
    export DATABRICKS_HOST=https://<workspace>.cloud.databricks.com   # ou azuredatabricks.net
    export DATABRICKS_WAREHOUSE_ID=<id do warehouse SQL>
    # autenticacao: perfil da CLI, ou DATABRICKS_TOKEN, ou OAuth do proprio SDK
    python setup/setup.py --app-name access-lens

    # so provisionar a Genie (pular grant de admin):
    python setup/setup.py --skip-admin-grant
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

try:
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.errors import DatabricksError
except ImportError:
    sys.exit("Falta o SDK. Rode:  pip install databricks-sdk")

APP_YAML = Path(__file__).resolve().parent.parent / "src" / "app.yaml"

# Tabelas de sistema que a Genie Space consulta. So system.* — nada especifico do cliente,
# entao a mesma sala funciona em qualquer metastore. Ordenadas por identifier (exigido pela
# API do Genie). information_schema.*_privileges nao entram: sao por-catalogo e a Genie nao
# lida bem com o volume; o app ja cobre privilegios em tela.
GENIE_TABLES = sorted([
    "system.access.audit",
    "system.access.table_lineage",
    "system.access.column_lineage",
    "system.access.workspaces_latest",
    "system.billing.usage",
    "system.compute.clusters",
    "system.compute.warehouses",
    "system.query.history",
    "system.lakeflow.jobs",
])

GENIE_INSTRUCTIONS = [
    "Você é um assistente de GOVERNANÇA e SEGURANÇA de dados. Responde perguntas sobre "
    "acessos, concessões de privilégio, uso de recursos, consumo e linhagem, usando as "
    "system tables do Databricks.",
    "Concessões e revogações de acesso estão em system.access.audit: filtre "
    "action_name IN ('generateTemporaryTableCredential','createGrant','removeGrant',"
    "'updatePermissions') e use request_params para o objeto e o grantee. O ator é "
    "user_identity.email e o horário é event_time.",
    "Consumo/custo vem de system.billing.usage (usage_quantity = DBUs, "
    "usage_metadata traz cluster_id/warehouse_id/job_id). Uso interativo de SQL vem de "
    "system.query.history (executed_by, compute.warehouse_id, start_time). Dependências "
    "entre tabelas vêm de system.access.table_lineage e column_lineage.",
    "Ao falar de datas relativas ('últimos 30 dias', 'mês passado'), use "
    "current_timestamp()/current_date() com INTERVAL. Sempre agrupe e ordene por "
    "relevância (contagem ou volume) e limite o resultado.",
]

GENIE_SAMPLES = [
    "Quais GRANTs foram concedidos nos últimos 30 dias e por quem?",
    "Quais os 10 principais consumidores de DBU no último mês?",
    "Quais tabelas não são consultadas há mais de 90 dias?",
    "Quem executou queries fora do horário comercial na última semana?",
    "Quais warehouses tiveram mais usuários distintos nos últimos 30 dias?",
]


def _log(msg: str) -> None:
    print(f"  {msg}", flush=True)


def ensure_admin(w: WorkspaceClient, app_name: str, skip: bool) -> None:
    """Garante o SP do app no grupo `admins`. Sem permissão, instrui em vez de falhar."""
    print("\n[2/4] Service principal do app como admin do workspace")
    if skip:
        _log("pulado (--skip-admin-grant).")
        return
    try:
        app = w.apps.get(name=app_name)
    except DatabricksError as e:
        _log(f"App '{app_name}' ainda não existe ({e}). Rode 'databricks bundle deploy' "
             "antes, ou passe --skip-admin-grant e conceda o admin manualmente depois.")
        return

    sp_id = getattr(app, "service_principal_id", None) or getattr(
        app, "service_principal_client_id", None
    )
    sp_name = getattr(app, "service_principal_name", None)
    _log(f"SP do app: {sp_name or sp_id}")

    try:
        admins = next((g for g in w.groups.list(filter='displayName eq "admins"')), None)
        if not admins:
            _log("Grupo 'admins' não encontrado — conceda o admin ao SP manualmente.")
            return
        members = {m.value for m in (admins.members or [])}
        if str(sp_id) in members:
            _log("Já é admin. Nada a fazer.")
            return
        from databricks.sdk.service.iam import Patch, PatchOp, PatchSchema
        w.groups.patch(
            admins.id,
            operations=[Patch(op=PatchOp.ADD, path="members", value=[{"value": str(sp_id)}])],
            schemas=[PatchSchema.URN_IETF_PARAMS_SCIM_API_MESSAGES_2_0_PATCH_OP],
        )
        _log("SP adicionado ao grupo 'admins'. IMPORTANTE: faça redeploy do app "
             "(o token do SP só renova o admin no restart).")
    except DatabricksError as e:
        _log(f"Sem permissão para conceder admin ({e}).")
        _log("Peça a um admin do workspace para adicionar o SP acima ao grupo 'admins'. "
             "Sem isso, a coluna 'chega por' e os membros de grupo ficam vazios.")


def provision_genie(w: WorkspaceClient, warehouse_id: str) -> str | None:
    """Cria a Genie Space sobre as system tables. Retorna o space_id."""
    print("\n[3/4] Provisionando a Genie Space de governança")
    try:
        space = w.genie.create_space(
            warehouse_id=warehouse_id,
            title="Access Lens — Governança",
            description="Perguntas em linguagem natural sobre acessos, consumo e linhagem "
                        "usando as system tables do Databricks.",
            serialized_space=_serialized_space(str(w.get_workspace_id())),
        )
        _log(f"Genie Space criada: {space.space_id}")
        return space.space_id
    except DatabricksError as e:
        _log(f"Não foi possível criar a Genie Space automaticamente ({e}).")
        _log("Crie uma sala manualmente sobre as system tables e passe o id via "
             "--genie-space-id, ou defina GENIE_SPACE_ID no app.yaml.")
        return None


def _serialized_space(workspace_id: str) -> str:
    """
    Monta o serialized_space. Gotchas validados (custaram debug):
      - data_sources.tables ordenado por identifier;
      - sample_questions ordenado por id;
      - instructions.join_specs/sql_snippets: ausentes se vazios (não [] );
      - benchmarks é {"questions": []}, não [].
    """
    qs = [{"id": uuid.uuid4().hex, "question": [q]} for q in GENIE_SAMPLES]
    qs.sort(key=lambda x: x["id"])
    ss = {
        "version": 2,
        "config": {"sample_questions": qs},
        "data_sources": {"tables": [{"identifier": t} for t in GENIE_TABLES]},
        "instructions": {
            "text_instructions": [{
                "id": uuid.uuid4().hex,
                "content": GENIE_INSTRUCTIONS + [
                    f"O workspace atual, onde o Access Lens está publicado, tem workspace_id = "
                    f"{workspace_id}. As system tables trazem dados de todos os workspaces da "
                    "conta: quando a pergunta disser 'neste workspace' ou não citar outro "
                    f"workspace, filtre por workspace_id = '{workspace_id}' e diga isso na resposta.",
                ],
            }]
        },
        "benchmarks": {"questions": []},
    }
    return json.dumps(ss)


def write_app_yaml(warehouse_id: str, genie_space_id: str | None) -> None:
    """Grava/atualiza os env vars no app.yaml, preservando o resto."""
    print("\n[4/4] Escrevendo o app.yaml")
    import re
    text = APP_YAML.read_text() if APP_YAML.exists() else (
        'command: ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]\n\nenv:\n'
    )

    def upsert(body: str, key: str, value: str) -> str:
        block = f'  - name: {key}\n    value: "{value}"'
        pat = re.compile(rf'  - name: {re.escape(key)}\n    value: ".*?"')
        if pat.search(body):
            return pat.sub(block, body)
        if "env:" not in body:
            body += "\nenv:\n"
        return body.rstrip() + "\n" + block + "\n"

    text = upsert(text, "DATABRICKS_WAREHOUSE_ID", warehouse_id)
    if genie_space_id:
        text = upsert(text, "GENIE_SPACE_ID", genie_space_id)
    APP_YAML.write_text(text)
    _log(f"app.yaml atualizado: warehouse={warehouse_id}"
         + (f", genie={genie_space_id}" if genie_space_id else " (sem Genie)"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Setup do acelerador Access Lens.")
    ap.add_argument("--app-name", default="access-lens", help="Nome do Databricks App.")
    ap.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID", ""),
                    help="ID do SQL warehouse (ou DATABRICKS_WAREHOUSE_ID).")
    ap.add_argument("--genie-space-id", default="",
                    help="Reusar uma Genie Space existente em vez de criar uma nova.")
    ap.add_argument("--skip-admin-grant", action="store_true",
                    help="Não tentar conceder admin ao SP.")
    ap.add_argument("--skip-genie", action="store_true", help="Não provisionar a Genie.")
    args = ap.parse_args()

    print("\n[1/4] Validando configuração")
    if not args.warehouse_id:
        sys.exit("  ERRO: informe --warehouse-id ou exporte DATABRICKS_WAREHOUSE_ID.")
    try:
        w = WorkspaceClient()
        me = w.current_user.me()
        _log(f"Autenticado como {me.user_name} em {w.config.host}")
    except Exception as e:  # noqa: BLE001
        sys.exit(f"  ERRO de autenticação: {e}\n  Configure a CLI (databricks auth login) "
                 "ou DATABRICKS_HOST/DATABRICKS_TOKEN.")
    try:
        w.warehouses.get(id=args.warehouse_id)
        _log(f"Warehouse {args.warehouse_id} acessível.")
    except DatabricksError as e:
        sys.exit(f"  ERRO: warehouse {args.warehouse_id} inacessível: {e}")

    ensure_admin(w, args.app_name, args.skip_admin_grant)

    genie_id = args.genie_space_id or None
    if not genie_id and not args.skip_genie:
        genie_id = provision_genie(w, args.warehouse_id)
    elif genie_id:
        print("\n[3/4] Usando Genie Space existente:", genie_id)

    write_app_yaml(args.warehouse_id, genie_id)

    print("\n✓ Setup concluído.")
    print("  Próximo passo: 'databricks bundle deploy' (ou redeploy se o SP virou admin agora).")


if __name__ == "__main__":
    main()
