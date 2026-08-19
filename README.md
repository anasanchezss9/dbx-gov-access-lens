# Access Lens — Acelerador de Governança de Acessos

**Governança de acessos com rastreabilidade de origem.**

O Access Lens é um aplicativo Databricks que responde, para qualquer usuário ou grupo do seu
ambiente, três perguntas que hoje não têm resposta única na plataforma:

1. **O que esta pessoa (ou grupo) acessa?** — privilégios em catálogos, schemas, tabelas,
   volumes e funções do Unity Catalog, mais permissões em recursos de workspace (warehouses,
   clusters, jobs, pipelines, apps, dashboards, Genie spaces e outros).
2. **De onde vem cada acesso?** — se o privilégio foi concedido diretamente no objeto ou
   **herdado** do catálogo/schema, e por qual caminho ele chega até a pessoa: direto, via um
   grupo, ou via um **grupo aninhado** (grupo dentro de grupo).
3. **O que acontece se eu remover este acesso ou objeto?** — quem realmente usou um warehouse
   ou cluster nos últimos dias, e o que depende de uma tabela (linhagem a jusante).

Fecha com uma **sala do Genie integrada**: um assistente de IA que responde, em linguagem
natural, perguntas sobre acessos e ambiente que o app não mostra em tela (concessões
recentes, consumo, tabelas ociosas, acesso fora de horário).

Este pacote é um **acelerador para você hospedar no seu próprio ambiente Databricks.** Ele lê
**apenas system tables e APIs nativas** — não depende de nenhuma tabela específica sua e não
guarda dado nenhum. Todo o conteúdo mostrado vem, ao vivo, do seu workspace.

---

## Por que este app é necessário

O Databricks não expõe, hoje, uma consulta única do tipo *"tudo o que o usuário X acessa e de
onde cada acesso vem"*. As informações existem, mas espalhadas:

| Pergunta | Onde a plataforma responde |
|---|---|
| Privilégios de UC de um usuário/grupo | `system.information_schema.*_privileges` |
| O grant é no objeto ou herdado? | coluna `inherited_from` das views acima |
| Permissão em cluster, warehouse, job, app… | Permissions API — **um objeto por chamada** |
| De qual grupo (inclusive aninhado) vem o acesso | comando `SHOW GROUPS WITH USER` |
| Uso real de um recurso / dependências de uma tabela | `system.query.history`, `system.billing.usage`, `system.access.table_lineage` |

O Access Lens **une essas fontes numa visão só**, resolve a expansão de grupos e mostra a
origem de cada acesso. É essa camada que não existe nativamente.

---

## O que vem no pacote

```
accelerator/
├── databricks.yml              # Configuração do Databricks Asset Bundle (o App)
├── resources/
│   └── access_lens.app.yml      # Definição do recurso "App"
├── setup/
│   └── setup.py                 # Script de preparação (roda uma vez)
├── src/
│   ├── app.py                   # Backend (FastAPI) — só system tables + APIs nativas
│   ├── app.yaml                 # Comando de inicialização + variáveis de ambiente
│   ├── requirements.txt         # Dependências Python do app
│   └── static/index.html        # Interface web (página única, sem etapa de build)
└── README.md                    # este documento
```

---

## Pré-requisitos

Antes de começar, você precisa de:

1. **Databricks CLI** instalada e autenticada no *seu* workspace.
   - Instalar: siga a documentação oficial da Databricks CLI (versão 0.239 ou superior).
   - Verificar a versão: `databricks -v`
   - Autenticar: `databricks auth login --host https://SEU-WORKSPACE.cloud.databricks.com`
     (para Azure, o host termina em `.azuredatabricks.net`)
2. **Um SQL Warehouse** no seu workspace (recomendado: serverless). Anote o **ID** dele —
   você o encontra na URL do warehouse ou em *SQL Warehouses* na interface.
3. **Python 3.10+** na máquina onde vai rodar o setup, com o SDK instalado:
   ```bash
   pip install databricks-sdk
   ```
4. **Permissão de administrador do workspace** para uma etapa do setup (explicada mais
   abaixo). Se você não for admin, um admin precisará executar uma ação de um clique — o
   script diz exatamente qual.

> **Importante:** todos os comandos abaixo agem sobre **o workspace em que a sua CLI está
> autenticada**. Não há nenhum link, ID ou credencial de outro ambiente embutido neste
> pacote. Confirme onde você está logado com: `databricks auth describe`

---

## Passo a passo do deploy

### Passo 1 — Preparar o ambiente (script de setup)

Este script roda **uma vez** e deixa tudo pronto. Ele é seguro para rodar de novo (idempotente).

```bash
cd accelerator
export DATABRICKS_WAREHOUSE_ID=<o-id-do-seu-warehouse>
python setup/setup.py --app-name access-lens
```

O que ele faz, em ordem:

1. **Valida** o acesso ao seu workspace e ao warehouse informado.
2. **Concede admin ao app** — adiciona o service principal do aplicativo ao grupo `admins`
   do workspace (veja *Por que o app precisa de admin* mais abaixo). Se você não tiver
   permissão para isso, o script **não falha**: ele imprime o nome exato do service principal
   e a instrução para um admin fazê-lo.
3. **Cria a sala do Genie** de governança, apontada para as system tables, já com instruções
   e perguntas de exemplo.
4. **Grava a configuração** (ID do warehouse e ID da sala do Genie) no arquivo `src/app.yaml`.

> Ainda não tem o app criado? Sem problema: rode o Passo 2 primeiro (para criar o app),
> depois volte e rode o setup — ou rode agora com `--skip-admin-grant` e conceda o admin
> depois. O script explica o caminho em qualquer ordem.

**Opções úteis do setup:**

| Opção | Quando usar |
|---|---|
| `--warehouse-id <id>` | Alternativa a exportar `DATABRICKS_WAREHOUSE_ID` |
| `--genie-space-id <id>` | Reaproveitar uma sala do Genie que você já tem, em vez de criar |
| `--skip-genie` | Não criar a sala do Genie (a aba de chat some da interface) |
| `--skip-admin-grant` | Não tentar conceder admin agora (fazer manualmente depois) |

### Passo 2 — Publicar o aplicativo

```bash
databricks bundle validate      # confere a configuração
databricks bundle deploy        # cria/atualiza o App no seu workspace
databricks bundle run access_lens   # inicia o App
```

Ao final, a CLI mostra a **URL do aplicativo no seu workspace**. É por ela que você e seu
time acessam o Access Lens.

### Passo 3 — Confirmar permissões e reiniciar se necessário

- No primeiro acesso, o app pede **consentimento** para agir em seu nome. Aprove o escopo
  `sql` quando solicitado.
- Se o setup adicionou o service principal ao grupo `admins` **depois** do primeiro deploy,
  rode `databricks bundle deploy` mais uma vez. O motivo: o app só passa a enxergar com
  privilégio de admin após ser reiniciado.

Pronto. O app está no ar, no seu ambiente, lendo os seus dados ao vivo.

---

## Configuração (variáveis de ambiente)

Ficam no arquivo `src/app.yaml` e são preenchidas pelo script de setup. Você raramente
precisa editá-las à mão.

| Variável | O que é |
|---|---|
| `DATABRICKS_WAREHOUSE_ID` | O SQL Warehouse que executa as consultas do app |
| `GENIE_SPACE_ID` | A sala do Genie da aba de chat. Se ficar vazia, a aba simplesmente não aparece |

As credenciais do aplicativo (host, client id e secret do service principal) são fornecidas
**automaticamente** pela plataforma Databricks Apps — você não precisa configurá-las.

---

## A sala do Genie (assistente de IA)

O botão **✨ Perguntar à IA** abre um chat lateral conectado a uma sala do Genie criada pelo
setup sobre as suas system tables de governança (auditoria, linhagem, consumo e histórico de
consultas). Use para perguntas que o app não traz em tela, por exemplo:

- *"Quais GRANTs foram concedidos nos últimos 30 dias e por quem?"*
- *"Quais os 10 maiores consumidores de DBU no último mês?"*
- *"Quais tabelas não são consultadas há mais de 90 dias?"*
- *"Quem executou consultas fora do horário comercial na última semana?"*

**Sobre a identidade das respostas do Genie:** por uma característica atual da plataforma, a
interface de IA opera com a identidade do próprio aplicativo (o service principal), e não com
a sua. As respostas refletem o que o aplicativo enxerga. O app avisa isso na primeira resposta.
Recomendamos registrar o service principal do aplicativo no seu processo de governança.

---

## Por que o app precisa de privilégio de admin

Para responder *"de qual grupo vem este acesso"* e *"quem são os membros deste grupo"*, o app
usa recursos da plataforma (`SHOW GROUPS WITH USER`, o diretório de identidades e a Permissions
API) que **só revelam o acesso de terceiros a quem tem privilégio de administrador**. Sem isso,
essas colunas voltam **vazias, sem erro** — o que seria enganoso.

Isso é esperado: uma ferramenta de revisão de acesso precisa, por definição, enxergar o acesso
de outras pessoas, e a identidade de quem faz a pergunta nunca daria essa visão. Por isso o
setup adiciona o service principal do aplicativo ao grupo `admins`. É uma decisão consciente
de governança — vale documentá-la internamente.

Além do admin, o service principal precisa de acesso de leitura aos objetos que você quer
inspecionar: `USE CATALOG` / `USE SCHEMA` nos catálogos e `CAN USE` no warehouse.

---

## O que o app cobre — e o que é limitação da plataforma

Transparência faz parte da ferramenta (há uma aba "Fontes de dados e limitações" dentro do
próprio app). Em resumo:

- **É uma fotografia do agora**, não um histórico. Para *"quem tinha acesso no mês passado"*,
  o caminho é a tabela de auditoria (`system.access.audit`), que a sala do Genie consulta.
- **Uso real** ("quem seria afetado se eu remover") existe para **warehouse e cluster**. Não
  há telemetria equivalente por objeto para job, app, dashboard ou sala do Genie.
- **Impacto de uma tabela** depende da linhagem executada na janela recente: um pipeline que
  não rodou nessa janela não aparece. Não substitui revisão de código.
- **Modelos de ML não são cobertos** — a plataforma não expõe, hoje, um caminho viável para
  listar acesso a modelos.
- **Permissões de recursos são locais ao workspace** onde o app está publicado; privilégios
  de Unity Catalog valem para todo o metastore. Para cobrir vários workspaces, publique uma
  instância do app em cada um.

---

## Solução de problemas

| Sintoma | Causa provável e solução |
|---|---|
| A coluna "chega por" ou os membros de grupo vêm vazios | O service principal não é admin. Rode o setup de novo (ou peça a um admin) e depois `databricks bundle deploy`. |
| "DATABRICKS_WAREHOUSE_ID não configurado" | Rode o setup, ou preencha o warehouse em `src/app.yaml`. |
| A aba "Perguntar à IA" não aparece | `GENIE_SPACE_ID` está vazio. Rode o setup sem `--skip-genie`, ou informe uma sala com `--genie-space-id`. |
| Erro de autenticação ao rodar o setup ou a CLI | Refaça o `databricks auth login` apontando para o seu workspace. Confirme com `databricks auth describe`. |
| O app não inicia após o deploy | Rode `databricks bundle run access_lens`. Para ver o motivo de um erro: `databricks apps logs access-lens`. |

---

## Como remover

Para retirar o aplicativo do seu ambiente:

```bash
databricks bundle destroy
```

A sala do Genie criada pelo setup pode ser excluída pela interface de Genie do seu workspace.
