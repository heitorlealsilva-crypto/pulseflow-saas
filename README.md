# PulseFlow SaaS

MVP funcional de uma camada de execução de follow-up. O PulseFlow não pretende substituir o CRM: ele conecta canais e sistemas existentes para garantir que cada lead receba a próxima ação certa, no tempo certo e com contexto.

## Princípio do produto

- O Pipeline organiza o trabalho de follow-up, sem duplicar o cadastro completo do CRM;
- Cada coluna tem SLA, IA observadora, IA operadora e automações independentes;
- A IA observadora analisa conversas e notas, mas não envia mensagens;
- A IA operadora sugere, executa com aprovação ou opera automaticamente, conforme a autonomia escolhida;
- Notas, valor do contrato e próxima ação mantêm apenas o contexto necessário para executar o acompanhamento;
- CRM, WhatsApp, VoIP e agenda continuam sendo integrados como fontes e destinos externos.

## O que está implementado

- Login/cadastro de demonstração e período grátis;
- Dashboard operacional com parâmetros da plataforma, pipeline drag-and-drop e colunas totalmente configuráveis;
- IA observadora, IA operadora e conjunto de automações configuráveis por coluna;
- Leads com origem, interesse, nicho, faturamento, notas e motivo de descarte;
- Área de notas, produto, preço do contrato, status comercial e próxima ação acessível diretamente pelo Pipeline;
- Coach de vendas que consolida mensagens, notas e ligações para estimar consciência, momento de compra, perguntas de descoberta, retomadas e condução para reunião;
- Pipeline de pós-venda com apenas IA observadora, sinais de conversas diretas e grupos autorizados, saúde do cliente, risco e oportunidade de expansão;
- Conversas em estilo WhatsApp, templates, registro de ligação obrigatório antes da primeira mensagem e respostas simuladas;
- Cadência configurável por horas/dias, automação por etapa e recuperação contextual;
- Lembretes, remarketing/abandonados, agente de IA por nicho, administração e planos;
- Conectores configuráveis para WhatsApp Business, VoIP, Google Agenda e CRMs.

## Produção: integrações e backend

Para produção, mantenha esta interface e conecte os botões de integração a um backend. O backend deve:

1. Armazenar dados em banco (Postgres, por exemplo) e autenticar usuários;
2. Criptografar tokens dos provedores e usar apenas a WhatsApp Cloud API ou parceiro oficial;
3. Receber `message.received` via webhook, pausar cadência, salvar mensagem e notificar o vendedor;
4. Executar cadências em uma fila/agendador (BullMQ/Temporal/Cloud Tasks) respeitando janelas de contato, opt-out e a regra de ligação;
5. Receber eventos de VoIP e Google Agenda para registrar chamadas e reuniões;
6. Expor API REST/Webhooks para CRM externo e auditoria de todas as alterações.

### WhatsApp oficial incluído

O projeto inclui duas Vercel Functions:

- `GET|POST /api/whatsapp`: verificação do webhook da Meta, validação HMAC da assinatura, normalização de mensagens diretas e eventos da Groups API;
- `GET|POST /api/send-whatsapp`: envio pela Cloud API, protegido por chave interna e bloqueado sem consentimento ou ligação registrada.

Configure na Vercel: `META_VERIFY_TOKEN`, `META_APP_SECRET`, `META_ACCESS_TOKEN`, `META_PHONE_NUMBER_ID`, `META_WABA_ID`, `META_GRAPH_VERSION` e `PULSEFLOW_INTERNAL_API_KEY`. Para persistir os eventos recebidos, configure também `PULSEFLOW_EVENT_SINK_URL` e, opcionalmente, `PULSEFLOW_EVENT_SINK_KEY`.

Credenciais nunca são armazenadas no navegador. A Groups API é uma capacidade oficial restrita: exige elegibilidade e aprovação da Meta, usa grupos compatíveis criados/administrados pela API e não deve ser tratada como acesso geral a qualquer grupo existente do aplicativo.

## API local incluída

Com Python 3 instalado, execute `python server.py` e acesse `http://127.0.0.1:8787`.

- `GET /api/health`, `GET|POST /api/leads`, `PATCH /api/leads/:id`;
- `POST /api/leads/:id/messages` — bloqueia a primeira mensagem se não houver chamada registrada;
- `POST /api/webhooks/whatsapp` — registra resposta, pausa automação e sinaliza notificação;
- `POST /api/webhooks/voip` — registra uma ligação concluída;
- `GET /api/events` e `GET|POST /api/integrations/:provider`.

Os endpoints são intencionalmente locais e usam arquivo JSON para permitir demonstração sem instalar banco ou serviços. Antes de produção, adicione autenticação, banco de dados, cofre de segredos, validação de assinatura de webhook, consentimento/opt-out e limites de envio.

## Publicar no Vercel

Importe esta pasta em um repositório GitHub e, no painel Vercel, escolha **Other / Static site** sem comando de build. O arquivo de entrada é `index.html`.

> As conexões mostradas no MVP são demonstrativas: credenciais reais e autorização das contas dos provedores são necessárias para ativá-las.
