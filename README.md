# PulseFlow SaaS

MVP funcional de um CRM de follow-up automático. A interface é estática e sem dependências; há também uma API local em Python para desenvolvimento, webhooks e testes de integração.

## O que está implementado

- Login/cadastro de demonstração e período grátis;
- Dashboard, pipeline drag-and-drop, SLA por coluna e criação de colunas;
- Leads com origem, interesse, nicho, faturamento, notas e motivo de descarte;
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
