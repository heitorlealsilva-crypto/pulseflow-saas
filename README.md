# PulseFlow

Ferramenta web de organização e acompanhamento comercial. A proposta é ajudar o vendedor a decidir **quem contatar, quando e com qual contexto**, mantendo a versão de entrada simples e sem substituir um CRM completo.

## Escopo real desta versão

- Cadastro e login por e-mail com sessões no servidor e PostgreSQL.
- Contas separadas por empresa. Os dados operacionais são salvos no banco; não dependem de um cadastro fictício no navegador.
- Contatos, pipelines, notas, próximos contatos, registro manual de ligações, valores comerciais e roteiros por nicho.
- Salvamento com revisão: quando duas sessões alteram a mesma conta, uma versão antiga não pode sobrescrever silenciosamente a mais recente.
- Administração global para consultar empresas e usuários, abrir uma empresa em modo suporte e controlar acessos. O administrador pode gerar um link de redefinição de senha com 30 minutos de validade e uso único para um usuário ativo; a conclusão encerra as sessões antigas. Ações administrativas são auditadas.
- Gestão de equipe pelo proprietário: o plano Base é individual e o plano Equipe permite até três usuários ativos no mesmo espaço, com convite único de 48 horas, senha definida pelo próprio vendedor, responsável por contato e suspensão imediata de sessões.
- Importação e exportação de contatos por CSV para integração leve com outros sistemas, sem transformar o PulseFlow em um CRM completo.
- API de integração por empresa, com chave revogável, escopos, escrita idempotente de contatos, fila de eventos e webhooks de saída assinados para sincronização com outros CRMs.
- Termos e Política de Privacidade públicos, com aceite versionado gravado no cadastro e no convite de equipe. Os textos do MVP precisam de identificação completa do operador e revisão jurídica antes da comercialização em escala.
- Configuração por empresa para a integração oficial do WhatsApp. Credenciais permanecem no servidor, criptografadas.
- Interface adaptada a computador e celular, com recursos avançados concentrados nas configurações.

### Mensagens e agenda

No modo manual, cadastrar um número **não conecta nem espelha o WhatsApp**. O sistema prepara a mensagem, abre a conversa no WhatsApp e mantém o acompanhamento. Abrir o WhatsApp não confirma entrega: o vendedor precisa confirmar o que efetivamente enviou. Uma ligação registrada é obrigatória antes do primeiro contato por mensagem; contatos que pediram para não receber mensagens devem permanecer bloqueados.

Agendamentos, cadências e regras de automação organizam as próximas ações. Cada etapa do pipeline pode ter prazo, observadora, operadora em modo de sugestão e uma cadência própria acionada na entrada, no vencimento ou após uma resposta. O backend mantém uma fila persistente e idempotente: o trabalhador encontra ações vencidas e as coloca na caixa **Aguardando sua decisão**. O agente prepara uma sugestão para revisão, mas uma tarefa vencida nunca significa mensagem enviada. Nenhuma simulação deve ser apresentada como conversa, ligação ou entrega real.

O projeto inclui dois disparadores para a mesma fila: um workflow GitHub Actions chama `POST /api/scheduler` aproximadamente a cada 30 minutos usando um token OIDC efêmero, e o cron diário da Vercel Hobby permanece como contingência em `/api/worker`. Não existe segredo permanente do banco ou do agendador no GitHub. A execução usa trava global, trava uma empresa por vez e nunca repete um POST cujo resultado ficou incerto. GitHub Actions e Vercel podem atrasar; a precisão esperada é uma janela de cerca de 30 minutos, não um SLA por minuto. Consulte `docs/SCHEDULER.md`.

### Sugestões e inteligência artificial

Cada empresa pode configurar seu agente, tom, objetivo, instruções da observadora, instruções da operadora, retenção de memória e regras na área **Automações**. O sistema registra sinais estruturados das conversas e das notas de ligações confirmadas, sempre dentro do espaço da própria empresa, e usa esses registros para dar contexto às próximas sugestões. Isso é memória operacional por regras, não treinamento dos pesos de um modelo nem aprendizagem cruzada entre clientes.

Os roteiros por nicho e sugestões locais continuam funcionando sem custo de modelo. Quando `OPENAI_API_KEY` está configurada, o vendedor pode solicitar uma análise semântica real dentro da conversa e, se habilitar o aprendizado contínuo, o trabalhador também observa mudanças de etapa, contexto, prazo e respostas com o sistema fechado. O plano Base permite até 3 análises contínuas por dia e o Equipe até 30; as análises manuais e contínuas também respeitam o limite total diário do plano. O backend envia somente contexto limitado e sem telefone/e-mail, não permite armazenamento no provedor, guarda a análise na empresa correta e aplica a retenção configurada. Contatos sem permissão ou com pedido de não contato não são enviados ao modelo.

Quando chega uma resposta oficial, o servidor atualiza o contato, cria um alerta durável e aplica a regra `Pausar ao responder` da etapa. Ao pausar, sugestões automáticas antigas são invalidadas, mas compromissos explicitamente agendados continuam ativos. Transcrição de áudio e interpretação automática de chamadas ainda não estão disponíveis. No pós-venda, o agente é somente observador; o envio operacional permanece bloqueado. Em todos os pipelines, a operadora trabalha em modo `suggest_only`: o vendedor revisa e autoriza qualquer mensagem.

### Planos e serviços externos

Os valores de referência são **Base: R$ 9,90/mês** para uma pessoa e **Equipe: R$ 29,90/mês** para até três usuários ativos. A cobrança, assinatura e cancelamento automático por um processador de pagamento não estão integrados. A alteração de plano pelo administrador é operacional; não efetua uma cobrança.

O consumo do WhatsApp oficial pertence à conta Meta do cliente. O PulseFlow não acrescenta uma mensalidade de API. A ponte genérica por API e CSV está disponível, mas Google Agenda, VoIP e conectores específicos de cada CRM ainda precisam de autorizações próprias; registrar manualmente uma reunião ou ligação não ativa essas integrações.

## Executar localmente com o backend real

Requisitos: Python 3.12 ou superior, PostgreSQL acessível e as dependências de `requirements.txt`.

```sh
python -m pip install -r requirements.txt
python server.py
```

Abra `http://127.0.0.1:8787`. O servidor importa os mesmos handlers de autenticação e WhatsApp usados em produção. Ele escuta apenas em localhost, não habilita CORS global, não lista pastas e só serve os arquivos públicos necessários ao frontend.

Variáveis de ambiente:

| Variável | Uso |
| --- | --- |
| `DATABASE_URL` ou `STORAGE_URL` | Conexão PostgreSQL. Usar banco separado para desenvolvimento. |
| `PULSEFLOW_APP_URL` | Endereço público HTTPS do SaaS; usado para origem e webhook. |
| `PULSEFLOW_ADMIN_EMAIL` | E-mail do administrador inicial. |
| `PULSEFLOW_ADMIN_PASSWORD` | Senha forte do administrador inicial, fornecida como segredo no servidor. |
| `PULSEFLOW_ENCRYPTION_KEY` | Segredo com pelo menos 32 caracteres para proteger credenciais WhatsApp, URLs e segredos dos webhooks de saída. Manter backup seguro. |
| `META_GRAPH_VERSION` | Versão da Graph API adotada pela integração, quando configurada. |
| `META_APP_ID` | Identificador público do aplicativo Meta usado pelo Cadastro Incorporado. |
| `META_APP_SECRET` | Segredo do aplicativo Meta, usado somente no servidor para trocar o código OAuth e validar webhooks. |
| `META_EMBEDDED_SIGNUP_CONFIG_ID` | Identificador da configuração Facebook Login for Business/Embedded Signup. |
| `META_WEBHOOK_VERIFY_TOKEN` | Segredo global de ao menos 32 caracteres usado para verificar o callback compartilhado do aplicativo. |
| `META_OAUTH_REDIRECT_URI` | Opcional; deve ser exatamente o callback HTTPS do PulseFlow. O padrão é `/api/whatsapp?action=onboarding-callback` na URL pública. |
| `META_OAUTH_PKCE_ENABLED` | Ativa PKCE S256 apenas quando a configuração Meta utilizada aceitar o parâmetro; permanece desativado por padrão. |
| `CRON_SECRET` | Segredo com pelo menos 16 caracteres, enviado como `Authorization: Bearer ...` pelo cron ou agendador externo. |
| `OPENAI_API_KEY` | Chave do projeto OpenAI usada somente pelo backend para analisar conversas. |
| `OPENAI_MODEL` | Modelo de análise; o padrão é `gpt-5.6-luna`. |
| `PULSEFLOW_GITHUB_REPOSITORY` | Repositório autorizado a chamar o agendador por OIDC; opcional enquanto permanecer `heitorlealsilva-crypto/pulseflow-saas`. |

Não colocar senhas, tokens ou URLs privadas do banco no JavaScript, no repositório ou em capturas de tela. Trocar a chave de criptografia sem migrar as credenciais existentes impede que elas sejam decifradas. As variáveis administrativas inicializam o administrador; não são uma tela de alteração de senha para usuários existentes.

Sem banco ou dependências, o servidor local informa indisponibilidade. Ele não substitui silenciosamente o banco por um JSON ou por dados de demonstração.

## Testes de interface isolados

Para desenvolver a interface sem tocar no banco ou em contas reais:

```sh
python tests/serve_test.py --test-only
```

Abra `http://127.0.0.1:8788`. Esse processo é **uma fixture de teste local em memória**, com dados apagados ao reiniciar e provedores externos desativados. Não deve ser publicado nem usado como armazenamento do produto.

- Vendedor: `seller@example.test`
- Administrador: `admin@example.test`
- Senha de ambas as fixtures locais: `PulseFlow-local-2026!`

O contrato de teste cobre login, cadastro, sessões, dados por empresa, conflito de revisões, suporte e suspensão de acesso. Ele permite testar a interface, mas **não comprova persistência PostgreSQL nem entrega por WhatsApp**. Esses pontos exigem validação com serviços reais configurados. Os testes de segurança dos handlers ficam separados das fixtures de navegação.

## Integrar outro CRM pela API

O proprietário da empresa cria e revoga chaves em **Configurações → Conta e dados → API para outros sistemas**. Ele escolhe separadamente as permissões de leitura, escrita e eventos; quando nenhuma é informada diretamente à API de gestão, a chave nasce somente com leitura. A chave completa aparece uma única vez e o banco armazena somente seu hash. O sistema externo deve enviá-la no cabeçalho `Authorization: Bearer <chave>`; a empresa é sempre determinada pela chave, nunca por um identificador fornecido pelo cliente externo.

- `GET /api/integrations?action=contacts`: lista a visão permitida dos contatos, com paginação por `limit` e `offset`.
- `POST /api/integrations?action=upsert-contact`: cria ou atualiza por `external_id`, que deve ser único na empresa e pode receber um prefixo do sistema de origem, como `meucrm:123`. A troca da chave não duplica esse contato. Cada escrita exige `request_id` UUID; repetir a mesma requisição é seguro e reutilizar o UUID com outro conteúdo é bloqueado.
- `GET /api/integrations?action=events`: entrega a fila de mudanças por `cursor`, para sincronização incremental.
- `GET /api/integrations?action=keys`, `POST ...?action=create-key` e `POST ...?action=revoke-key`: rotas do navegador autenticado para o proprietário ou administrador; não são rotas para o CRM externo.

Uma integração pode consultar ou alterar apenas os campos permitidos: identificação, contato, origem, interesse, tags, notas, pipeline, etapa, contrato, produto, nicho e faturamento. Para entrar em `Abandonados`, também são obrigatórios `discard_reason` e `recovery_at` em ISO 8601 com fuso e data futura. Ela não recebe conversas, chamadas, memória da IA, equipe ou configurações. Contatos novos entram com automação pausada e sem consentimento presumido; um pedido de não contato pode ser acrescentado, mas nunca removido pela API.

No plano Equipe, o proprietário também pode cadastrar até três destinos em **API para outros sistemas → Webhooks de saída**. Cada entrega automática acontece no ciclo do agendador — hoje, com janela esperada de cerca de 30 minutos — por meio de um `POST` JSON assinado com HMAC-SHA256 no cabeçalho `X-PulseFlow-Signature`; os cabeçalhos `X-PulseFlow-Timestamp`, `X-PulseFlow-Event-Id`, `X-PulseFlow-Delivery-Id` e `X-PulseFlow-Event-Type` permitem validar frescor, idempotência e tipo. A assinatura usa `v1=` seguido do hexadecimal de `HMAC(segredo, timestamp + "." + corpo_bruto)`. O segredo completo aparece somente na criação.

Os eventos contêm apenas identificadores, pipeline/etapa, estado de bloqueio ou pausa e horário necessários à sincronização. Conversas, notas, ligações, telefone, e-mail e memória da IA não são enviados. Destinos aceitam somente HTTPS público na porta 443; endereços locais, metadados de nuvem, IP literal, redirecionamento e chamada ao próprio PulseFlow são bloqueados. Falhas transitórias entram em retentativa com espera crescente; `410 Gone` ou o esgotamento das tentativas pausa o destino para impedir tráfego indefinido.

Os tipos disponíveis são `contact.created`, `contact.updated`, `contact.stage_changed`, `contact.deleted`, `contact.reply_received` e `contacts.resync_required`. Em alterações em massa com mais de 100 contatos, o último substitui centenas de notificações individuais e orienta o sistema conectado a buscar novamente os dados pela API.

O consumo incremental de `events` continua disponível como reconciliação confiável: o consumidor deve salvar o cursor e consultar periodicamente para cobrir indisponibilidades do seu endpoint. Registros de idempotência são mantidos por 7 dias e eventos por 90 dias; eventos com entrega ainda pendente não são removidos pela retenção.

## Integrar o WhatsApp oficial

A integração usa a WhatsApp Cloud API e depende de um aplicativo Meta configurado, uma configuração do Facebook Login for Business (Embedded Signup), conta WhatsApp Business, número habilitado e permissões válidas. O cadastro de desenvolvedor, a verificação empresarial e a aprovação do aplicativo devem ser concluídos na Meta pelo titular da plataforma. O cliente final não precisa digitar o App Secret nem o token da plataforma.

No Vercel, configure somente no ambiente **Production**: `META_APP_ID`, `META_APP_SECRET`, `META_EMBEDDED_SIGNUP_CONFIG_ID`, `META_WEBHOOK_VERIFY_TOKEN` (pelo menos 32 caracteres), `PULSEFLOW_ENCRYPTION_KEY` (pelo menos 32 caracteres), `PULSEFLOW_APP_URL` e, opcionalmente, `META_GRAPH_VERSION` e `META_REGISTRATION_PIN`. A configuração do Facebook Login for Business deve incluir o domínio publicado em Allowed Domains e Valid OAuth Redirect URIs. O callback global do webhook é `/api/whatsapp?action=webhook`; o token de verificação é o mesmo valor de `META_WEBHOOK_VERIFY_TOKEN`.

Para o fluxo recomendado de SaaS, o proprietário usa **Conectar com a Meta**. O SDK oficial abre o Embedded Signup, devolve um código de uso curto e um evento `WA_EMBEDDED_SIGNUP` com WABA e número escolhidos. O backend cria um `state` de uso único vinculado à sessão, usuário e empresa, troca o código no servidor, confirma que o número pertence à WABA autorizada, assina o webhook da WABA, registra o número com PIN de seis dígitos e cifra a credencial antes de persistir. O segredo do aplicativo, token de webhook, código OAuth, token de acesso, PIN e eventual verificador PKCE nunca fazem parte do workspace nem das respostas de status.

- `GET /api/whatsapp?action=connection`: estado da conexão, sem revelar credenciais.
- `GET /api/whatsapp?action=onboarding-status`: disponibilidade da configuração e último fluxo da sessão, sem segredos.
- `POST /api/whatsapp?action=onboarding-start`: inicia um estado de autorização para a empresa autenticada e devolve somente identificadores públicos para o SDK.
- `GET|POST /api/whatsapp?action=onboarding-callback`: consome uma única vez o código OAuth e o evento Embedded Signup, associa WABA e número confirmados e registra o número.
- `GET /api/whatsapp?action=messages`: mensagens da empresa autenticada.
- `POST /api/whatsapp?action=connect`: salva a configuração cifrada.
- `POST /api/whatsapp?action=validate`: verifica a configuração no provedor.
- `POST /api/whatsapp?action=send`: envio autorizado, sujeito às regras comerciais e à resposta real da Meta.
- `GET|POST /api/whatsapp?action=webhook`: verificação e recebimento de eventos com validação de assinatura.
- `/api/send-whatsapp`: endpoint legado desativado; não utilizar.

O webhook global valida a assinatura da Meta e localiza a empresa pelo par WABA/Phone Number ID; isso mantém o isolamento entre clientes mesmo quando uma entrega contém vários eventos. Ele passa a armazenar mensagens recebidas após a conexão válida. Não existe importação geral do histórico antigo, espelhamento de grupos do aplicativo ou conexão por QR Code não oficial. Envios fora das condições aceitas pela Meta devem ser bloqueados; suporte a templates aprovados depende dos tipos de envio realmente implementados no handler.

## Publicação e validação

Testes automatizados sem serviços externos: `node --test tests/core.test.mjs` e `python -m unittest discover -s tests -p "test_*.py"`. O fluxo específico de agentes e cadências por etapa fica em `tests/column_automation_ui.test.cjs`. Os testes de interface usam Playwright e o servidor isolado na porta 8788, sem enviar mensagens reais. As capturas geradas ficam fora do Git e da publicação.

O frontend usa HTML, CSS e JavaScript sem bibliotecas de interface externas. Na Vercel, os handlers Python ficam em `api/` e as dependências em `requirements.txt`. Configure as variáveis nos ambientes corretos e use banco separado para previews.

`vercel.json` aplica uma política de conteúdo da mesma origem, bloqueia enquadramento por outros sites e desabilita recursos de câmera, microfone e localização que a interface não utiliza. Não publicar fixtures, arquivos de ambiente, cópias locais ou diretórios de testes.

Antes de liberar uma versão para clientes, validar cadastro e login, reabertura dos dados em outra sessão, isolamento entre duas empresas, conflito de gravação, controles do administrador e os fluxos no celular. Entrega real de mensagens só está validada quando houver credenciais Meta e um evento de resposta do provedor — aprovação visual ou gravação local não equivalem a envio.
