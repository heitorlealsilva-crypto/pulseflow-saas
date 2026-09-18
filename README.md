# PulseFlow

Ferramenta web de organização e acompanhamento comercial. A proposta é ajudar o vendedor a decidir **quem contatar, quando e com qual contexto**, mantendo a versão de entrada simples e sem substituir um CRM completo.

## Escopo real desta versão

- Cadastro e login por e-mail com sessões no servidor e PostgreSQL.
- Contas separadas por empresa. Os dados operacionais são salvos no banco; não dependem de um cadastro fictício no navegador.
- Contatos, pipelines, notas, próximos contatos, registro manual de ligações, valores comerciais e roteiros por nicho.
- Salvamento com revisão: quando duas sessões alteram a mesma conta, uma versão antiga não pode sobrescrever silenciosamente a mais recente.
- Administração global para consultar empresas e usuários, abrir uma empresa em modo suporte e controlar acessos. Ações administrativas são auditadas.
- Configuração por empresa para a integração oficial do WhatsApp. Credenciais permanecem no servidor, criptografadas.
- Interface adaptada a computador e celular, com recursos avançados concentrados nas configurações.

### Mensagens e agenda

No modo manual, cadastrar um número **não conecta nem espelha o WhatsApp**. O sistema prepara a mensagem, abre a conversa no WhatsApp e mantém o acompanhamento. Abrir o WhatsApp não confirma entrega: o vendedor precisa confirmar o que efetivamente enviou. Uma ligação registrada é obrigatória antes do primeiro contato por mensagem; contatos que pediram para não receber mensagens devem permanecer bloqueados.

Agendamentos, cadências e regras de automação organizam as próximas ações. As regras são avaliadas quando o espaço é aberto e quando chegam eventos compatíveis; esta versão não inclui um trabalhador de fila ou cron de envio contínuo em segundo plano. O agente pode preparar uma sugestão para revisão, mas uma tarefa vencida nunca significa mensagem enviada. Nenhuma simulação deve ser apresentada como conversa, ligação ou entrega real.

### Sugestões e inteligência artificial

Cada empresa pode configurar seu agente, tom, objetivo, instruções da observadora, instruções da operadora, retenção de memória e regras na área **Automações**. O sistema registra sinais estruturados das conversas e das notas de ligações confirmadas, sempre dentro do espaço da própria empresa, e usa esses registros para dar contexto às próximas sugestões. Isso é memória operacional por regras, não treinamento dos pesos de um modelo nem aprendizagem cruzada entre clientes.

Os roteiros por nicho e sugestões locais continuam funcionando sem custo de modelo. A análise semântica por um modelo de IA, transcrição de áudio e interpretação automática de chamadas ainda dependem de um provedor configurado no servidor e de limites de consumo. No pós-venda, o agente é somente observador; o envio operacional permanece bloqueado. Em todos os pipelines, a operadora trabalha em modo `suggest_only`: o vendedor revisa e autoriza qualquer mensagem.

### Planos e serviços externos

Os valores de referência são **Base: R$ 9,90/mês** e **Equipe: R$ 29,90/mês**. A cobrança, assinatura e cancelamento automático por um processador de pagamento não estão integrados. A alteração de plano pelo administrador é operacional; não efetua uma cobrança.

O consumo do WhatsApp oficial pertence à conta Meta do cliente. O PulseFlow não acrescenta uma mensalidade de API. Google Agenda, VoIP e outros CRMs ainda precisam de conectores e autorizações próprios; registrar manualmente uma reunião ou ligação não ativa essas integrações.

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
| `PULSEFLOW_ENCRYPTION_KEY` | Segredo com pelo menos 32 caracteres para proteger credenciais WhatsApp. Manter backup seguro. |
| `META_GRAPH_VERSION` | Versão da Graph API adotada pela integração, quando configurada. |

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

## Integrar o WhatsApp oficial

A integração usa a WhatsApp Cloud API e depende de um aplicativo Meta configurado, conta WhatsApp Business, número habilitado e permissões válidas. A verificação do cadastro de desenvolvedor e do número deve ser concluída na Meta pelo titular da conta.

Na configuração do WhatsApp da empresa, informar o identificador do número, o identificador da conta comercial, o token de acesso autorizado, o segredo do aplicativo e um token de verificação de webhook. Usar o endereço de webhook mostrado pelo sistema na configuração da Meta e assinar o evento de mensagens.

- `GET /api/whatsapp?action=connection`: estado da conexão, sem revelar credenciais.
- `GET /api/whatsapp?action=messages`: mensagens da empresa autenticada.
- `POST /api/whatsapp?action=connect`: salva a configuração cifrada.
- `POST /api/whatsapp?action=validate`: verifica a configuração no provedor.
- `POST /api/whatsapp?action=send`: envio autorizado, sujeito às regras comerciais e à resposta real da Meta.
- `GET|POST /api/whatsapp?action=webhook`: verificação e recebimento de eventos com validação de assinatura.
- `/api/send-whatsapp`: endpoint legado desativado; não utilizar.

O webhook passa a armazenar mensagens recebidas após a conexão válida. Não existe importação geral do histórico antigo, espelhamento de qualquer grupo do aplicativo ou conexão por QR Code não oficial. Envios fora das condições aceitas pela Meta devem ser bloqueados; suporte a templates aprovados depende dos tipos de envio realmente implementados no handler.

## Publicação e validação

Testes automatizados sem serviços externos: `node --test tests/core.test.mjs` e `python -m unittest discover -s tests -p "test_*.py"`. Os testes de interface em `tests/ui.test.cjs` usam Playwright e o servidor isolado na porta 8788, sem enviar mensagens reais. As capturas geradas ficam fora do Git e da publicação.

O frontend usa HTML, CSS e JavaScript sem bibliotecas de interface externas. Na Vercel, os handlers Python ficam em `api/` e as dependências em `requirements.txt`. Configure as variáveis nos ambientes corretos e use banco separado para previews.

`vercel.json` aplica uma política de conteúdo da mesma origem, bloqueia enquadramento por outros sites e desabilita recursos de câmera, microfone e localização que a interface não utiliza. Não publicar fixtures, arquivos de ambiente, cópias locais ou diretórios de testes.

Antes de liberar uma versão para clientes, validar cadastro e login, reabertura dos dados em outra sessão, isolamento entre duas empresas, conflito de gravação, controles do administrador e os fluxos no celular. Entrega real de mensagens só está validada quando houver credenciais Meta e um evento de resposta do provedor — aprovação visual ou gravação local não equivalem a envio.
