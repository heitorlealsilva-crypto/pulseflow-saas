# Agendador do PulseFlow

## O que fica automático

O workflow `.github/workflows/pulseflow-worker.yml` solicita uma chamada à produção
nos minutos 7 e 37 de cada hora. Ele encontra compromissos, cadências, recuperações e regras vencidas e
as coloca em **Aguardando sua decisão**. O trabalhador é idempotente e usa uma
trava global: chamadas simultâneas não processam vários lotes ao mesmo tempo.
O invocador faz um único POST com espera de até 120 segundos; se o resultado
for incerto, a próxima execução retoma a fila persistente em vez de repetir a
chamada. Ele nunca envia mensagens; o vendedor continua responsável por
revisar e autorizar cada envio.

O cron diário configurado na Vercel continua ativo como contingência. Assim, o
plano Hobby não precisa executar cron a cada 30 minutos. Ainda assim, o GitHub
pode atrasar ou descartar execuções; uma cadência em horas não equivale a uma
garantia de aviso pontual com o navegador fechado. Ao abrir o sistema, as ações
vencidas também são recuperadas.

## Autenticação sem segredo compartilhado

O GitHub gera um token OIDC de poucos minutos para cada execução. O endpoint
`POST /api/scheduler` consulta as chaves públicas oficiais do GitHub e valida:

- emissor e assinatura RSA;
- audience `pulseflow-worker`;
- repositório `heitorlealsilva-crypto/pulseflow-saas`;
- arquivo `.github/workflows/pulseflow-worker.yml`;
- branch `main`;
- evento `schedule` ou execução manual.

Não existe `CRON_SECRET` no GitHub. O `CRON_SECRET` da Vercel continua sendo
usado exclusivamente pelo fallback diário em `/api/worker`.

## Ativação e verificação

1. Confirme que **GitHub Actions** está habilitado no repositório.
2. Depois do deploy da branch `main`, abra **Actions → PulseFlow scheduler**.
3. Use **Run workflow** uma vez e confirme a mensagem `Agendador concluído`.
4. As execuções seguintes são solicitadas duas vezes por hora, sem garantia de horário.

Em um repositório privado, essa frequência representa aproximadamente 1.440
execuções mensais. Como o GitHub arredonda cada job para um minuto, ela cabe na
franquia comum de 2.000 minutos e ainda reserva margem para testes e deploys.

Nenhuma variável secreta precisa ser criada. Caso o projeto seja renomeado ou
transferido, atualize `PULSEFLOW_GITHUB_REPOSITORY` na Vercel e também o nome do
repositório no workflow. O validador falha fechado enquanto os dois lados não
coincidirem.

## Limites reais

GitHub Actions não oferece garantia de horário exato e uma execução programada
pode atrasar ou ser descartada em momentos de alta demanda. Na verificação de
produção, houve intervalo superior a seis horas entre duas execuções bem-sucedidas,
apesar da programação semihorária. Portanto, **não anunciar SLA de 30 minutos**
para lembretes com o navegador fechado. Para prazo confiável, será necessário um
serviço de agendamento com garantia adequada; a fila persistente e as chaves de
idempotência já permitem essa troca sem alterar as cadências dos clientes.
