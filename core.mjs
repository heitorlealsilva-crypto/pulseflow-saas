export const BOARDS=['Principal','Remarketing','Abandonados','Pós-venda'];
export const NICHES=['Serviços','Marketing e tráfego','Barbearia','Salão de beleza','Clínica','Loja','Imobiliária'];
export const id=()=>globalThis.crypto.randomUUID();
export const escapeHTML=(v='')=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function phoneNumber(v){let n=String(v||'').replace(/\D/g,'');if(n.length===10||n.length===11)n='55'+n;return /^[1-9]\d{9,14}$/.test(n)?n:''}
export function defaultAutomations(){return [
 {id:'auto-stage',name:'Contato parado na etapa',enabled:true,trigger:'stage_timeout',board:'Principal',delay:24,action:'prepare_followup',instructions:'Retome o contexto e proponha um próximo passo simples.'},
 {id:'auto-reply',name:'Cliente respondeu',enabled:true,trigger:'reply_received',board:'Todos',delay:0,action:'notify_seller',instructions:'Pause a cadência, avise o vendedor e destaque a intenção do cliente.'},
 {id:'auto-inactive',name:'Reabrir conversa inativa',enabled:true,trigger:'inactive_lead',board:'Principal',delay:720,action:'prepare_followup',instructions:'Reabra a conversa com contexto, sem pressionar.'},
 {id:'auto-postsale',name:'Sinal de expansão no pós-venda',enabled:true,trigger:'post_sale_signal',board:'Pós-venda',delay:0,action:'observe_only',instructions:'Observe satisfação, adoção, novas necessidades e momento de expansão. Não envie mensagens.'}
]}
export function freshWorkspace(){return {schemaVersion:4,leads:[],columns:[{id:'new',name:'Novo lead',limit:24,color:'#9b8afb'},{id:'service',name:'Em atendimento',limit:48,color:'#4d96d9'},{id:'waiting',name:'Aguardando resposta',limit:24,color:'#dfa04d'},{id:'closed',name:'Fechado',limit:0,color:'#46aa83'}],postSaleColumns:[{id:'onboarding',name:'Implantação',limit:168},{id:'adoption',name:'Adoção',limit:336},{id:'expansion',name:'Oportunidade',limit:168},{id:'renewal',name:'Renovação',limit:720}],cadence:defaultCadence(),automations:defaultAutomations(),automationRuns:[],reminders:[],notifications:[],whatsapp:{number:'',businessName:''},businessProfile:{niche:'',customNiche:'',onboarded:false},settings:{inactiveDays:30,recoveryDays:30},ai:{enabled:false,name:'Agente PulseFlow',goal:'Organizar o acompanhamento e ajudar o vendedor a avançar cada conversa.',tone:'Consultivo e direto',autonomy:'suggest_only',learningEnabled:true,memoryRetentionDays:180,observerInstructions:'Identifique intenção, necessidade, objeção, urgência e próximo passo.',operatorInstructions:'Prepare sugestões curtas e contextuais. Nunca envie sem aprovação.',memories:[],feedback:[]},manualApprovals:[]}}
export function defaultCadence(){return [2,24,48,72,120,168,240,336,504,720].map((delay,i)=>({id:'step-'+i,delay,unit:'horas',text:[ 'Oi, {nome}! Posso entender o que você está buscando neste momento?', '{nome}, ficou alguma dúvida sobre o que conversamos? Posso ajudar a esclarecer.', 'Qual seria o resultado mais importante para você agora?', 'Faz sentido uma ligação breve para entender o seu cenário?', 'Há alguma informação que faltou para você avaliar a proposta?', 'Posso apresentar um exemplo relacionado ao seu objetivo?', 'Vale reservarmos 15 minutos para definir um próximo passo?', 'Seu momento continua o mesmo ou alguma prioridade mudou?', 'Gostaria de retomar aquele objetivo ou prefere conversar mais adiante?', '{nome}, vou encerrar este acompanhamento por enquanto. Se quiser retomar, estou à disposição.' ][i]}))}
// Old releases wrote these exact demonstration records into every workspace.
// Keep originals in the backup; do not turn untouched samples into real contacts.
const legacyPostSaleSamples=[
 {id:'ps1',leadId:'l5',name:'Rafael Alves',company:'Alves Imóveis',stage:'adoption',directMessages:18,groupMessages:34,group:'Clientes · Alves Imóveis',health:82,lastSignal:'Equipe comentou que já reduziu o tempo de resposta aos novos contatos.',moment:'Bom momento para expansão',expansionProduct:'Módulo de IA para qualificação',expansionValue:4800,nextReview:'',notes:'Cliente engajado e com equipe usando o processo diariamente.'},
 {id:'ps2',name:'Paula Ribeiro',company:'Clínica Vitta',stage:'onboarding',directMessages:9,groupMessages:21,group:'Implantação · Clínica Vitta',health:64,lastSignal:'Duas pessoas da equipe ainda não concluíram a configuração.',moment:'Priorizar adoção',expansionProduct:'',expansionValue:0,nextReview:'',notes:'Aguardar primeiro resultado antes de apresentar outro produto.'},
 {id:'ps3',name:'Diego Martins',company:'Barbearia Central',stage:'expansion',directMessages:27,groupMessages:48,group:'Sucesso · Barbearia Central',health:91,lastSignal:'Perguntou no grupo se existe automação para recuperar clientes inativos.',moment:'Alta abertura para nova oferta',expansionProduct:'Recuperação automática',expansionValue:2400,nextReview:'',notes:'Usar o resultado atual como prova antes de apresentar o módulo.'}
];
export function isUntouchedLegacySample(record){return legacyPostSaleSamples.some(sample=>Object.entries(sample).every(([k,v])=>record?.[k]===v)&&Object.keys(record).every(k=>k==='entered'||Object.hasOwn(sample,k)))}
export function normalizeWorkspace(raw){
 const fresh=freshWorkspace(),s=raw&&typeof raw==='object'&&!Array.isArray(raw)?structuredClone(raw):{};
 const result={...fresh,...s,whatsapp:{...fresh.whatsapp,...s.whatsapp},businessProfile:{...fresh.businessProfile,...s.businessProfile},settings:{...fresh.settings,...s.settings},ai:{...fresh.ai,...(s.ai&&typeof s.ai==='object'&&!Array.isArray(s.ai)?s.ai:{})}};
 for(const key of ['leads','columns','postSaleColumns','cadence','automations','automationRuns','reminders','notifications','manualApprovals'])result[key]=Array.isArray(s[key])?s[key].filter(x=>x&&typeof x==='object'&&!Array.isArray(x)):fresh[key];
 for(const key of ['memories','feedback'])result.ai[key]=Array.isArray(result.ai[key])?result.ai[key].filter(x=>x&&typeof x==='object'&&!Array.isArray(x)).slice(-500):[];
 const memoryCutoff=Date.now()-Math.max(7,Math.min(730,Number(result.ai.memoryRetentionDays)||180))*86400000;
 result.ai.memories=result.ai.memories.filter(m=>!m.at||!Number.isFinite(Date.parse(m.at))||Date.parse(m.at)>=memoryCutoff);
 for(const key of ['columns','postSaleColumns'])if(!result[key].length)result[key]=fresh[key];
 for(const c of Array.isArray(s.postSaleCustomers)?s.postSaleCustomers:[]){if(!c||!c.id||isUntouchedLegacySample(c)||result.leads.some(l=>l.id==='post-'+c.id||l.id===c.leadId&&l.board==='Pós-venda'))continue;const linked=result.leads.find(l=>l.id===c.leadId);result.leads.push({...c,id:'post-'+c.id,name:c.name||c.company||'Cliente',phone:c.phone||linked?.phone||'',board:'Pós-venda',product:c.expansionProduct||c.product||'',contractValue:c.contractValue||0,notes:c.notes||'',messages:[],calls:[]})}
 result.leads=result.leads.map(l=>{const board=BOARDS.includes(l.board)?l.board:'Principal',cols=board==='Pós-venda'?result.postSaleColumns:result.columns;return {...l,id:String(l.id||id()),name:String(l.name||'Contato'),phone:String(l.phone||''),board,stage:cols.some(c=>c.id===l.stage)?l.stage:cols[0].id,messages:Array.isArray(l.messages)?l.messages.filter(Boolean):[],calls:Array.isArray(l.calls)?l.calls.filter(c=>c&&typeof c==='object'):[],notes:String(l.notes||''),entered:Number(l.entered)||Date.parse(l.entered)||Date.now()}});
 result.schemaVersion=4;
 return result;
}
export function elapsed(since,now=Date.now()){const hours=Math.max(0,Math.floor((now-new Date(since).getTime())/3600000));return hours<1?'menos de 1h':hours<24?hours+'h':Math.floor(hours/24)+'d '+hours%24+'h'}
export function canContact(l){return !!l&&!l.optOut&&l.stage!=='closed'&&l.board!=='Pós-venda'}
export function callRecorded(l){return Array.isArray(l?.calls)&&l.calls.some(c=>c?.id&&c.at&&c.outcome&&!['agendada','cancelada','scheduled','planned','cancelled'].includes(String(c.outcome).toLowerCase())&&Number.isFinite(Date.parse(c.at))&&Date.parse(c.at)<=Date.now())}
export function nextDue(l,w,now=Date.now()){
 if(!canContact(l))return null;
 if(l.nextDate)return {at:new Date(l.nextDate).getTime(),type:l.nextAction||'Ligação',reason:'Agendamento'};
 if(l.automationPaused)return null;
 if(l.board==='Abandonados'){if(!l.discardReason||!l.recoveryAt)return null;return {at:new Date(l.recoveryAt).getTime(),type:'Revisar recuperação',reason:l.discardReason}}
 if(!callRecorded(l))return {at:l.entered,type:'Ligação',reason:'Primeiro contato'};
 if(l.cadenceEnabled){const step=w.cadence[l.cadenceIndex||0];if(step){const factor=/dia/.test(step.unit)?24:1;return {at:Number(l.cadenceStarted||l.entered)+Number(step.delay)*factor*3600000,type:step.action==='Ligar'?'Ligação':'Mensagem',reason:'Etapa '+((l.cadenceIndex||0)+1)}}}
 const last=new Date(l.lastContactAt||l.entered).getTime();
 if(l.board==='Principal'&&now-last>=Number(w.settings.inactiveDays||30)*86400000)return {at:last+Number(w.settings.inactiveDays||30)*86400000,type:'Retomar contato',reason:'Inativo'};
 if(l.stage==='waiting'){const col=w.columns.find(c=>c.id===l.stage);if(col?.limit===0)return null;return {at:Math.max(l.entered,Number(l.lastTaskCompletedAt)||0)+Number(col?.limit||24)*3600000,type:'Follow-up',reason:'Aguardando resposta'}}
 return null;
}
export function taskList(w,now=Date.now()){return w.leads.map(lead=>({lead,task:nextDue(lead,w,now)})).filter(x=>x.task&&Number.isFinite(x.task.at)).sort((a,b)=>a.task.at-b.task.at)}
export function dueReviewActions(w,now=Date.now()){
 const niche=w.businessProfile?.customNiche||w.businessProfile?.niche||'Serviços';
 return taskList(w,now).filter(({task})=>task.at<=now).map(({lead,task})=>{
  const due=Math.floor(task.at/1000),index=Math.max(0,Number(lead.cadenceIndex)||0);
  let dedupeKey=`task:${lead.id}:${task.type}:${due}`,kind='task',title=task.type,summary=task.reason||'Revise o contexto e conclua a próxima ação.',text='';
  if(task.reason==='Agendamento'){dedupeKey=`schedule:${lead.id}:${due}`;kind='appointment';title=`${task.type} agendada`;summary='Revise o contexto e conclua a próxima ação.'}
  else if(lead.board==='Abandonados'){dedupeKey=`recovery:${lead.id}:${due}`;kind='recovery';title='Revisar recuperação';summary=lead.discardReason||summary;text=suggestions(niche,lead)[1]}
  else if(!callRecorded(lead)){dedupeKey=`call-first:${lead.id}:${due}`;kind='call';title='Primeiro contato por ligação';summary='Registre uma tentativa de ligação antes de preparar qualquer mensagem.'}
  else if(lead.cadenceEnabled&&task.reason===`Etapa ${index+1}`){const step=w.cadence[index]||{};dedupeKey=`cadence:${lead.id}:${index}:${due}`;kind=task.type==='Ligação'?'call':'cadence';title=`Cadência · etapa ${index+1}`;summary=kind==='call'?'Faça a ligação e registre o resultado.':'Revise a mensagem antes de autorizar o envio.';text=kind==='cadence'?String(step.text||'').replaceAll('{nome}',String(lead.name||'Contato').split(' ')[0]):''}
  else if(task.type==='Retomar contato'||task.type==='Follow-up'){kind='followup';title=task.type;summary=task.reason||summary;text=suggestions(niche,lead)[1]}
  return {dedupeKey,leadId:lead.id,leadName:lead.name,kind,title,summary,text,dueAt:new Date(task.at).toISOString()};
 });
}
const calendarStamp=value=>new Date(value).toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');
const calendarText=value=>String(value||'').replace(/\\/g,'\\\\').replace(/\r?\n/g,'\\n').replace(/,/g,'\\,').replace(/;/g,'\\;');
export function calendarEvent(lead,task,business='PulseFlow'){
 const start=Number(task?.at),end=start+30*60000;
 if(!lead||!Number.isFinite(start))return null;
 const title=`${task.type||'Contato'} · ${lead.name||'Contato'}`,description=[task.reason,lead.product&&`Produto: ${lead.product}`,lead.needs&&`Objetivo: ${lead.needs}`,`Organizado no ${business}`].filter(Boolean).join('\n');
 const dates=`${calendarStamp(start)}/${calendarStamp(end)}`,query=new URLSearchParams({action:'TEMPLATE',text:title,dates,details:description});
 const uid=`${String(lead.id||'contato').replace(/[^a-zA-Z0-9-]/g,'')}@pulseflow`;
 const ics=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//PulseFlow//Agenda//PT-BR','CALSCALE:GREGORIAN','BEGIN:VEVENT',`UID:${calendarText(uid)}`,`DTSTAMP:${calendarStamp(Date.now())}`,`DTSTART:${calendarStamp(start)}`,`DTEND:${calendarStamp(end)}`,`SUMMARY:${calendarText(title)}`,`DESCRIPTION:${calendarText(description)}`,'END:VEVENT','END:VCALENDAR',''].join('\r\n');
 return {title,url:`https://calendar.google.com/calendar/render?${query}`,ics};
}
export function suggestions(niche,l={}){const name=(l.name||'{nome}').split(' ')[0];const topic={'Barbearia':'corte, barba ou os dois','Salão de beleza':'corte, cor ou tratamento','Clínica':'sua avaliação inicial','Loja':'o produto e o prazo que você procura','Imobiliária':'a região, o orçamento e o prazo da busca','Marketing e tráfego':'sua oferta, público e objetivo com os anúncios'}[niche];return [topic?`Oi, ${name}! Posso entender melhor seu interesse em ${topic}?`:`Oi, ${name}! Qual resultado você procura e o que é prioridade agora?`,l.discardReason?`${name}, quando conversamos, você mencionou ${l.discardReason}. Esse cenário mudou ou prefere retomar em outro momento?`:`${name}, ficou alguma dúvida sobre ${l.product||'o que conversamos'}? Posso ajudar a definir o próximo passo.`,`${name}, faz sentido marcarmos uma conversa breve para entender ${l.needs||'o que você precisa'} e avaliar os próximos passos?` ]}
export function contextualTips(l){const tips=[];if(l.optOut)return ['Este contato pediu para não receber mensagens. Mantenha o acompanhamento pausado.'];if(!l.needs)tips.push('Pergunte: qual resultado você espera alcançar e por que isso importa agora?');if(!callRecorded(l))tips.push('Registre uma tentativa de ligação antes de preparar a primeira mensagem.');if(l.discardReason)tips.push('Confirme se o motivo do descarte ainda se aplica: '+l.discardReason+'.');if(l.product&&!l.contractValue)tips.push('Confirme escopo e expectativas antes de apresentar o investimento.');if(l.notes)tips.push('Use suas notas como contexto. Confirme com o cliente o que ainda estiver em aberto.');tips.push('Antes de sugerir uma reunião, confirme o objetivo, quem participa e a disponibilidade.');return tips.slice(0,4)}
export function messageData(m){return Array.isArray(m)?{direction:m[0],body:m[1],time:m[2],status:'registro anterior'}:m}
