// GET/PUT /api/data — reads/writes the panel's JSON blob { items, finance }
async function getSession(request, env){
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if(!token) return null;
  const raw = await env.PANEL_KV.get('session:'+token);
  return raw ? JSON.parse(raw) : null;
}

export async function onRequestGet({request, env}){
  const session = await getSession(request, env);
  if(!session) return new Response('Unauthorized', {status:401});
  const val = await env.PANEL_KV.get('workorders');
  return new Response(val || '{"items":{},"finance":{}}', {headers:{'content-type':'application/json; charset=utf-8'}});
}

export async function onRequestPut({request, env}){
  const session = await getSession(request, env);
  if(!session) return new Response('Unauthorized', {status:401});
  if(session.role !== 'admin') return new Response('Forbidden — viewer role is read-only', {status:403});
  const body = await request.text();
  try{ JSON.parse(body); }catch(e){ return new Response('Bad JSON', {status:400}); }
  await env.PANEL_KV.put('workorders', body);
  return new Response('ok');
}
