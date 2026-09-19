// GET/POST/DELETE /api/users  — admin only
async function sha256(str){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function getSession(request, env){
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if(!token) return null;
  const raw = await env.PANEL_KV.get('session:'+token);
  return raw ? JSON.parse(raw) : null;
}
async function getUsers(env){
  const raw = await env.PANEL_KV.get('users');
  return raw ? JSON.parse(raw) : [];
}

export async function onRequestGet({request, env}){
  const session = await getSession(request, env);
  if(!session || session.role !== 'admin') return new Response('Unauthorized', {status:401});
  const users = await getUsers(env);
  return new Response(JSON.stringify({users: users.map(u=>({username:u.username, role:u.role}))}), {headers:{'content-type':'application/json'}});
}

export async function onRequestPost({request, env}){
  const session = await getSession(request, env);
  if(!session || session.role !== 'admin') return new Response('Unauthorized', {status:401});
  let body;
  try{ body = await request.json(); }catch(e){ return new Response('Bad request', {status:400}); }
  const {username, password, role} = body || {};
  if(!username || !password || !['admin','viewer'].includes(role)) return new Response('Invalid input', {status:400});
  const users = await getUsers(env);
  if(users.find(u=>u.username===username)) return new Response('User exists', {status:409});
  const passHash = await sha256(password);
  users.push({username, passHash, role});
  await env.PANEL_KV.put('users', JSON.stringify(users));
  return new Response('ok');
}

export async function onRequestDelete({request, env}){
  const session = await getSession(request, env);
  if(!session || session.role !== 'admin') return new Response('Unauthorized', {status:401});
  const url = new URL(request.url);
  const username = url.searchParams.get('username');
  if(!username) return new Response('Missing username', {status:400});
  let users = await getUsers(env);
  users = users.filter(u=>u.username!==username);
  await env.PANEL_KV.put('users', JSON.stringify(users));
  return new Response('ok');
}
