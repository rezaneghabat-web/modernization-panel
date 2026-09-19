// POST /api/login  { username, password }  -> { token, role, username }
async function sha256(str){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function getUsers(env){
  const raw = await env.PANEL_KV.get('users');
  return raw ? JSON.parse(raw) : [];
}

export async function onRequestPost({request, env}){
  let body;
  try{ body = await request.json(); }catch(e){ return new Response('Bad request', {status:400}); }
  const {username, password} = body || {};
  if(!username || !password) return new Response('Missing credentials', {status:400});

  let role = null;
  // Bootstrap / recovery admin login via environment variables
  if(env.ADMIN_USER && env.ADMIN_PASS && username === env.ADMIN_USER && password === env.ADMIN_PASS){
    role = 'admin';
  } else {
    const users = await getUsers(env);
    const hash = await sha256(password);
    const u = users.find(u => u.username === username && u.passHash === hash);
    if(u) role = u.role;
  }
  if(!role) return new Response('Invalid credentials', {status:401});

  const token = crypto.randomUUID();
  await env.PANEL_KV.put('session:'+token, JSON.stringify({username, role}), {expirationTtl: 60*60*24*7});
  return new Response(JSON.stringify({token, role, username}), {headers:{'content-type':'application/json'}});
}
