const COOKIE="bol_session", SESSION_DAYS=7;
const MAPS={
  hardpoint:["Raid","Standoff","Slums","Yemen"],
  snd:["Raid","Standoff","Meltdown","Express"],
  ctf:["Raid","Standoff","Slums"]
};
const ALLOWED_LEAGUES=[3,4];

const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json;charset=UTF-8",...headers}});
const body=async r=>{try{return await r.json()}catch{return {}}};
function cors(r){const o=r.headers.get("Origin");return {"Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Credentials":"true",...(o?{"Access-Control-Allow-Origin":o,"Vary":"Origin"}:{})}}
function cookie(t){return `${COOKIE}=${encodeURIComponent(t)}; Path=/; Max-Age=${SESSION_DAYS*86400}; HttpOnly; SameSite=Lax; Secure`}
function delCookie(){return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`}
function getCookie(r){const c=r.headers.get("Cookie")||"",m=c.match(new RegExp("(^|;\\s*)"+COOKIE+"=([^;]+)"));return m?decodeURIComponent(m[2]):null}
async function hash(password,salt=crypto.randomUUID()){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);const b=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:100000,hash:"SHA-256"},k,256);return salt+"."+btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll("=","")}
async function verify(p,s){if(!s||!s.includes("."))return false;const [salt,h]=s.split(".");return await hash(p,salt)===salt+"."+h}
async function col(env,t,c,d){const x=await env.DB.prepare(`PRAGMA table_info(${t})`).all();if(!x.results.some(a=>a.name===c))await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${d}`).run()}
async function init(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS clans(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,captain_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS members(clan_id INTEGER NOT NULL,user_id INTEGER NOT NULL,joined_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(clan_id,user_id))`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS invites(id INTEGER PRIMARY KEY AUTOINCREMENT,clan_id INTEGER NOT NULL,inviter_id INTEGER NOT NULL,invitee_id INTEGER NOT NULL,status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY AUTOINCREMENT,creator_clan_id INTEGER NOT NULL,accepter_clan_id INTEGER,status TEXT DEFAULT 'open',map1 TEXT NOT NULL,map2 TEXT NOT NULL,map3 TEXT NOT NULL,winner_clan_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,completed_at TEXT)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id INTEGER NOT NULL,clan_id INTEGER NOT NULL,winner_clan_id INTEGER NOT NULL,UNIQUE(challenge_id,clan_id))`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS scores(clan_id INTEGER PRIMARY KEY,points INTEGER DEFAULT 0,wins INTEGER DEFAULT 0,losses INTEGER DEFAULT 0,played INTEGER DEFAULT 0)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,type TEXT DEFAULT 'general',is_read INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id INTEGER NOT NULL,user_id INTEGER NOT NULL,message TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`).run();
  for(const [t,c,d] of [
    ["users","psn_id","TEXT"],["users","is_blocked","INTEGER DEFAULT 0"],["users","blocked_until","INTEGER"],
    ["clans","league","INTEGER DEFAULT 4"],["clans","clan_code","TEXT"],
    ["members","role","TEXT DEFAULT 'member'"],
    ["challenges","team_size","INTEGER DEFAULT 4"],["challenges","game_modes",`TEXT DEFAULT '["snd"]'`],["challenges","scheduled_at","TEXT"],["challenges","expires_at","TEXT"],["challenges","cancel_reason","TEXT"],["challenges","cancelled_at","TEXT"],
    ["scores","league","INTEGER DEFAULT 4"]
  ]){try{await col(env,t,c,d)}catch(e){console.log("MIGRATION",t,c,e.message)}}
  // Crear un código único para clanes antiguos y fijar liga 4 si no existe.
  const old=await env.DB.prepare(`SELECT id FROM clans WHERE clan_code IS NULL OR clan_code=''`).all();
  for(const c of old.results){await env.DB.prepare(`UPDATE clans SET clan_code=? WHERE id=?`).bind("BOL-"+String(c.id).padStart(5,"0"),c.id).run()}
  // El usuario ADMIN se identifica por nombre, sin contraseña especial.
}
async function user(r,env){const t=getCookie(r);if(!t)return null;return await env.DB.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?`).bind(t,Date.now()).first()}
function admin(u){return !!u&&u.username.toLowerCase()==="admin"}
async function clanOf(env,uid,league=null){
  return league?await env.DB.prepare(`SELECT c.* FROM clans c JOIN members m ON m.clan_id=c.id WHERE m.user_id=? AND c.league=? LIMIT 1`).bind(uid,league).first()
  :await env.DB.prepare(`SELECT c.* FROM clans c JOIN members m ON m.clan_id=c.id WHERE m.user_id=? ORDER BY c.league LIMIT 1`).bind(uid).first()
}
async function expire(env){
  const now=new Date().toISOString();
  await env.DB.prepare(`UPDATE challenges SET status='expired',cancel_reason='No aceptado en 30 minutos',cancelled_at=? WHERE status='open' AND expires_at IS NOT NULL AND expires_at<=?`).bind(now,now).run()
}
function pick(list){return [...list].sort(()=>Math.random()-.5)[0]}
function challengeMaps(mode){
  if(mode==="snd") return [...MAPS.snd].sort(()=>Math.random()-.5).slice(0,3);
  return [pick(MAPS.hardpoint),pick(MAPS.snd),pick(MAPS.ctf)];
}

async function api(r,env,path){
  const H=cors(r); if(r.method==="OPTIONS")return new Response(null,{status:204,headers:H});
  await init(env); await expire(env);
  let me=await user(r,env);
  if(r.method==="GET"&&path==="/api/me")return json({user:me,admin:admin(me)},200,H);
  if(r.method==="POST"&&path==="/api/register"){
    const d=await body(r),u=String(d.username||"").trim(),p=String(d.password||"");
    if(u.length<3||u.length>20||p.length<6)return json({error:"Usuario 3-20 caracteres y contraseña mínimo 6."},400,H);
    if(await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(u).first())return json({error:"Ese usuario ya existe."},400,H);
    try{const x=await env.DB.prepare("INSERT INTO users(username,password_hash) VALUES(?,?)").bind(u,await hash(p)).run(),id=x.meta.last_row_id,t=crypto.randomUUID();await env.DB.prepare("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)").bind(t,id,Date.now()+SESSION_DAYS*864e5).run();return json({ok:true,user:{id,username:u}},200,{...H,"Set-Cookie":cookie(t)})}catch(e){return json({error:"No se pudo crear la cuenta.",detail:e.message},500,H)}
  }
  if(r.method==="POST"&&path==="/api/login"){
    const d=await body(r),u=String(d.username||"").trim(),p=String(d.password||""),x=await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(u).first();
    if(!x||!(await verify(p,x.password_hash)))return json({error:"Usuario o contraseña incorrectos."},401,H);
    if(x.is_blocked&&(x.blocked_until===null||x.blocked_until===undefined||Number(x.blocked_until)===0||Number(x.blocked_until)>Date.now()))return json({error:"Usuario bloqueado."},403,H);
    const t=crypto.randomUUID();await env.DB.prepare("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)").bind(t,x.id,Date.now()+SESSION_DAYS*864e5).run();return json({ok:true,user:{id:x.id,username:x.username}},200,{...H,"Set-Cookie":cookie(t)})
  }
  if(r.method==="POST"&&path==="/api/logout"){const t=getCookie(r);if(t)await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(t).run();return json({ok:true},200,{...H,"Set-Cookie":delCookie()})}
  if(!me)return json({error:"Debes iniciar sesión."},401,H);
  if(me.is_blocked&&(me.blocked_until===0||me.blocked_until> Date.now()))return json({error:"Usuario bloqueado."},403,H);

  if(r.method==="PUT"&&path==="/api/profile"){
    const d=await body(r),psn=String(d.psn_id||"").trim().slice(0,32);await env.DB.prepare("UPDATE users SET psn_id=? WHERE id=?").bind(psn,me.id).run();return json({ok:true},200,H)
  }
  if(r.method==="GET"&&path==="/api/users"){const q=String(new URL(r.url).searchParams.get("q")||"").trim();const rs=await env.DB.prepare(`SELECT id,username,psn_id,created_at FROM users WHERE username LIKE ? ORDER BY username LIMIT 50`).bind("%"+q+"%").all();return json(rs.results,200,H)}
  if(r.method==="GET"&&path.startsWith("/api/users/")){
    const id=Number(path.split("/").pop());const u=await env.DB.prepare("SELECT id,username,psn_id,created_at FROM users WHERE id=?").bind(id).first();if(!u)return json({error:"Jugador no encontrado."},404,H);const cs=await env.DB.prepare(`SELECT c.id,c.name,c.clan_code,c.league FROM clans c JOIN members m ON m.clan_id=c.id WHERE m.user_id=? ORDER BY c.league`).bind(id).all();return json({user:u,clans:cs.results},200,H)
  }
  if(r.method==="GET"&&path==="/api/clans"){const sp=new URL(r.url).searchParams,q=String(sp.get("q")||""),l=Number(sp.get("league")||0);let sql=`SELECT c.id,c.name,c.clan_code,c.league,c.captain_id,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played,(SELECT COUNT(*) FROM members m WHERE m.clan_id=c.id) member_count FROM clans c LEFT JOIN scores s ON s.clan_id=c.id WHERE c.name LIKE ?`;const a=["%"+q+"%"];if(ALLOWED_LEAGUES.includes(l)){sql+=" AND c.league=?";a.push(l)}sql+=" ORDER BY points DESC,name LIMIT 100";return json((await env.DB.prepare(sql).bind(...a).all()).results,200,H)}
  if(r.method==="GET"&&/^\/api\/clans\/\d+$/.test(path)){
    const id=Number(path.split("/").pop()),c=await env.DB.prepare(`SELECT c.*,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played,(SELECT COUNT(*) FROM members m2 WHERE m2.clan_id=c.id) member_count FROM clans c LEFT JOIN scores s ON s.clan_id=c.id WHERE c.id=?`).bind(id).first();
    if(!c)return json({error:"Clan no encontrado."},404,H);
    const m=await env.DB.prepare(`SELECT u.id,u.username,u.psn_id,m.user_id,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.clan_id=? ORDER BY m.role DESC,u.username`).bind(id).all();
    const viewerMember=await env.DB.prepare("SELECT role FROM members WHERE clan_id=? AND user_id=?").bind(id,me.id).first();
    const pending=await env.DB.prepare("SELECT id FROM invites WHERE clan_id=? AND invitee_id=? AND status='join_pending'").bind(id,me.id).first();
    const requests=me.id===c.captain_id?await env.DB.prepare(`SELECT i.id,i.created_at,u.id user_id,u.username,u.psn_id FROM invites i JOIN users u ON u.id=i.invitee_id WHERE i.clan_id=? AND i.status='join_pending' ORDER BY i.id DESC`).bind(id).all():{results:[]};
    return json({clan:c,members:m.results,viewer_is_member:!!viewerMember,viewer_role:viewerMember?.role||null,join_request_pending:!!pending,join_requests:requests.results},200,H);
  }
  if(r.method==="POST"&&path==="/api/clans"){
    const d=await body(r),name=String(d.name||"").trim(),code=String(d.clan_code||"").trim().toUpperCase(),logo=String(d.logo_url||"").trim().slice(0,500),league=Number(d.league);
    if(name.length<2||name.length>24||!ALLOWED_LEAGUES.includes(league)||!/^[A-Z]{4}$/.test(code)) return json({error:"Nombre 2-24, insignia de 4 letras y liga 3v3 o 4v4."},400,H);
    const anyClan=await clanOf(env,me.id);
    if(anyClan) return json({error:"Ya perteneces a un equipo. Solo puedes pertenecer a un equipo a la vez."},400,H);
    if(await env.DB.prepare("SELECT id FROM clans WHERE name=? AND league=?").bind(name,league).first()) return json({error:"Ese nombre ya existe en esa liga."},400,H);
    if(await env.DB.prepare("SELECT id FROM clans WHERE clan_code=? AND league=?").bind(code,league).first()) return json({error:"Esa insignia ya está utilizada."},400,H);
    let id=null;
    try{
      const x=await env.DB.prepare("INSERT INTO clans(name,captain_id,league,clan_code,logo_url) VALUES(?,?,?,?,?)").bind(name,me.id,league,code,logo).run();
      id=x.meta.last_row_id;
      await env.DB.prepare("INSERT INTO members(clan_id,user_id,role) VALUES(?,?,?)").bind(id,me.id,"captain").run();
      const member=await env.DB.prepare("SELECT clan_id,user_id,role FROM members WHERE clan_id=? AND user_id=?").bind(id,me.id).first();
      if(!member) throw new Error("No se pudo registrar al capitán como miembro.");
      await env.DB.prepare("INSERT OR IGNORE INTO scores(clan_id,league) VALUES(?,?)").bind(id,league).run();
      return json({ok:true,clanId:id,clanCode:code,clan:{id,name,clan_code:code,league,captain_id:me.id,role:"captain"}},200,H);
    }catch(e){
      if(id) { try{await env.DB.prepare("DELETE FROM members WHERE clan_id=?").bind(id).run();await env.DB.prepare("DELETE FROM scores WHERE clan_id=?").bind(id).run();await env.DB.prepare("DELETE FROM clans WHERE id=?").bind(id).run()}catch(_){} }
      console.error("CREATE CLAN ERROR",e);
      return json({error:"No se pudo crear el clan.",detail:e.message},500,H);
    }
  }
  const joinMatch=path.match(/^\/api\/clans\/(\d+)\/join$/);
  if(r.method==="POST"&&joinMatch){
    const clanId=Number(joinMatch[1]);
    const clan=await env.DB.prepare("SELECT * FROM clans WHERE id=?").bind(clanId).first();
    if(!clan||!ALLOWED_LEAGUES.includes(Number(clan.league))) return json({error:"Clan no encontrado."},404,H);
    if(await env.DB.prepare("SELECT 1 FROM members WHERE user_id=?").bind(me.id).first()) return json({error:"Ya perteneces a un equipo."},400,H);
    const count=await env.DB.prepare("SELECT COUNT(*) n FROM members WHERE clan_id=?").bind(clanId).first();
    if(Number(count?.n||0)>=6)return json({error:"El equipo está completo."},400,H);
    if(await env.DB.prepare("SELECT id FROM invites WHERE clan_id=? AND invitee_id=? AND status='join_pending'").bind(clanId,me.id).first()) return json({error:"Ya has enviado una solicitud."},400,H);
    const x=await env.DB.prepare("INSERT INTO invites(clan_id,inviter_id,invitee_id,status) VALUES(?,?,?,'join_pending')").bind(clanId,me.id,clan.captain_id).run();
    await env.DB.prepare(`INSERT INTO notifications(user_id,title,message,type,is_read) VALUES(?,?,?,?,0)`).bind(clan.captain_id,"Solicitud para unirse","Un jugador quiere entrar en tu equipo.","clan_join_request").run();
    return json({ok:true,id:x.meta.last_row_id},200,H);
  }
  const joinAccept=path.match(/^\/api\/clan-requests\/(\d+)\/accept$/);
  if(r.method==="POST"&&joinAccept){
    const reqId=Number(joinAccept[1]);
    const req=await env.DB.prepare("SELECT i.*,c.league,c.captain_id FROM invites i JOIN clans c ON c.id=i.clan_id WHERE i.id=? AND i.status='join_pending'").bind(reqId).first();
    if(!req)return json({error:"Solicitud no encontrada."},404,H);
    if(req.captain_id!==me.id)return json({error:"Solo el capitán puede aceptar solicitudes."},403,H);
    const already=await env.DB.prepare("SELECT 1 FROM members WHERE user_id=?").bind(req.invitee_id).first();
    if(already)return json({error:"Ese jugador ya pertenece a un equipo."},400,H);
    const count=await env.DB.prepare("SELECT COUNT(*) n FROM members WHERE clan_id=?").bind(req.clan_id).first();
    if(Number(count?.n||0)>=6)return json({error:"El equipo está completo."},400,H);
    await env.DB.prepare("INSERT INTO members(clan_id,user_id,role) VALUES(?,?,?)").bind(req.clan_id,req.invitee_id,"member").run();
    await env.DB.prepare("UPDATE invites SET status='accepted' WHERE id=?").bind(reqId).run();
    await env.DB.prepare(`INSERT INTO notifications(user_id,title,message,type,is_read) VALUES(?,?,?,?,0)`).bind(req.invitee_id,"Solicitud aceptada","Has entrado en el equipo.","clan_join_accepted").run();
    return json({ok:true},200,H);
  }
  const joinReject=path.match(/^\/api\/clan-requests\/(\d+)\/reject$/);
  if(r.method==="POST"&&joinReject){
    const reqId=Number(joinReject[1]);
    const req=await env.DB.prepare("SELECT i.*,c.captain_id FROM invites i JOIN clans c ON c.id=i.clan_id WHERE i.id=? AND i.status='join_pending'").bind(reqId).first();
    if(!req)return json({error:"Solicitud no encontrada."},404,H);
    if(req.captain_id!==me.id)return json({error:"Solo el capitán puede rechazar solicitudes."},403,H);
    await env.DB.prepare("UPDATE invites SET status='rejected' WHERE id=?").bind(reqId).run();
    await env.DB.prepare(`INSERT INTO notifications(user_id,title,message,type,is_read) VALUES(?,?,?,?,0)`).bind(req.invitee_id,"Solicitud rechazada","Tu solicitud para entrar en el equipo ha sido rechazada.","clan_join_rejected").run();
    return json({ok:true},200,H);
  }
  if(r.method==="GET"&&path==="/api/my-clan-requests"){
    const rows=await env.DB.prepare(`SELECT i.id,i.created_at,u.id user_id,u.username,u.psn_id,c.id clan_id,c.name clan_name,c.league FROM invites i JOIN users u ON u.id=i.invitee_id JOIN clans c ON c.id=i.clan_id WHERE i.status='join_pending' AND c.captain_id=? ORDER BY i.id DESC`).bind(me.id).all();
    return json({requests:rows.results},200,H);
  }
  if(r.method==="GET"&&path==="/api/leaderboard"){const l=Number(new URL(r.url).searchParams.get("league")||4);const rs=await env.DB.prepare(`SELECT c.id,c.name,c.clan_code,c.league,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played FROM clans c LEFT JOIN scores s ON s.clan_id=c.id WHERE c.league=? ORDER BY points DESC,wins DESC,name`).bind(l).all();return json(rs.results,200,H)}
  if(r.method==="POST"&&path==="/api/challenges"){
    const d=await body(r),league=Number(d.league||4),mode=String(d.mode||"snd");
    if(!ALLOWED_LEAGUES.includes(league)) return json({error:"Los retos solo están disponibles en 3v3 y 4v4."},400,H);
    if(!["snd","three_modes"].includes(mode)) return json({error:"Modalidad no válida."},400,H);
    const c=await clanOf(env,me.id,league);
    if(!c||c.captain_id!==me.id) return json({error:"Solo el capitán puede crear retos."},403,H);
    const active=await env.DB.prepare(`SELECT id FROM challenges WHERE (creator_clan_id=? OR accepter_clan_id=?) AND status IN('open','accepted') LIMIT 1`).bind(c.id,c.id).first();
    if(active)return json({error:"Tu equipo ya tiene un reto activo."},400,H);
    const dmaps=challengeMaps(mode),now=Date.now(),created=new Date(now).toISOString(),expires=new Date(now+30*60*1000).toISOString();
    const x=await env.DB.prepare(`INSERT INTO challenges(creator_clan_id,status,map1,map2,map3,team_size,game_modes,scheduled_at,expires_at) VALUES(?,'open',?,?,?,?,?,?,?)`).bind(c.id,dmaps[0],dmaps[1],dmaps[2],league,JSON.stringify(mode==="snd"?["snd","snd","snd"]:["hardpoint","snd","ctf"]),created,expires).run();
    return json({ok:true,id:x.meta.last_row_id,expires_at:expires,maps:dmaps,mode},200,H);
  }
  if(r.method==="GET"&&path==="/api/challenges"){await expire(env);const c=await clanOf(env,me.id,Number(new URL(r.url).searchParams.get("league")||4)),cid=c?.id||-1;const rs=await env.DB.prepare(`SELECT ch.*,a.name creator_name,a.clan_code creator_code,b.name accepter_name FROM challenges ch JOIN clans a ON a.id=ch.creator_clan_id LEFT JOIN clans b ON b.id=ch.accepter_clan_id WHERE (ch.status IN('open','accepted')) AND (a.league=?) AND (ch.status='open' OR ch.creator_clan_id=? OR ch.accepter_clan_id=?) ORDER BY ch.id DESC`).bind(Number(new URL(r.url).searchParams.get("league")||4),cid,cid).all();return json(rs.results,200,H)}
  const am=path.match(/^\/api\/challenges\/(\d+)\/accept$/);if(r.method==="POST"&&am){const id=Number(am[1]),ch=await env.DB.prepare("SELECT * FROM challenges WHERE id=? AND status='open'").bind(id).first(),c=await clanOf(env,me.id,Number(ch?.team_size||4));if(!ch||!c||c.id===ch.creator_clan_id||c.league!==Number(ch.team_size))return json({error:"Reto no disponible."},400,H);if(ch.expires_at&&ch.expires_at<=new Date().toISOString()){await env.DB.prepare("UPDATE challenges SET status='expired' WHERE id=?").bind(id).run();return json({error:"El reto ha caducado."},400,H)}await env.DB.prepare("UPDATE challenges SET accepter_clan_id=?,status='accepted' WHERE id=? AND status='open'").bind(c.id,id).run();return json({ok:true},200,H)}
  const rm=path.match(/^\/api\/challenges\/(\d+)\/report$/);if(r.method==="POST"&&rm){const id=Number(rm[1]),d=await body(r),c=await clanOf(env,me.id),ch=await env.DB.prepare("SELECT * FROM challenges WHERE id=? AND status='accepted'").bind(id).first();if(!c||!ch||![ch.creator_clan_id,ch.accepter_clan_id].includes(c.id)||c.captain_id!==me.id)return json({error:"No puedes reportar este reto."},403,H);const winner=String(d.result)==="win"?c.id:(c.id===ch.creator_clan_id?ch.accepter_clan_id:ch.creator_clan_id);await env.DB.prepare("INSERT OR REPLACE INTO reports(challenge_id,clan_id,winner_clan_id) VALUES(?,?,?)").bind(id,c.id,winner).run();const rs=await env.DB.prepare("SELECT * FROM reports WHERE challenge_id=?").bind(id).all();if(rs.results.length<2)return json({ok:true,completed:false,message:"Resultado enviado. Falta el otro capitán."},200,H);if(rs.results[0].winner_clan_id!==rs.results[1].winner_clan_id)return json({ok:true,completed:false,conflict:true,message:"Los resultados no coinciden."},200,H);const w=rs.results[0].winner_clan_id,loser=w===ch.creator_clan_id?ch.accepter_clan_id:ch.creator_clan_id;await env.DB.batch([env.DB.prepare(`UPDATE challenges SET status='completed',winner_clan_id=?,completed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(w,id),env.DB.prepare(`UPDATE scores SET played=played+1,wins=wins+1,points=points+10 WHERE clan_id=?`).bind(w),env.DB.prepare(`UPDATE scores SET played=played+1,losses=losses+1,points=MAX(points-5,0) WHERE clan_id=?`).bind(loser)]);return json({ok:true,completed:true},200,H)}
  if(r.method==="GET"&&path==="/api/history"){const c=await clanOf(env,me.id),rs=await env.DB.prepare(`SELECT ch.*,a.name creator_name,b.name accepter_name,w.name winner_name FROM challenges ch JOIN clans a ON a.id=ch.creator_clan_id LEFT JOIN clans b ON b.id=ch.accepter_clan_id LEFT JOIN clans w ON w.id=ch.winner_clan_id WHERE ch.status='completed' AND (ch.creator_clan_id=? OR ch.accepter_clan_id=?) ORDER BY ch.id DESC LIMIT 100`).bind(c?.id||-1,c?.id||-1).all();return json(rs.results,200,H)}
  if(admin(me)){
    if(r.method==="GET"&&path==="/api/admin/users"){return json((await env.DB.prepare("SELECT id,username,psn_id,is_blocked,blocked_until,created_at FROM users ORDER BY id DESC LIMIT 500").all()).results,200,H)}
    if(r.method==="POST"&&path==="/api/admin/block"){const d=await body(r),id=Number(d.user_id),until=d.permanent?0:Date.now()+Number(d.minutes||60)*60000;await env.DB.prepare("UPDATE users SET is_blocked=1,blocked_until=? WHERE id=?").bind(until,id).run();await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();return json({ok:true},200,H)}
    if(r.method==="POST"&&path==="/api/admin/unblock"){const d=await body(r);await env.DB.prepare("UPDATE users SET is_blocked=0,blocked_until=NULL WHERE id=?").bind(Number(d.user_id)).run();return json({ok:true},200,H)}
    if(r.method==="POST"&&path==="/api/admin/reset-ranking"){const l=Number((await body(r)).league||4);await env.DB.prepare("UPDATE scores SET points=0,wins=0,losses=0,played=0 WHERE league=?").bind(l).run();return json({ok:true},200,H)}
    if(r.method==="POST"&&path==="/api/admin/delete-challenge"){const d=await body(r);await env.DB.prepare("UPDATE challenges SET status='cancelled',cancel_reason='ADMIN',cancelled_at=CURRENT_TIMESTAMP WHERE id=?").bind(Number(d.challenge_id)).run();return json({ok:true},200,H)}
  }
  return json({error:"Ruta no encontrada."},404,H)
}
async function handle(r,env){const u=new URL(r.url);if(u.pathname.startsWith("/api/"))return api(r,env,u.pathname);return env.ASSETS?.fetch(r)??new Response("BlackOpsLALIGA",{status:200})}
export default {async fetch(r,env){try{return await handle(r,env)}catch(e){console.error(e);return json({error:"Error interno del servidor",detail:e.message},500,cors(r))}}}
