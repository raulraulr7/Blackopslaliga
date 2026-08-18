const COOKIE = "bol_session";
const SESSION_DAYS = 30;
const MAPS = ["Raid","Standoff","Slums","Yemen","Meltdown","Express"];
const LEAGUES = {1:1,2:2,3:3,4:4};

const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json;charset=UTF-8",...headers}});
const body=async r=>{try{return await r.json()}catch{return {}}};
function cors(r){const o=r.headers.get("Origin");return {"Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Credentials":"true",...(o?{"Access-Control-Allow-Origin":o,"Vary":"Origin"}:{})}}
function setCookie(t){return `${COOKIE}=${encodeURIComponent(t)}; Path=/; Max-Age=${SESSION_DAYS*86400}; HttpOnly; SameSite=Lax; Secure`}
function delCookie(){return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`}
function getCookie(r){const c=r.headers.get("Cookie")||"",m=c.match(new RegExp("(^|;\\s*)"+COOKIE+"=([^;]+)"));return m?decodeURIComponent(m[2]):null}
async function hash(password,salt=crypto.randomUUID()){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);const b=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:100000,hash:"SHA-256"},k,256);return salt+"."+btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll("=","")}
async function verify(password,stored){if(!stored||!stored.includes("."))return false;const [salt,h]=stored.split(".");return await hash(password,salt)===salt+"."+h}
async function ensureColumn(env,table,column,definition){const x=await env.DB.prepare(`PRAGMA table_info(${table})`).all();if(!x.results.some(v=>v.name===column))await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run()}

async function init(env){
  const tables=[
    `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS clans(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,captain_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS members(clan_id INTEGER NOT NULL,user_id INTEGER NOT NULL,joined_at TEXT DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(clan_id,user_id))`,
    `CREATE TABLE IF NOT EXISTS invites(id INTEGER PRIMARY KEY AUTOINCREMENT,clan_id INTEGER NOT NULL,inviter_id INTEGER NOT NULL,invitee_id INTEGER NOT NULL,status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY AUTOINCREMENT,creator_clan_id INTEGER NOT NULL,accepter_clan_id INTEGER,status TEXT DEFAULT 'open',map1 TEXT NOT NULL,map2 TEXT NOT NULL,map3 TEXT NOT NULL,winner_clan_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,completed_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id INTEGER NOT NULL,clan_id INTEGER NOT NULL,winner_clan_id INTEGER NOT NULL,UNIQUE(challenge_id,clan_id))`,
    `CREATE TABLE IF NOT EXISTS scores(clan_id INTEGER PRIMARY KEY,points INTEGER DEFAULT 0,wins INTEGER DEFAULT 0,losses INTEGER DEFAULT 0,played INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,type TEXT DEFAULT 'general',is_read INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id INTEGER NOT NULL,user_id INTEGER NOT NULL,message TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS community_messages(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,league INTEGER,message TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS admin_result_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id INTEGER NOT NULL,admin_user_id INTEGER NOT NULL,action TEXT NOT NULL,old_winner_clan_id INTEGER,new_winner_clan_id INTEGER,reason TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`,
  ];
  for(const sql of tables) await env.DB.prepare(sql).run();
  const cols=[
    ["users","psn_id","TEXT"],["users","avatar_url","TEXT"],["users","is_blocked","INTEGER DEFAULT 0"],["users","blocked_until","INTEGER"],
    ["clans","league","INTEGER DEFAULT 4"],["clans","clan_code","TEXT"],["clans","logo_url","TEXT"],
    ["members","role","TEXT DEFAULT 'member'"],
    ["challenges","team_size","INTEGER DEFAULT 4"],["challenges","game_modes",`TEXT DEFAULT '["snd"]'`],["challenges","scheduled_at","TEXT"],["challenges","expires_at","TEXT"],["challenges","cancel_reason","TEXT"],["challenges","cancelled_at","TEXT"],["challenges","one_vs_one_mode","TEXT"],["challenges","admin_result_modified","INTEGER DEFAULT 0"],["challenges","admin_result_reason","TEXT"],
    ["scores","league","INTEGER DEFAULT 4"],
    ["notifications","target_type","TEXT"],["notifications","target_id","INTEGER"]
  ];
  for(const [t,c,d] of cols){try{await ensureColumn(env,t,c,d)}catch(e){console.log("migration",t,c,e.message)}}
  const old=await env.DB.prepare(`SELECT id FROM clans WHERE clan_code IS NULL OR clan_code=''`).all();
  for(const c of old.results)await env.DB.prepare(`UPDATE clans SET clan_code=? WHERE id=?`).bind("BOL-"+String(c.id).padStart(5,"0"),c.id).run();
}

async function currentUser(r,env){const t=getCookie(r);if(!t)return null;return await env.DB.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?`).bind(t,Date.now()).first()}
function isAdmin(u){return !!u&&String(u.username||"").toLowerCase()==="admin"}
function leagueName(l){return Number(l)===1?"1v1":`${l}v${l}`}
function teamSizeForLeague(l){return Number(l)}
async function clanOf(env,userId,league){return await env.DB.prepare(`SELECT c.* FROM clans c JOIN members m ON m.clan_id=c.id WHERE m.user_id=? AND c.league=? LIMIT 1`).bind(userId,league).first()}
async function userClans(env,userId){return (await env.DB.prepare(`SELECT c.id,c.name,c.clan_code,c.logo_url,c.league,c.captain_id,m.role,(SELECT COUNT(*) FROM members mm WHERE mm.clan_id=c.id) member_count,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played FROM clans c JOIN members m ON m.clan_id=c.id LEFT JOIN scores s ON s.clan_id=c.id WHERE m.user_id=? ORDER BY c.league`).bind(userId).all()).results}
async function notify(env,userId,title,message,type,targetType=null,targetId=null){await env.DB.prepare(`INSERT INTO notifications(user_id,title,message,type,is_read,target_type,target_id) VALUES(?,?,?,?,0,?,?)`).bind(userId,title,message,type,targetType,targetId).run()}
async function notifyClan(env,clanId,title,message,type,targetType=null,targetId=null){const ms=await env.DB.prepare(`SELECT user_id FROM members WHERE clan_id=?`).bind(clanId).all();for(const m of ms.results)await notify(env,m.user_id,title,message,type,targetType,targetId)}
async function expire(env){const now=new Date().toISOString();const old=await env.DB.prepare(`SELECT id FROM challenges WHERE status='open' AND expires_at IS NOT NULL AND expires_at<=?`).bind(now).all();for(const c of old.results){await env.DB.prepare(`DELETE FROM reports WHERE challenge_id=?`).bind(c.id).run();await env.DB.prepare(`DELETE FROM chat_messages WHERE challenge_id=?`).bind(c.id).run();await env.DB.prepare(`DELETE FROM challenges WHERE id=? AND status='open'`).bind(c.id).run()}}
function maps(){return [...MAPS].sort(()=>Math.random()-.5).slice(0,3)}
async function memberCount(env,clanId){const r=await env.DB.prepare(`SELECT COUNT(*) total FROM members WHERE clan_id=?`).bind(clanId).first();return Number(r?.total||0)}
async function clanStatus(env,clan){const active=await env.DB.prepare(`SELECT id,status FROM challenges WHERE (creator_clan_id=? OR accepter_clan_id=?) AND status IN('open','accepted','pending_result') LIMIT 1`).bind(clan.id,clan.id).first();if(active)return active.status==='open'?'waiting':active.status==='accepted'?'battle':'battle';return 'available'}

async function deleteChallenge(env,id){await env.DB.prepare(`DELETE FROM reports WHERE challenge_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM chat_messages WHERE challenge_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM challenges WHERE id=?`).bind(id).run()}
async function deleteClan(env,id){const ch=await env.DB.prepare(`SELECT id FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?`).bind(id,id).all();for(const c of ch.results)await deleteChallenge(env,c.id);await env.DB.prepare(`DELETE FROM invites WHERE clan_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM members WHERE clan_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM scores WHERE clan_id=?`).bind(id).run();await env.DB.prepare(`DELETE FROM clans WHERE id=?`).bind(id).run()}
async function addWin(env,clanId){await env.DB.prepare(`UPDATE scores SET points=points+3,wins=wins+1,played=played+1 WHERE clan_id=?`).bind(clanId).run()}
async function addLoss(env,clanId){await env.DB.prepare(`UPDATE scores SET losses=losses+1,played=played+1 WHERE clan_id=?`).bind(clanId).run()}
async function rebuildScores(env){await env.DB.prepare(`UPDATE scores SET points=0,wins=0,losses=0,played=0`).run();const rs=(await env.DB.prepare(`SELECT id,creator_clan_id,accepter_clan_id,winner_clan_id FROM challenges WHERE status='completed' AND winner_clan_id IS NOT NULL`).all()).results;for(const ch of rs){const loser=Number(ch.winner_clan_id)===Number(ch.creator_clan_id)?Number(ch.accepter_clan_id):Number(ch.creator_clan_id);await addWin(env,Number(ch.winner_clan_id));if(loser)await addLoss(env,loser)}}

async function api(r,env,path){
 const H=cors(r); if(r.method==='OPTIONS')return new Response(null,{status:204,headers:H}); await init(env); await expire(env); let me=await currentUser(r,env);
    /* ===================================================
     AUTH
  =================================================== */

  if(r.method==="POST" && path==="/api/register"){
    const d=await body(r);
    const username=String(d.username||"").trim();
    const password=String(d.password||"");

    if(username.length<3||username.length>20||password.length<6)
      return json({error:"Usuario 3-20 caracteres y contraseña mínimo 6."},400,H);

    const exists=await env.DB.prepare(`SELECT id FROM users WHERE LOWER(username)=LOWER(?)`).bind(username).first();
    if(exists)return json({error:"Ese usuario ya existe."},400,H);

    try{
      const ph=await hash(password);
      const x=await env.DB.prepare(`INSERT INTO users(username,password_hash) VALUES(?,?)`).bind(username,ph).run();
      const token=crypto.randomUUID();

      await env.DB.prepare(`INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)`)
        .bind(token,x.meta.last_row_id,Date.now()+SESSION_DAYS*86400000).run();

      return json({
        ok:true,
        user:{id:x.meta.last_row_id,username},
        clans:[]
      },200,{...H,"Set-Cookie":setCookie(token)});
    }catch(e){
      return json({error:"No se pudo crear la cuenta.",detail:e.message},500,H);
    }
  }


  if(r.method==="POST" && path==="/api/login"){
    const d=await body(r);
    const username=String(d.username||"").trim();
    const password=String(d.password||"");

    const u=await env.DB.prepare(`SELECT * FROM users WHERE LOWER(username)=LOWER(?)`).bind(username).first();

    if(!u||!(await verify(password,u.password_hash)))
      return json({error:"Usuario o contraseña incorrectos."},401,H);

    if(u.is_blocked && (!u.blocked_until||Number(u.blocked_until)>Date.now()))
      return json({error:"Usuario bloqueado."},403,H);

    const token=crypto.randomUUID();

    await env.DB.prepare(`INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)`)
      .bind(token,u.id,Date.now()+SESSION_DAYS*86400000).run();

    return json({
      ok:true,
      user:{
        id:u.id,
        username:u.username,
        psn_id:u.psn_id,
        avatar_url:u.avatar_url
      },
      admin:isAdmin(u),
      clans:await userClans(env,u.id)
    },200,{...H,"Set-Cookie":setCookie(token)});
  }


  if(r.method==="POST" && path==="/api/logout"){
    const token=getCookie(r);
    if(token)
      await env.DB.prepare(`DELETE FROM sessions WHERE token=?`).bind(token).run();

    return json({ok:true},200,{...H,"Set-Cookie":delCookie()});
  }


  /* ===================================================
     ME / PERFIL
  =================================================== */

  if(r.method==="GET" && path==="/api/me"){
    return json({
      user:me,
      admin:isAdmin(me),
      clans:me?await userClans(env,me.id):[]
    },200,H);
  }


  if(r.method==="PUT" && path==="/api/profile"){
    const d=await body(r);

    await env.DB.prepare(`
      UPDATE users
      SET psn_id=?,avatar_url=?
      WHERE id=?
    `)
      .bind(
        String(d.psn_id||"").trim().slice(0,32),
        String(d.avatar_url||"").trim().slice(0,500),
        me.id
      )
      .run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     USUARIOS
  =================================================== */

  if(r.method==="GET" && path==="/api/users"){
    const q=new URL(r.url).searchParams.get("q")||"";

    const result=await env.DB.prepare(`
      SELECT id,username,psn_id,avatar_url,created_at
      FROM users
      WHERE username LIKE ?
      ORDER BY username
      LIMIT 100
    `).bind("%"+q.trim()+"%").all();

    return json(result.results,200,H);
  }


  if(r.method==="GET" && /^\/api\/users\/\d+$/.test(path)){
    const id=Number(path.split("/").pop());

    const user=await env.DB.prepare(`
      SELECT id,username,psn_id,avatar_url,created_at
      FROM users
      WHERE id=?
    `).bind(id).first();

    if(!user)
      return json({error:"Jugador no encontrado."},404,H);

    return json({
      user,
      clans:await userClans(env,id)
    },200,H);
  }


  /* ===================================================
     CLANES
  =================================================== */

  if(r.method==="GET" && path==="/api/my-clans"){
    const clans=await userClans(env,me.id);

    for(const c of clans)
      c.status=await clanStatus(env,c);

    return json(clans,200,H);
  }


  if(r.method==="POST" && path==="/api/clans"){
    const d=await body(r);

    const name=String(d.name||"").trim();
    const code=String(d.clan_code||"").trim().toUpperCase();
    const logo=String(d.logo_url||"").trim().slice(0,500);
    const league=Number(d.league);

    if(name.length<2||name.length>30)
      return json({error:"El nombre debe tener entre 2 y 30 caracteres."},400,H);

    if(!/^[A-Z0-9]{4}$/.test(code))
      return json({error:"La insignia debe tener 4 caracteres."},400,H);

    if(![1,2,3,4].includes(league))
      return json({error:"Liga no válida."},400,H);

    const already=await clanOf(env,me.id,league);

    if(already)
      return json({
        error:`Ya estás en un clan de ${leagueName(league)}.`
      },400,H);

    const nameExists=await env.DB.prepare(`
      SELECT id FROM clans
      WHERE LOWER(name)=LOWER(?) AND league=?
    `).bind(name,league).first();

    if(nameExists)
      return json({error:"Ya existe un clan con ese nombre en esta liga."},400,H);

    const codeExists=await env.DB.prepare(`
      SELECT id FROM clans WHERE UPPER(clan_code)=?
    `).bind(code).first();

    if(codeExists)
      return json({error:"Esa insignia ya está utilizada."},400,H);

    try{
      const x=await env.DB.prepare(`
        INSERT INTO clans(name,captain_id,league,clan_code,logo_url)
        VALUES(?,?,?,?,?)
      `).bind(name,me.id,league,code,logo).run();

      const clanId=x.meta.last_row_id;

      await env.DB.prepare(`
        INSERT INTO members(clan_id,user_id,role)
        VALUES(?,?,?)
      `).bind(clanId,me.id,"captain").run();

      await env.DB.prepare(`
        INSERT OR IGNORE INTO scores(clan_id,league,points,wins,losses,played)
        VALUES(?,?,0,0,0,0)
      `).bind(clanId,league).run();

      return json({
        ok:true,
        clan:{
          id:clanId,
          name,
          clan_code:code,
          logo_url:logo,
          league,
          captain_id:me.id,
          role:"captain",
          member_count:1,
          points:0,
          wins:0,
          losses:0,
          played:0,
          status:"available"
        }
      },200,H);

    }catch(e){
      return json({
        error:"No se pudo crear el clan.",
        detail:e.message
      },500,H);
    }
  }


  if(r.method==="GET" && path==="/api/clans"){
    const p=new URL(r.url).searchParams;
    const q=String(p.get("q")||p.get("search")||"").trim();
    const league=Number(p.get("league")||0);

    let sql=`
      SELECT
        c.*,
        COALESCE(s.points,0) points,
        COALESCE(s.wins,0) wins,
        COALESCE(s.losses,0) losses,
        COALESCE(s.played,0) played,
        (SELECT COUNT(*) FROM members m WHERE m.clan_id=c.id) member_count
      FROM clans c
      LEFT JOIN scores s ON s.clan_id=c.id
      WHERE c.name LIKE ?
    `;

    const values=["%"+q+"%"];

    if([1,2,3,4].includes(league)){
      sql+=` AND c.league=?`;
      values.push(league);
    }

    sql+=` ORDER BY points DESC,wins DESC,c.name ASC LIMIT 200`;

    const result=await env.DB.prepare(sql).bind(...values).all();

    for(const c of result.results)
      c.status=await clanStatus(env,c);

    return json(result.results,200,H);
  }


  if(r.method==="GET" && /^\/api\/clans\/\d+$/.test(path)){
    const clanId=Number(path.split("/")[3]);

    const clan=await env.DB.prepare(`
      SELECT
        c.*,
        COALESCE(s.points,0) points,
        COALESCE(s.wins,0) wins,
        COALESCE(s.losses,0) losses,
        COALESCE(s.played,0) played
      FROM clans c
      LEFT JOIN scores s ON s.clan_id=c.id
      WHERE c.id=?
    `).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    clan.status=await clanStatus(env,clan);

    const members=await env.DB.prepare(`
      SELECT
        u.id,
        u.username,
        u.psn_id,
        u.avatar_url,
        m.role,
        m.joined_at
      FROM members m
      JOIN users u ON u.id=m.user_id
      WHERE m.clan_id=?
      ORDER BY
        CASE WHEN m.role='captain' THEN 0 ELSE 1 END,
        u.username
    `).bind(clanId).all();

    return json({
      clan,
      members:members.results
    },200,H);
  }


  /* ===================================================
     INVITACIONES
  =================================================== */

  if(r.method==="POST" && /^\/api\/clans\/\d+\/invite$/.test(path)){
    const clanId=Number(path.split("/")[3]);
    const d=await body(r);

    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    const meMember=await env.DB.prepare(`
      SELECT * FROM members
      WHERE clan_id=? AND user_id=?
    `).bind(clanId,me.id).first();

    if(!meMember||meMember.role!=="captain")
      return json({error:"Solo el capitán puede invitar."},403,H);

    const username=String(d.username||"").trim();

    const player=await env.DB.prepare(`
      SELECT * FROM users
      WHERE LOWER(username)=LOWER(?)
    `).bind(username).first();

    if(!player)
      return json({error:"Jugador no encontrado."},404,H);

    if(Number(player.id)===Number(me.id))
      return json({error:"No puedes invitarte a ti mismo."},400,H);

    if(await clanOf(env,player.id,Number(clan.league)))
      return json({
        error:"Ese jugador ya está en un clan de esta liga."
      },400,H);

    const pending=await env.DB.prepare(`
      SELECT id FROM invites
      WHERE clan_id=? AND invitee_id=? AND status='pending'
    `).bind(clanId,player.id).first();

    if(pending)
      return json({error:"Ya tiene una invitación pendiente."},400,H);

    const created=await env.DB.prepare(`
      INSERT INTO invites(clan_id,inviter_id,invitee_id,status)
      VALUES(?,?,?,'pending')
    `).bind(clanId,me.id,player.id).run();

    await notify(
      env,
      player.id,
      "⚔️ Invitación al clan",
      `${clan.name} te ha invitado a unirte.`,
      "clan_invite",
      "clan",
      clanId
    );

    return json({
      ok:true,
      id:created.meta.last_row_id
    },200,H);
  }


  if(r.method==="GET" && path==="/api/invites"){
    const result=await env.DB.prepare(`
      SELECT
        i.id,
        i.status,
        i.created_at,
        c.id clan_id,
        c.name clan_name,
        c.clan_code,
        c.logo_url,
        c.league,
        u.username inviter_username
      FROM invites i
      JOIN clans c ON c.id=i.clan_id
      JOIN users u ON u.id=i.inviter_id
      WHERE i.invitee_id=? AND i.status='pending'
      ORDER BY i.id DESC
    `).bind(me.id).all();

    return json(result.results,200,H);
  }



 const inv=path.match(/^\/api\/invites\/(\d+)\/(accept|reject)$/);

  if(r.method==="POST"&&inv){
    const inviteId=Number(inv[1]);
    const action=inv[2];

    const invite=await env.DB.prepare(`
      SELECT * FROM invites
      WHERE id=? AND invitee_id=? AND status='pending'
    `).bind(inviteId,me.id).first();

    if(!invite)
      return json({error:"Invitación no disponible."},404,H);

    if(action==="reject"){
      await env.DB.prepare(`UPDATE invites SET status='rejected' WHERE id=?`).bind(inviteId).run();
      return json({ok:true},200,H);
    }

    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(invite.clan_id).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    if(await clanOf(env,me.id,Number(clan.league)))
      return json({error:"Ya perteneces a un clan en esta liga."},400,H);

    await env.DB.prepare(`
      INSERT OR IGNORE INTO members(clan_id,user_id,role)
      VALUES(?,?,?)
    `).bind(clan.id,me.id,"member").run();

    await env.DB.prepare(`
      UPDATE invites SET status='accepted' WHERE id=?
    `).bind(inviteId).run();

    await notifyClan(
      env,
      clan.id,
      "👤 Nuevo jugador",
      `${me.username} se ha unido al clan.`,
      "clan_join",
      "clan",
      clan.id
    );

    return json({ok:true},200,H);
  }


  /* ===================================================
     NOTIFICACIONES
  =================================================== */

  if(r.method==="GET" && path==="/api/notifications"){
    const result=await env.DB.prepare(`
      SELECT *
      FROM notifications
      WHERE user_id=? AND is_read=0
      ORDER BY id DESC
      LIMIT 100
    `).bind(me.id).all();

    return json(result.results,200,H);
  }


  if(r.method==="POST" && /^\/api\/notifications\/\d+\/read$/.test(path)){
    const id=Number(path.split("/")[3]);

    await env.DB.prepare(`
      UPDATE notifications
      SET is_read=1
      WHERE id=? AND user_id=?
    `).bind(id,me.id).run();

    return json({ok:true},200,H);
  }


  if(r.method==="POST" && path==="/api/notifications/read-all"){
    await env.DB.prepare(`
      UPDATE notifications
      SET is_read=1
      WHERE user_id=?
    `).bind(me.id).run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     ABANDONAR CLAN
  =================================================== */

  if(r.method==="POST" && /^\/api\/clans\/\d+\/leave$/.test(path)){
    const clanId=Number(path.split("/")[3]);

    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    const member=await env.DB.prepare(`
      SELECT * FROM members
      WHERE clan_id=? AND user_id=?
    `).bind(clanId,me.id).first();

    if(!member)
      return json({error:"No perteneces a este clan."},400,H);

    if(Number(clan.captain_id)===Number(me.id))
      return json({
        error:"El capitán debe transferir la capitanía o borrar el clan."
      },400,H);

    await env.DB.prepare(`
      DELETE FROM members
      WHERE clan_id=? AND user_id=?
    `).bind(clanId,me.id).run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     TRANSFERIR CAPITÁN
  =================================================== */

  if(r.method==="POST" && /^\/api\/clans\/\d+\/transfer$/.test(path)){
    const clanId=Number(path.split("/")[3]);
    const d=await body(r);
    const newCaptainId=Number(d.user_id);

    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    if(Number(clan.captain_id)!==Number(me.id))
      return json({error:"Solo el capitán puede transferir el clan."},403,H);

    const target=await env.DB.prepare(`
      SELECT * FROM members
      WHERE clan_id=? AND user_id=?
    `).bind(clanId,newCaptainId).first();

    if(!target)
      return json({error:"Ese jugador no pertenece al clan."},400,H);

    await env.DB.batch([
      env.DB.prepare(`UPDATE members SET role='member' WHERE clan_id=?`).bind(clanId),
      env.DB.prepare(`UPDATE members SET role='captain' WHERE clan_id=? AND user_id=?`).bind(clanId,newCaptainId),
      env.DB.prepare(`UPDATE clans SET captain_id=? WHERE id=?`).bind(newCaptainId,clanId)
    ]);

    await notify(
      env,
      newCaptainId,
      "👑 Ahora eres capitán",
      `Has recibido la capitanía de ${clan.name}.`,
      "captain",
      "clan",
      clanId
    );

    return json({ok:true},200,H);
  }


  /* ===================================================
     EXPULSAR JUGADOR
  =================================================== */

  if(r.method==="POST" && /^\/api\/clans\/\d+\/kick$/.test(path)){
    const clanId=Number(path.split("/")[3]);
    const d=await body(r);
    const userId=Number(d.user_id);

    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    if(Number(clan.captain_id)!==Number(me.id))
      return json({error:"Solo el capitán puede expulsar jugadores."},403,H);

    if(userId===Number(me.id))
      return json({error:"No puedes expulsarte a ti mismo."},400,H);

    await env.DB.prepare(`
      DELETE FROM members
      WHERE clan_id=? AND user_id=?
    `).bind(clanId,userId).run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     CREAR RETO
  =================================================== */

  if(r.method==="POST" && path==="/api/challenges"){
    const d=await body(r);
    const league=Number(d.league||4);
    const teamSize=league;

    if(![1,2,3,4].includes(league))
      return json({error:"Liga no válida."},400,H);

    const clan=await clanOf(env,me.id,league);

    if(!clan)
      return json({error:`No tienes clan en ${leagueName(league)}.`},400,H);

    if(Number(clan.captain_id)!==Number(me.id)&&!isAdmin(me))
      return json({error:"Solo el capitán puede publicar retos."},403,H);

    const count=await memberCount(env,clan.id);

    if(count<teamSize)
      return json({
        error:`Necesitas al menos ${teamSize} jugador${teamSize>1?"es":""} para publicar este reto.`
      },400,H);

    const active=await env.DB.prepare(`
      SELECT id FROM challenges
      WHERE creator_clan_id=? AND status IN('open','accepted','pending_result')
      LIMIT 1
    `).bind(clan.id).first();

    if(active)
      return json({error:"Tu clan ya tiene un reto activo."},400,H);

    const expires=new Date(Date.now()+30*60*1000).toISOString();

    if(league===1){
      const mode=String(d.mode||d.one_vs_one_mode||"").toLowerCase();

      if(!["franco","sniper","arma","weapon"].includes(mode))
        return json({error:"Elige Solo Franco o Solo Arma."},400,H);

      await env.DB.prepare(`
        INSERT INTO challenges
        (creator_clan_id,status,map1,map2,map3,team_size,game_modes,one_vs_one_mode,expires_at)
        VALUES(?,'open','Nuketown','Nuketown','Nuketown',1,?,?,?)
      `)
        .bind(
          clan.id,
          JSON.stringify([mode]),
          mode,
          expires
        ).run();

    }else{
      const m=maps();

      await env.DB.prepare(`
        INSERT INTO challenges
        (creator_clan_id,status,map1,map2,map3,team_size,game_modes,expires_at)
        VALUES(?,'open',?,?,?,?,?,?)
      `)
        .bind(
          clan.id,
          m[0],
          m[1],
          m[2],
          teamSize,
          JSON.stringify([String(d.mode||"snd")]),
          expires
        ).run();
    }

    return json({ok:true},200,H);
  }


  /* ===================================================
     FIN PARTE 2
  ===================================================

    /* ===================================================
     LISTAR RETOS
  =================================================== */

  if(r.method==="GET" && path==="/api/challenges"){
    const p=new URL(r.url).searchParams;
    const league=Number(p.get("league")||4);

    if(![1,2,3,4].includes(league))
      return json([],200,H);

    const result=await env.DB.prepare(`
      SELECT
        ch.*,
        c1.name creator_clan_name,
        c1.clan_code creator_clan_code,
        c1.logo_url creator_logo,
        c2.name accepter_clan_name,
        c2.clan_code accepter_clan_code,
        c2.logo_url accepter_logo
      FROM challenges ch
      JOIN clans c1 ON c1.id=ch.creator_clan_id
      LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
      WHERE c1.league=?
      AND ch.status IN('open','accepted','pending_result')
      ORDER BY ch.id DESC
      LIMIT 100
    `).bind(league).all();

    return json(
      result.results.map(x=>({
        ...x,
        league,
        team_size:Number(x.team_size||league),
        maps:league===1
          ? ["Nuketown"]
          : [x.map1,x.map2,x.map3],
        mode:x.one_vs_one_mode||"snd"
      })),
      200,
      H
    );
  }


  /* ===================================================
     MIS RETOS
  =================================================== */

  if(r.method==="GET" && path==="/api/my-challenges"){
    const result=await env.DB.prepare(`
      SELECT
        ch.*,
        c1.name creator_clan_name,
        c1.clan_code creator_clan_code,
        c2.name accepter_clan_name,
        c2.clan_code accepter_clan_code
      FROM challenges ch
      JOIN clans c1 ON c1.id=ch.creator_clan_id
      LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
      WHERE
        ch.creator_clan_id IN(
          SELECT clan_id FROM members WHERE user_id=?
        )
        OR
        ch.accepter_clan_id IN(
          SELECT clan_id FROM members WHERE user_id=?
        )
      ORDER BY ch.id DESC
      LIMIT 200
    `).bind(me.id,me.id).all();

    return json(result.results,200,H);
  }


  /* ===================================================
     VER RETO
     SOLO LOS DOS CLANES O ADMIN
  =================================================== */

  if(r.method==="GET" && /^\/api\/challenges\/\d+$/.test(path)){
    const id=Number(path.split("/")[3]);

    const ch=await env.DB.prepare(`
      SELECT
        ch.*,
        c1.name creator_clan_name,
        c1.clan_code creator_clan_code,
        c1.logo_url creator_logo,
        c1.league,
        c2.name accepter_clan_name,
        c2.clan_code accepter_clan_code,
        c2.logo_url accepter_logo
      FROM challenges ch
      JOIN clans c1 ON c1.id=ch.creator_clan_id
      LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
      WHERE ch.id=?
    `).bind(id).first();

    if(!ch)
      return json({error:"Reto no encontrado."},404,H);

    const mine=await env.DB.prepare(`
      SELECT 1
      FROM members
      WHERE user_id=?
      AND clan_id IN(?,?)
      LIMIT 1
    `).bind(
      me.id,
      ch.creator_clan_id,
      ch.accepter_clan_id||0
    ).first();

    if(!mine&&!isAdmin(me))
      return json({
        error:"No puedes ver este enfrentamiento."
      },403,H);

    const reports=await env.DB.prepare(`
      SELECT
        r.*,
        c.name clan_name,
        u.username
      FROM reports r
      JOIN clans c ON c.id=r.clan_id
      LEFT JOIN users u ON u.id=(
        SELECT user_id
        FROM members
        WHERE clan_id=r.clan_id
        AND role='captain'
        LIMIT 1
      )
      WHERE r.challenge_id=?
      ORDER BY r.id
    `).bind(id).all();

    const messages=await env.DB.prepare(`
      SELECT
        cm.*,
        u.username,
        u.avatar_url
      FROM chat_messages cm
      JOIN users u ON u.id=cm.user_id
      WHERE cm.challenge_id=?
      ORDER BY cm.id
      LIMIT 200
    `).bind(id).all();

    return json({
      ...ch,
      reports:reports.results,
      messages:messages.results,
      maps:Number(ch.team_size)===1
        ? ["Nuketown"]
        : [ch.map1,ch.map2,ch.map3]
    },200,H);
  }


  /* ===================================================
     ACEPTAR RETO
  =================================================== */

  if(r.method==="POST" && /^\/api\/challenges\/\d+\/accept$/.test(path)){
    const id=Number(path.split("/")[3]);

    const ch=await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
      AND status='open'
    `).bind(id).first();

    if(!ch)
      return json({
        error:"Este reto ya no está disponible."
      },404,H);

    const league=Number(ch.team_size||4);
    const clan=await clanOf(env,me.id,league);

    if(!clan)
      return json({
        error:`No tienes clan en ${leagueName(league)}.`
      },400,H);

    if(Number(clan.id)===Number(ch.creator_clan_id))
      return json({
        error:"No puedes aceptar tu propio reto."
      },400,H);

    if(Number(clan.captain_id)!==Number(me.id)&&!isAdmin(me))
      return json({
        error:"Solo el capitán puede aceptar retos."
      },403,H);
 const count=await memberCount(env,clan.id);

    if(count<league)
      return json({
        error:`Necesitas al menos ${league} jugadores.`
      },400,H);

    const ownActive=await env.DB.prepare(`
      SELECT id
      FROM challenges
      WHERE
        (creator_clan_id=? OR accepter_clan_id=?)
      AND status IN('accepted','pending_result')
      LIMIT 1
    `).bind(clan.id,clan.id).first();

    if(ownActive)
      return json({
        error:"Tu clan ya está disputando otro reto."
      },400,H);

    await env.DB.prepare(`
      UPDATE challenges
      SET accepter_clan_id=?,
          status='accepted'
      WHERE id=? AND status='open'
    `).bind(clan.id,id).run();

    await notifyClan(
      env,
      ch.creator_clan_id,
      "⚔️ Reto aceptado",
      `${clan.name} ha aceptado vuestro reto.`,
      "challenge",
      "challenge",
      id
    );

    await notifyClan(
      env,
      clan.id,
      "⚔️ Enfrentamiento confirmado",
      `Has aceptado el reto contra el clan rival.`,
      "challenge",
      "challenge",
      id
    );

    return json({ok:true},200,H);
  }


  /* ===================================================
     PUBLICAR RESULTADO
     CADA CAPITÁN PUEDE VOTAR UNA VEZ
  =================================================== */

  if(r.method==="POST" && /^\/api\/challenges\/\d+\/report$/.test(path)){
    const id=Number(path.split("/")[3]);
    const d=await body(r);

    const result=String(d.result||"").toLowerCase();

    if(!["win","loss"].includes(result))
      return json({
        error:"Debes indicar victoria o derrota."
      },400,H);

    const ch=await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
      AND status IN('accepted','pending_result')
    `).bind(id).first();

    if(!ch)
      return json({
        error:"Este reto no permite publicar resultados."
      },400,H);

    const league=Number(ch.team_size||4);
    const clan=await clanOf(env,me.id,league);

    if(!clan)
      return json({
        error:"No perteneces a la liga del reto."
      },403,H);

    const creator=Number(clan.id)===Number(ch.creator_clan_id);
    const accepter=Number(clan.id)===Number(ch.accepter_clan_id);

    if(!creator&&!accepter)
      return json({
        error:"Tu clan no participa en este reto."
      },403,H);

    if(Number(clan.captain_id)!==Number(me.id)&&!isAdmin(me))
      return json({
        error:"Solo el capitán puede publicar el resultado."
      },403,H);

    const exists=await env.DB.prepare(`
      SELECT id
      FROM reports
      WHERE challenge_id=?
      AND clan_id=?
    `).bind(id,clan.id).first();

    if(exists)
      return json({
        error:"Tu clan ya ha publicado su resultado."
      },400,H);

    const winner=
      result==="win"
        ? Number(clan.id)
        : creator
          ? Number(ch.accepter_clan_id)
          : Number(ch.creator_clan_id);

    await env.DB.prepare(`
      INSERT INTO reports
      (challenge_id,clan_id,winner_clan_id)
      VALUES(?,?,?)
    `).bind(id,clan.id,winner).run();

    const all=await env.DB.prepare(`
      SELECT *
      FROM reports
      WHERE challenge_id=?
    `).bind(id).all();

    if(all.results.length<2){

      await env.DB.prepare(`
        UPDATE challenges
        SET status='pending_result'
        WHERE id=?
      `).bind(id).run();

      const other=
        creator
          ? Number(ch.accepter_clan_id)
          : Number(ch.creator_clan_id);

      await notifyClan(
        env,
        other,
        "🏆 Resultado pendiente",
        `${clan.name} ha publicado su resultado. Entra en el reto para confirmar.`,
        "challenge_result",
        "challenge",
        id
      );

      return json({
        ok:true,
        completed:false,
        message:"Resultado publicado. Falta el otro capitán."
      },200,H);
    }

    const a=Number(all.results[0].winner_clan_id);
    const b=Number(all.results[1].winner_clan_id);

    if(a!==b){

      await env.DB.prepare(`
        DELETE FROM reports
        WHERE challenge_id=?
      `).bind(id).run();

      await env.DB.prepare(`
        UPDATE challenges
        SET status='accepted'
        WHERE id=?
      `).bind(id).run();

      await notifyClan(
        env,
        ch.creator_clan_id,
        "⚠️ Resultado no coincidente",
        "Los resultados de los capitanes no coinciden.",
        "challenge_conflict",
        "challenge",
        id
      );

      await notifyClan(
        env,
        ch.accepter_clan_id,
        "⚠️ Resultado no coincidente",
        "Los resultados de los capitanes no coinciden.",
        "challenge_conflict",
        "challenge",
        id
      );

      return json({
        error:"Los resultados no coinciden.",
        conflict:true
      },409,H);
    }

    const winnerId=a;
    const loserId=
      winnerId===Number(ch.creator_clan_id)
        ? Number(ch.accepter_clan_id)
        : Number(ch.creator_clan_id);

    await env.DB.prepare(`
      UPDATE challenges
      SET
        status='completed',
        winner_clan_id=?,
        completed_at=?
      WHERE id=?
    `).bind(
      winnerId,
      new Date().toISOString(),
      id
    ).run();

    await rebuildScores(env);

    await notifyClan(
      env,
      winnerId,
      "🏆 Victoria confirmada",
      "El resultado ha sido confirmado por ambos capitanes.",
      "challenge_complete",
      "challenge",
      id
    );

    await notifyClan(
      env,
      loserId,
      "Resultado confirmado",
      "El resultado ha sido confirmado por ambos capitanes.",
      "challenge_complete",
      "challenge",
      id
    );

    return json({
      ok:true,
      completed:true,
      winner_clan_id:winnerId
    },200,H);
  }


  /* ===================================================
     CHAT DEL RETO
  =================================================== */

  if(r.method==="GET" && /^\/api\/challenges\/\d+\/chat$/.test(path)){
    const id=Number(path.split("/")[3]);

    const ch=await env.DB.prepare(`
      SELECT creator_clan_id,accepter_clan_id
      FROM challenges
      WHERE id=?
    `).bind(id).first();

    if(!ch)
      return json({error:"Reto no encontrado."},404,H);

    const access=await env.DB.prepare(`
      SELECT 1
      FROM members
      WHERE user_id=?
      AND clan_id IN(?,?)
    `).bind(
      me.id,
      ch.creator_clan_id,
      ch.accepter_clan_id||0
    ).first();

    if(!access&&!isAdmin(me))
      return json({error:"Sin acceso."},403,H);

    const result=await env.DB.prepare(`
      SELECT
        cm.*,
        u.username,
        u.avatar_url
      FROM chat_messages cm
      JOIN users u ON u.id=cm.user_id
      WHERE cm.challenge_id=?
      ORDER BY cm.id
      LIMIT 200
    `).bind(id).all();

    return json(result.results,200,H);
  }


  if(r.method==="POST" && /^\/api\/challenges\/\d+\/chat$/.test(path)){
    const id=Number(path.split("/")[3]);
    const d=await body(r);
    const message=String(d.message||"").trim().slice(0,500);

    if(!message)
      return json({error:"Mensaje vacío."},400,H);

    const ch=await env.DB.prepare(`
      SELECT creator_clan_id,accepter_clan_id
      FROM challenges
      WHERE id=?
    `).bind(id).first();

    if(!ch)
      return json({error:"Reto no encontrado."},404,H);

    const access=await env.DB.prepare(`
      SELECT 1
      FROM members
      WHERE user_id=?
      AND clan_id IN(?,?)
    `).bind(
      me.id,
      ch.creator_clan_id,
      ch.accepter_clan_id||0
    ).first();

    if(!access&&!isAdmin(me))
      return json({error:"Sin acceso."},403,H);

    await env.DB.prepare(`
      INSERT INTO chat_messages
      (challenge_id,user_id,message)
      VALUES(?,?,?)
    `).bind(id,me.id,message).run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     CHAT COMUNIDAD
  =================================================== */

  if(r.method==="GET" && path==="/api/community"){
    const p=new URL(r.url).searchParams;
    const league=Number(p.get("league")||0);

    const result=await env.DB.prepare(`
      SELECT
        cm.*,
        u.username,
        u.avatar_url
      FROM community_messages cm
      JOIN users u ON u.id=cm.user_id
      WHERE (?=0 OR cm.league=?)
      ORDER BY cm.id DESC
      LIMIT 200
    `).bind(league,league).all();

    return json(result.results.reverse(),200,H);
  }


  if(r.method==="POST" && path==="/api/community"){
    const d=await body(r);
    const league=Number(d.league||0);
    const message=String(d.message||"").trim().slice(0,500);

    if(!message)
      return json({error:"Mensaje vacío."},400,H);

    if(league!==0&&!([1,2,3,4].includes(league)))
      return json({error:"Liga no válida."},400,H);

    const last=await env.DB.prepare(`
      SELECT created_at
      FROM community_messages
      WHERE user_id=?
      ORDER BY id DESC
      LIMIT 1
    `).bind(me.id).first();

    if(last){
      const diff=Date.now()-new Date(last.created_at).getTime();
      if(diff<5000)
        return json({
          error:"Espera unos segundos antes de enviar otro mensaje."
        },429,H);
    }

    await env.DB.prepare(`
      INSERT INTO community_messages
      (user_id,league,message)
      VALUES(?,?,?)
    `).bind(me.id,league,message).run();

    return json({ok:true},200,H);
  }


  if(r.method==="DELETE" && /^\/api\/community\/\d+$/.test(path)){
    const id=Number(path.split("/")[3]);

    const msg=await env.DB.prepare(`
      SELECT *
      FROM community_messages
      WHERE id=?
    `).bind(id).first();

    if(!msg)
      return json({error:"Mensaje no encontrado."},404,H);

    if(Number(msg.user_id)!==Number(me.id)&&!isAdmin(me))
      return json({error:"No puedes borrar este mensaje."},403,H);

    await env.DB.prepare(`
      DELETE FROM community_messages
      WHERE id=?
    `).bind(id).run();

    return json({ok:true},200,H);
  }


  /* ===================================================
     RANKING
  =================================================== */

  if(r.method==="GET" && path==="/api/leaderboard"){
    const league=Number(
      new URL(r.url).searchParams.get("league")||4
    );

    if(![1,2,3,4].includes(league))
      return json([],200,H);

    const result=await env.DB.prepare(`
      SELECT
        c.id,
        c.name,
        c.clan_code,
        c.logo_url,
        c.league,
        COALESCE(s.points,0) points,
        COALESCE(s.wins,0) wins,
        COALESCE(s.losses,0) losses,
        COALESCE(s.played,0) played
      FROM clans c
      LEFT JOIN scores s ON s.clan_id=c.id
      WHERE c.league=?
      ORDER BY points DESC,wins DESC,played ASC,c.name ASC
    `).bind(league).all();

    return json(result.results,200,H);
  }


  /* ===================================================
     HISTORIAL
  =================================================== */

  if(r.method==="GET" && path==="/api/history"){
    const league=Number(
      new URL(r.url).searchParams.get("league")||0
    );

    let sql=`
      SELECT
        ch.*,
        c1.name creator_clan_name,
        c2.name accepter_clan_name,
        cw.name winner_clan_name
      FROM challenges ch
      JOIN clans c1 ON c1.id=ch.creator_clan_id
      LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
      LEFT JOIN clans cw ON cw.id=ch.winner_clan_id
      WHERE ch.status='completed'
    `;

  const values=[];

    if([1,2,3,4].includes(league)){
      sql+=` AND c1.league=?`;
      values.push(league);
    }

    sql+=` ORDER BY ch.completed_at DESC LIMIT 200`;

    const result=await env.DB.prepare(sql).bind(...values).all();

    return json(result.results,200,H);
  }


  /* ===================================================
     BORRAR CLAN — CAPITÁN
  =================================================== */

  if(r.method==="DELETE" && /^\/api\/clans\/\d+$/.test(path)){
    const clanId=Number(path.split("/")[3]);

    const clan=await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `).bind(clanId).first();

    if(!clan)
      return json({error:"Clan no encontrado."},404,H);

    if(Number(clan.captain_id)!==Number(me.id)&&!isAdmin(me))
      return json({
        error:"Solo el capitán puede borrar el clan."
      },403,H);

    const active=await env.DB.prepare(`
      SELECT id
      FROM challenges
      WHERE
        (creator_clan_id=? OR accepter_clan_id=?)
      AND status IN('accepted','pending_result')
      LIMIT 1
    `).bind(clanId,clanId).first();

    if(active)
      return json({
        error:"No puedes borrar el clan mientras tiene un enfrentamiento activo."
      },400,H);

    await deleteClan(env,clanId);

    return json({ok:true},200,H);
  }


  /* ===================================================
     ADMIN
  =================================================== */

    /* ===================================================
   ADMIN — RESUMEN
=================================================== */

if(r.method==="GET" && path==="/api/admin"){
  if(!isAdmin(me)){
    return json({error:"Acceso de administrador requerido."},403,H);
  }

  const users = await env.DB.prepare(`
    SELECT id,username,psn_id,avatar_url,is_blocked,blocked_until,created_at
    FROM users ORDER BY id DESC LIMIT 500
  `).all();

  const clans = await env.DB.prepare(`
    SELECT c.*,u.username captain_username,
      (SELECT COUNT(*) FROM members m WHERE m.clan_id=c.id) member_count
    FROM clans c LEFT JOIN users u ON u.id=c.captain_id
    ORDER BY c.league,c.name
  `).all();

  const challenges = await env.DB.prepare(`
    SELECT ch.*,c1.name creator_clan_name,c2.name accepter_clan_name,cw.name winner_clan_name
    FROM challenges ch JOIN clans c1 ON c1.id=ch.creator_clan_id
    LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
    LEFT JOIN clans cw ON cw.id=ch.winner_clan_id
    ORDER BY ch.id DESC LIMIT 500
  `).all();

  return json({users:users.results,clans:clans.results,challenges:challenges.results},200,H);
}

  if(path.startsWith("/api/admin/")){
    if(!isAdmin(me))
      return json({
        error:"Acceso de administrador requerido."
      },403,H);


    /* USUARIOS */

    if(r.method==="GET"&&path==="/api/admin/users"){
      const result=await env.DB.prepare(`
        SELECT
          id,username,psn_id,avatar_url,
          is_blocked,blocked_until,created_at
        FROM users
        ORDER BY id DESC
        LIMIT 500
      `).all();

      return json(result.results,200,H);
    }


    /* CLANES */

    if(r.method==="GET"&&path==="/api/admin/clans"){
      const result=await env.DB.prepare(`
        SELECT
          c.*,
          u.username captain_username,
          (SELECT COUNT(*) FROM members m WHERE m.clan_id=c.id) member_count
        FROM clans c
        LEFT JOIN users u ON u.id=c.captain_id
        ORDER BY c.league,c.name
      `).all();

      return json(result.results,200,H);
    }


    /* RETOS */

    if(r.method==="GET"&&path==="/api/admin/challenges"){
      const result=await env.DB.prepare(`
        SELECT
          ch.*,
          c1.name creator_clan_name,
          c2.name accepter_clan_name,
          cw.name winner_clan_name
        FROM challenges ch
        JOIN clans c1 ON c1.id=ch.creator_clan_id
        LEFT JOIN clans c2 ON c2.id=ch.accepter_clan_id
        LEFT JOIN clans cw ON cw.id=ch.winner_clan_id
        ORDER BY ch.id DESC
        LIMIT 500
      `).all();

      return json(result.results,200,H);
    }


    /* BLOQUEAR */

    if(r.method==="POST"&&/^\/api\/admin\/users\/\d+\/block$/.test(path)){
      const id=Number(path.split("/")[4]);

      if(id===Number(me.id))
        return json({
          error:"No puedes bloquearte a ti mismo."
        },400,H);

      await env.DB.prepare(`
        UPDATE users
        SET is_blocked=1,blocked_until=NULL
        WHERE id=?
      `).bind(id).run();

      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id=?
      `).bind(id).run();

      return json({ok:true},200,H);
    }


    /* DESBLOQUEAR */

    if(r.method==="POST"&&/^\/api\/admin\/users\/\d+\/unblock$/.test(path)){
      const id=Number(path.split("/")[4]);

      await env.DB.prepare(`
        UPDATE users
        SET is_blocked=0,blocked_until=NULL
        WHERE id=?
      `).bind(id).run();

      return json({ok:true},200,H);
    }


    /* BORRAR CLAN */

    if(r.method==="DELETE"&&/^\/api\/admin\/clans\/\d+$/.test(path)){
      const id=Number(path.split("/").pop());

      await deleteClan(env,id);

      await rebuildScores(env);

      return json({ok:true},200,H);
    }


    /* BORRAR RETO */

    if(r.method==="DELETE"&&/^\/api\/admin\/challenges\/\d+$/.test(path)){
      const id=Number(path.split("/").pop());

      await deleteChallenge(env,id);

      await rebuildScores(env);

      return json({ok:true},200,H);
    }


    /* =================================================
       ADMINISTRAR RESULTADO
       
       El admin puede:
       - cambiar ganador
       - deshacer resultado
       - poner motivo
       ================================================= */

    if(r.method==="POST"&&/^\/api\/admin\/challenges\/\d+\/result$/.test(path)){
      const id=Number(path.split("/")[4]);
      const d=await body(r);

      const action=String(d.action||"").toLowerCase();
      const reason=String(d.reason||"").trim().slice(0,500);

      const ch=await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE id=?
      `).bind(id).first();

      if(!ch)
        return json({
          error:"Reto no encontrado."
        },404,H);


      /* DESHACER */

      if(action==="undo"){

        const oldWinner=ch.winner_clan_id;

        await env.DB.prepare(`
          UPDATE challenges
          SET
            status='accepted',
            winner_clan_id=NULL,
            completed_at=NULL,
            admin_result_modified=1,
            admin_result_reason=?
          WHERE id=?
        `).bind(reason||"Resultado deshecho por administración.",id).run();

        await env.DB.prepare(`
          DELETE FROM reports
          WHERE challenge_id=?
        `).bind(id).run();

        await env.DB.prepare(`
          INSERT INTO admin_result_audit
          (challenge_id,admin_user_id,action,old_winner_clan_id,new_winner_clan_id,reason)
          VALUES(?,?,?,?,?,?)
        `).bind(
          id,
          me.id,
          "undo",
          oldWinner,
          null,
          reason||"Resultado deshecho por administración."
        ).run();

        await rebuildScores(env);

        if(ch.creator_clan_id)
          await notifyClan(
            env,
            ch.creator_clan_id,
            "⚠️ Resultado modificado",
            "Administración ha deshecho el resultado de vuestro reto.",
            "admin_result",
            "challenge",
            id
          );

        if(ch.accepter_clan_id)
          await notifyClan(
            env,
            ch.accepter_clan_id,
            "⚠️ Resultado modificado",
            "Administración ha deshecho el resultado de vuestro reto.",
            "admin_result",
            "challenge",
            id
          );

        return json({
          ok:true,
          action:"undo"
        },200,H);
      }


      /* CAMBIAR GANADOR */

      if(action==="set_winner"){
        const winnerId=Number(d.winner_clan_id);

        if(
          winnerId!==Number(ch.creator_clan_id) &&
          winnerId!==Number(ch.accepter_clan_id)
        )
          return json({
            error:"El ganador debe ser uno de los dos clanes."
          },400,H);

        const oldWinner=ch.winner_clan_id;

        await env.DB.prepare(`
          UPDATE challenges
          SET
            status='completed',
            winner_clan_id=?,
            completed_at=?,
            admin_result_modified=1,
            admin_result_reason=?
          WHERE id=?
        `).bind(
          winnerId,
          new Date().toISOString(),
          reason||"Resultado modificado por administración.",
          id
        ).run();

        await env.DB.prepare(`
          DELETE FROM reports
          WHERE challenge_id=?
        `).bind(id).run();

        await env.DB.prepare(`
          INSERT INTO admin_result_audit
          (challenge_id,admin_user_id,action,old_winner_clan_id,new_winner_clan_id,reason)
          VALUES(?,?,?,?,?,?)
        `).bind(
          id,
          me.id,
          "set_winner",
          oldWinner,
          winnerId,
          reason||"Resultado modificado por administración."
        ).run();

        await rebuildScores(env);

        await notifyClan(
          env,
          ch.creator_clan_id,
          "👑 Resultado modificado por administración",
          `Administración ha establecido como ganador a un clan. Motivo: ${reason||"No indicado"}`,
          "admin_result",
          "challenge",
          id
        );

        if(ch.accepter_clan_id)
          await notifyClan(
            env,
            ch.accepter_clan_id,
            "👑 Resultado modificado por administración",
            `Administración ha establecido como ganador a un clan. Motivo: ${reason||"No indicado"}`,
            "admin_result",
            "challenge",
            id
          );

        return json({
          ok:true,
          action:"set_winner",
          winner_clan_id:winnerId
        },200,H);
      }


      return json({
        error:"Acción de resultado no válida."
      },400,H);
    }


    /* HISTORIAL DE CAMBIOS ADMIN */

    if(r.method==="GET"&&/^\/api\/admin\/challenges\/\d+\/audit$/.test(path)){
      const id=Number(path.split("/")[4]);

      const result=await env.DB.prepare(`
        SELECT
          a.*,
          u.username admin_username
        FROM admin_result_audit a
        JOIN users u ON u.id=a.admin_user_id
        WHERE a.challenge_id=?
        ORDER BY a.id DESC
      `).bind(id).all();

      return json(result.results,200,H);
    }


    /* RECONSTRUIR RANKINGS */

    if(r.method==="POST"&&path==="/api/admin/rebuild-scores"){
      await rebuildScores(env);

      return json({
        ok:true,
        message:"Clasificaciones reconstruidas."
      },200,H);
    }


    return json({
      error:"Ruta de administración no encontrada."
    },404,H);
  }


  /* ===================================================
     RUTA NO ENCONTRADA
  =================================================== */

  return json({
    error:"Ruta no encontrada.",
    path,
    method:r.method
  },404,H);
}


/* =====================================================
   WORKER
===================================================== */

export default {
  async fetch(request,env){

    const url=new URL(request.url);

    try{

      return await api(
        request,
        env,
        url.pathname
      );

    }catch(e){

      console.error(
        "WORKER ERROR",
        e
      );

      return json({
        error:"Error interno del servidor.",
        detail:e.message
      },500,cors(request));

    }
  }
};


  
