var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var COOKIE = "bol_session";
var SESSION_DAYS = 7;
var MAPS = [
"Raid",
"Standoff",
"Slums",
"Yemen",
"Meltdown",
"Express"
];
var json = /* @PURE / __name((data, status = 200, headers = {}) => new Response(
JSON.stringify(data),
{
status,
headers: {
"content-type": "application/json;charset=UTF-8",
...headers
}
}
), "json");
var body = / @PURE / __name(async (request) => {
try {
return await request.json();
} catch {
return {};
}
}, "body");
function cors(request) {
const origin = request.headers.get("Origin");
return {
"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
"Access-Control-Allow-Headers": "Content-Type",
"Access-Control-Allow-Credentials": "true",
...origin ? {
"Access-Control-Allow-Origin": origin,
"Vary": "Origin"
} : {}
};
}
__name(cors, "cors");
function sessionCookie(token) {
return ${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; SameSite=Lax; Secure;
}
__name(sessionCookie, "sessionCookie");
function deleteSessionCookie() {
return ${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure;
}
__name(deleteSessionCookie, "deleteSessionCookie");
function getCookie(request) {
const cookies = request.headers.get("Cookie") || "";
const match = cookies.match(
new RegExp(
"(^|;\s)" + COOKIE + "=([^;]+)"
)
);
return match ? decodeURIComponent(match[2]) : null;
}
__name(getCookie, "getCookie");
async function hashPassword(password, salt = crypto.randomUUID()) {
const key = await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(password),
"PBKDF2",
false,
["deriveBits"]
);
const bits = await crypto.subtle.deriveBits(
{
name: "PBKDF2",
salt: new TextEncoder().encode(salt),
iterations: 1e5,
hash: "SHA-256"
},
key,
256
);
const encoded = btoa(
String.fromCharCode(
...new Uint8Array(bits)
)
).replaceAll("=", "");
return ${salt}.${encoded};
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, stored) {
if (!stored || !stored.includes(".")) {
return false;
}
const [
salt,
hash
] = stored.split(".");
const generated = await hashPassword(
password,
salt
);
return generated === ${salt}.${hash};
}
__name(verifyPassword, "verifyPassword");
async function ensureColumn(env, table, column, definition) {
const result = await env.DB.prepare(
PRAGMA table_info(${table})
).all();
const exists = result.results.some(
(item) => item.name === column
);
if (!exists) {
await env.DB.prepare(
ALTER TABLE ${table}
       ADD COLUMN ${column}
       ${definition}
).run();
}
}
__name(ensureColumn, "ensureColumn");
async function initDatabase(env) {
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires INTEGER NOT NULL
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS clans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      captain_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS members(
      clan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(clan_id,user_id)
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS invites(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clan_id INTEGER NOT NULL,
      inviter_id INTEGER NOT NULL,
      invitee_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS challenges(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      creator_clan_id INTEGER NOT NULL,
      accepter_clan_id INTEGER,
      status TEXT DEFAULT 'open',
      map1 TEXT NOT NULL,
      map2 TEXT NOT NULL,
      map3 TEXT NOT NULL,
      winner_clan_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      completed_at TEXT
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      clan_id INTEGER NOT NULL,
      winner_clan_id INTEGER NOT NULL,
      UNIQUE(
        challenge_id,
        clan_id
      )
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS scores(
      clan_id INTEGER PRIMARY KEY,
      points INTEGER DEFAULT 0,
      wins INTEGER DEFAULT 0,
      losses INTEGER DEFAULT 0,
      played INTEGER DEFAULT 0
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'general',
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
 ).run();
await env.DB.prepare(    CREATE TABLE IF NOT EXISTS chat_messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
 ).run();
const columns = [
[
"notifications",
"target_type",
"TEXT"
],
[
"notifications",
"target_id",
"INTEGER"
],
[
"users",
"psn_id",
"TEXT"
],
[
"users",
"psn_changed_at",
"INTEGER"
],
[
"users",
"avatar_url",
"TEXT"
],
[
"users",
"is_blocked",
"INTEGER DEFAULT 0"
],
[
"users",
"blocked_until",
"INTEGER"
],
[
"clans",
"league",
"INTEGER DEFAULT 4"
],
[
"clans",
"clan_code",
"TEXT"
],
[
"clans",
"logo_url",
"TEXT"
],
[
"members",
"role",
"TEXT DEFAULT 'member'"
],
[
"challenges",
"team_size",
"INTEGER DEFAULT 4"
],
[
"challenges",
"game_modes",
TEXT DEFAULT '["snd"]'
],
[
"challenges",
"one_vs_one_mode",
"TEXT"
],
[
"challenges",
"scheduled_at",
"TEXT"
],
[
"challenges",
"expires_at",
"TEXT"
],
[
"challenges",
"cancel_reason",
"TEXT"
],
[
"challenges",
"cancelled_at",
"TEXT"
],
[
"scores",
"league",
"INTEGER DEFAULT 4"
]
];
for (const [
table,
column,
definition
] of columns) {
try {
await ensureColumn(
env,
table,
column,
definition
);
} catch (error) {
console.log(
"MIGRATION",
table,
column,
error.message
);
}
}
try {
const oldClans = await env.DB.prepare(        SELECT id
        FROM clans
        WHERE clan_code IS NULL
        OR clan_code=''
     ).all();
for (const clan of oldClans.results) {
let n = Number(clan.id);
let code = "";
for (let i=0;i<4;i++) { code = String.fromCharCode(65 + (n % 26)) + code; n = Math.floor(n / 26); }
await env.DB.prepare(UPDATE clans SET clan_code=? WHERE id=?).bind(code, clan.id).run();
}
} catch (error) {
console.log(
"CLAN CODE MIGRATION",
error.message
);
}
}
__name(initDatabase, "initDatabase");
async function getCurrentUser(request, env) {
const token = getCookie(request);
if (!token) {
return null;
}
return await env.DB.prepare(    SELECT
      u.*
    FROM sessions s
    JOIN users u
      ON u.id=s.user_id
    WHERE
      s.token=?
      AND s.expires>?
 ).bind(
token,
Date.now()
).first();
}
__name(getCurrentUser, "getCurrentUser");
function isAdmin(user) {
return !!user && user.username.toLowerCase() === "admin";
}
__name(isAdmin, "isAdmin");
function normalizeLeague(value, fallback = 4) {
if (typeof value === "string") {
const s = value.trim().toLowerCase();
const m = s.match(/^(1|2|3|4)\sv\s4?$/);
if (m) return Number(m[1]);
if (/^[1-4]$/.test(s)) return Number(s);
const n = Number(s);
if ([1,2,3,4].includes(n)) return n;
}
const n = Number(value);
return [1,2,3,4].includes(n) ? n : fallback;
}
__name(normalizeLeague, "normalizeLeague");
async function getUserClan(env, userId, league = null) {
if (league) {
return await env.DB.prepare(      SELECT
        c.*
      FROM clans c
      JOIN members m
        ON m.clan_id=c.id
      WHERE
        m.user_id=?
        AND c.league=?
      LIMIT 1
   ).bind(
userId,
league
).first();
}
return await env.DB.prepare(    SELECT
      c.*
    FROM clans c
    JOIN members m
      ON m.clan_id=c.id
    WHERE
      m.user_id=?
    ORDER BY c.league
    LIMIT 1
 ).bind(userId).first();
}
__name(getUserClan, "getUserClan");
function randomMaps() {
return [
...MAPS
].sort(
() => Math.random() - 0.5
).slice(0, 3);
}
__name(randomMaps, "randomMaps");
async function expireChallenges(env) {
const now = (/* @PURE */ new Date()).toISOString();
await env.DB.prepare(`
UPDATE challenges

SET
  status='expired',
  cancel_reason=
    'No aceptado en 30 minutos',
  cancelled_at=?

WHERE
  status='open'
  AND expires_at IS NOT NULL
  AND expires_at<=?

).bind(
    now,
    now
  ).run();
}
__name(expireChallenges, "expireChallenges");
async function api(request, env, path) {
  const headers = cors(request);
  if (request.method === "OPTIONS") {
    return new Response(
      null,
      {
        status: 204,
        headers
      }
    );
  }
  await initDatabase(env);
  await expireChallenges(env);
  if (request.method === "GET" && path === "/api/me") {
    const user = await getCurrentUser(
      request,
      env
    );
    return json(
      {
        user,
        admin: isAdmin(user)
      },
      200,
      headers
    );
  }
  if (request.method === "POST" && path === "/api/register") {
    const data = await body(request);
    const username = String(
      data.username || ""
    ).trim();
    const password = String(
      data.password || ""
    );
    if (username.length < 3 || username.length > 20 || password.length < 6) {
      return json(
        {
          error: "Usuario 3-20 caracteres y contrase\xF1a m\xEDnimo 6."
        },
        400,
        headers
      );
    }
    const exists = await env.DB.prepare(
SELECT id
FROM users
WHERE username=?
).bind(username).first();
    if (exists) {
      return json(
        {
          error: "Ese usuario ya existe."
        },
        400,
        headers
      );
    }
    try {
        const passwordHash = await hashPassword(
        password
          );
      const created = await env.DB.prepare(
INSERT INTO users
(
username,
password_hash
)
VALUES (?,?)
).bind(
        username,
        passwordHash
      ).run();
      const userId = created.meta.last_row_id;
      const token = crypto.randomUUID();
      await env.DB.prepare(
INSERT INTO sessions
(
token,
user_id,
expires
)
VALUES (?,?,?)
).bind(
        token,
        userId,
        Date.now() + SESSION_DAYS * 864e5
      ).run();
      return json(
        {
          ok: true,
          user: {
            id: userId,
            username
          }
        },
        200,
        {
          ...headers,
          "Set-Cookie": sessionCookie(token)
        }
      );
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );
      return json(
        {
          error: "No se pudo crear la cuenta.",
          detail: error.message
        },
        500,
        headers
      );
    }
  }
  if (request.method === "POST" && path === "/api/login") {
    const data = await body(request);
    const username = String(
      data.username || ""
    ).trim();
    const password = String(
      data.password || ""
    );
    const user = await env.DB.prepare(
SELECT *
FROM users
WHERE username=?
).bind(username).first();
    if (!user || !await verifyPassword(
      password,
      user.password_hash
    )) {
      return json(
        {
          error: "Usuario o contrase\xF1a incorrectos."
        },
        401,
        headers
      );
    }
    if (user.is_blocked && (user.blocked_until === 0 || user.blocked_until > Date.now())) {
      return json(
        {
          error: "Usuario bloqueado."
        },
        403,
        headers
      );
    }
    const token = crypto.randomUUID();
    await env.DB.prepare(
INSERT INTO sessions
(
token,
user_id,
expires
)
VALUES (?,?,?)
).bind(
      token,
      user.id,
      Date.now() + SESSION_DAYS * 864e5
    ).run();
    return json(
      {
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          psn_id: user.psn_id
        }
      },
      200,
      {
        ...headers,
        "Set-Cookie": sessionCookie(token)
      }
    );
  }
  if (request.method === "POST" && path === "/api/logout") {
    const token = getCookie(request);
    if (token) {
      await env.DB.prepare(
DELETE FROM sessions
WHERE token=?
).bind(token).run();
    }
    return json(
      { ok: true },
      200,
      {
        ...headers,
        "Set-Cookie": deleteSessionCookie()
      }
    );
  }
  const me = await getCurrentUser(
    request,
    env
  );
  const publicRoute = request.method === "GET" && (path === "/api/leaderboard" || path === "/api/clans" || path === "/api/users" || /^\/api\/clans\/\d+$/.test(path) || /^\/api\/users\/\d+$/.test(path));
  if (!me && !publicRoute) {
    return json(
      {
        error: "Debes iniciar sesi\xF3n."
      },
      401,
      headers
    );
  }
  if (me && me.is_blocked && (me.blocked_until === 0 || me.blocked_until > Date.now())) {
    return json(
      {
        error: "Usuario bloqueado."
      },
      403,
      headers
    );
  }
  if (me.is_blocked && (me.blocked_until === 0 || me.blocked_until > Date.now())) {
    return json(
      {
        error: "Usuario bloqueado."
      },
      403,
      headers
    );
  }
  if (request.method === "PUT" && path === "/api/profile") {
    const data = await body(request);
    const psn = String(data.psn_id || "").trim().slice(0, 32);
    const avatar = String(data.avatar_url || "").trim().slice(0, 500);
    const changingPsn = psn !== String(me.psn_id || "");
    if (changingPsn && !isAdmin(me) && me.psn_changed_at && Date.now() - Number(me.psn_changed_at) < 24 * 60 * 60 * 1000) {
      const remaining = 24 * 60 * 60 * 1000 - (Date.now() - Number(me.psn_changed_at));
      return json({ error: "Solo puedes cambiar tu ID una vez cada 24 horas.", retry_after_ms: remaining }, 400, headers);
    }
    await env.DB.prepare(
UPDATE users
SET psn_id=?, avatar_url=?, psn_changed_at=?
WHERE id=?
).bind(psn, avatar, changingPsn && !isAdmin(me) ? Date.now() : (me.psn_changed_at || null), me.id).run();
    return json({ ok: true }, 200, headers);
  }
  if (request.method === "GET" && path === "/api/users") {
    const params = new URL(request.url).searchParams;
    const query = String(
      params.get("q") || ""
    ).trim();
    const result = await env.DB.prepare(
SELECT
id,
username,
psn_id,
avatar_url,
created_at
FROM users
WHERE username LIKE ?
ORDER BY username
LIMIT 50
).bind(
      "%" + query + "%"
    ).all();
    return json(
      result.results,
      200,
      headers
    );
  }
  if (request.method === "GET" && /^\/api\/users\/\d+$/.test(path)) {
    const id = Number(
      path.split("/").pop()
    );
    const user = await env.DB.prepare(
SELECT
id,
username,
psn_id,
avatar_url,
created_at
FROM users
WHERE id=?
).bind(id).first();
    if (!user) {
      return json(
        {
          error: "Jugador no encontrado."
        },
        404,
        headers
      );
    }
    const clans = await env.DB.prepare(
SELECT
c.id,
c.name,
c.clan_code,
c.league
FROM clans c
JOIN members m
ON m.clan_id=c.id
WHERE m.user_id=?
ORDER BY c.league
).bind(id).all();
    return json(
      {
        user,
        clans: clans.results
      },
      200,
      headers
    );
  }
  if (request.method === "GET" && path === "/api/my-clans") {
    const result = await env.DB.prepare(
SELECT
c.id,
c.name,
c.clan_code,
c.logo_url,
c.league,
c.captain_id,
m.role
FROM members m
JOIN clans c ON c.id=m.clan_id
WHERE m.user_id=?
ORDER BY c.league, c.id
).bind(me.id).all();
    return json({ clans: result.results }, 200, headers);
  }
  if (request.method === "GET" && path === "/api/clans") {
    const params = new URL(request.url).searchParams;
    const query = String(
      params.get("q") || ""
    );
    const league = Number(
      params.get("league") || 0
    );
    let sql = 
SELECT
c.id,
c.name,
c.clan_code,
c.logo_url,
c.league,
c.captain_id,

    COALESCE(
      s.points,
      0
    ) points,

    COALESCE(
      s.wins,
      0
    ) wins,

    COALESCE(
      s.losses,
      0
    ) losses,

    COALESCE(
      s.played,
      0
    ) played

  FROM clans c

  LEFT JOIN scores s
    ON s.clan_id=c.id

  WHERE c.name LIKE ?
`;
const values = [
  "%" + query + "%"
];
if ([1, 2, 3, 4].includes(
  league
)) {
  sql += " AND c.league=?";
  values.push(
    league
  );
}
sql += `
  ORDER BY
    points DESC,
    name
  LIMIT 100
`;
const result = await env.DB.prepare(sql).bind(...values).all();
return json(
  result.results,
  200,
  headers
);

}
if (request.method === "GET" && /^/api/clans/\d+$/.test(path)) {
const id = Number(
path.split("/").pop()
);
const clan = await env.DB.prepare(`
SELECT
c.*,

      COALESCE(
        s.points,
        0
      ) points,

      COALESCE(
        s.wins,
        0
      ) wins,

      COALESCE(
        s.losses,
        0
      ) losses,

      COALESCE(
        s.played,
        0
      ) played

    FROM clans c

    LEFT JOIN scores s
      ON s.clan_id=c.id

    WHERE c.id=?
  `).bind(id).first();
if (!clan) {
  return json(
    {
      error: "Clan no encontrado."
    },
    404,
    headers
  );
}
const members = await env.DB.prepare(`
    SELECT
      u.id,
      u.username,
      u.psn_id,
      m.role

    FROM members m

    JOIN users u
      ON u.id=m.user_id

    WHERE
      m.clan_id=?

    ORDER BY
      m.role DESC,
      u.username
  `).bind(id).all();
return json(
  {
    clan,
    members: members.results
  },
  200,
  headers
);

}
if (request.method === "POST" && path === "/api/clans") {
const data = await body(request);
const name = String(data.name || "").trim();
const clanCode = String(data.clan_code || "").trim().toUpperCase();
const logoUrl = String(data.logo_url || "").trim().slice(0, 500);
const league = normalizeLeague(data.league, 0);
if (name.length < 2 || name.length > 24 || !/^[A-Z]{4}$/.test(clanCode) || ![1, 2, 3, 4].includes(league)) {
return json({ error: "Nombre 2-24 caracteres, insignia de exactamente 4 letras y liga 1v1, 2v2, 3v3 o 4v4." }, 400, headers);
}
const existingMembership = await getUserClan(env, me.id, league);
if (existingMembership) return json({ error: "Ya perteneces a un clan en esta liga." }, 400, headers);
const existingClan = await env.DB.prepare(SELECT id FROM clans WHERE name=? AND league=?).bind(name, league).first();
if (existingClan) return json({ error: "Ese nombre ya existe en esa liga." }, 400, headers);
const existingCode = await env.DB.prepare(SELECT id FROM clans WHERE clan_code=?).bind(clanCode).first();
if (existingCode) return json({ error: "Esa insignia ya está utilizada." }, 400, headers);
try {
const created = await env.DB.prepare(INSERT INTO clans (name,captain_id,league,clan_code,logo_url) VALUES (?,?,?,?,?)).bind(name, me.id, league, clanCode, logoUrl).run();
const clanId = created.meta.last_row_id;
await env.DB.prepare(INSERT INTO members (clan_id,user_id,role) VALUES (?,?,?)).bind(clanId, me.id, "captain").run();
await env.DB.prepare(INSERT OR IGNORE INTO scores (clan_id,league) VALUES (?,?)).bind(clanId, league).run();
return json({
ok: true,
clanId,
clanCode,
clan: {
