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
var json = /* @__PURE__ */ __name((data, status = 200, headers = {}) => new Response(
  JSON.stringify(data),
  {
    status,
    headers: {
      "content-type": "application/json;charset=UTF-8",
      ...headers
    }
  }
), "json");
var body = /* @__PURE__ */ __name(async (request) => {
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
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; SameSite=Lax; Secure`;
}
__name(sessionCookie, "sessionCookie");
function deleteSessionCookie() {
  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;
}
__name(deleteSessionCookie, "deleteSessionCookie");
function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(
    new RegExp(
      "(^|;\\s*)" + COOKIE + "=([^;]+)"
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
  return `${salt}.${encoded}`;
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
  return generated === `${salt}.${hash}`;
}
__name(verifyPassword, "verifyPassword");
async function ensureColumn(env, table, column, definition) {
  const result = await env.DB.prepare(
    `PRAGMA table_info(${table})`
  ).all();
  const exists = result.results.some(
    (item) => item.name === column
  );
  if (!exists) {
    await env.DB.prepare(
      `ALTER TABLE ${table}
       ADD COLUMN ${column}
       ${definition}`
    ).run();
  }
}
__name(ensureColumn, "ensureColumn");
async function initDatabase(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires INTEGER NOT NULL
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS clans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      captain_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS members(
      clan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(clan_id,user_id)
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS invites(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clan_id INTEGER NOT NULL,
      inviter_id INTEGER NOT NULL,
      invitee_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS challenges(
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
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      clan_id INTEGER NOT NULL,
      winner_clan_id INTEGER NOT NULL,
      UNIQUE(
        challenge_id,
        clan_id
      )
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores(
      clan_id INTEGER PRIMARY KEY,
      points INTEGER DEFAULT 0,
      wins INTEGER DEFAULT 0,
      losses INTEGER DEFAULT 0,
      played INTEGER DEFAULT 0
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'general',
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS chat_messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
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
      `TEXT DEFAULT '["snd"]'`
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
    const oldClans = await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE clan_code IS NULL
        OR clan_code=''
      `).all();
    for (const clan of oldClans.results) {
      let n = Number(clan.id);
      let code = "";
      for (let i=0;i<4;i++) { code = String.fromCharCode(65 + (n % 26)) + code; n = Math.floor(n / 26); }
      await env.DB.prepare(`UPDATE clans SET clan_code=? WHERE id=?`).bind(code, clan.id).run();
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
  return await env.DB.prepare(`
    SELECT
      u.*
    FROM sessions s
    JOIN users u
      ON u.id=s.user_id
    WHERE
      s.token=?
      AND s.expires>?
  `).bind(
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
    const m = s.match(/^(1|2|3|4)\\s*v\\s*4?$/);
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
    return await env.DB.prepare(`
      SELECT
        c.*
      FROM clans c
      JOIN members m
        ON m.clan_id=c.id
      WHERE
        m.user_id=?
        AND c.league=?
      LIMIT 1
    `).bind(
      userId,
      league
    ).first();
  }
  return await env.DB.prepare(`
    SELECT
      c.*
    FROM clans c
    JOIN members m
      ON m.clan_id=c.id
    WHERE
      m.user_id=?
    ORDER BY c.league
    LIMIT 1
  `).bind(userId).first();
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
  const now = (/* @__PURE__ */ new Date()).toISOString();
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
  `).bind(
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
    const exists = await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE username=?
      `).bind(username).first();
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
      const created = await env.DB.prepare(`
          INSERT INTO users
          (
            username,
            password_hash
          )
          VALUES (?,?)
        `).bind(
        username,
        passwordHash
      ).run();
      const userId = created.meta.last_row_id;
      const token = crypto.randomUUID();
      await env.DB.prepare(`
        INSERT INTO sessions
        (
          token,
          user_id,
          expires
        )
        VALUES (?,?,?)
      `).bind(
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
    const user = await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE username=?
      `).bind(username).first();
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
    await env.DB.prepare(`
      INSERT INTO sessions
      (
        token,
        user_id,
        expires
      )
      VALUES (?,?,?)
    `).bind(
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
      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE token=?
      `).bind(token).run();
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
    await env.DB.prepare(`
      UPDATE users
      SET psn_id=?, avatar_url=?, psn_changed_at=?
      WHERE id=?
    `).bind(psn, avatar, changingPsn && !isAdmin(me) ? Date.now() : (me.psn_changed_at || null), me.id).run();
    return json({ ok: true }, 200, headers);
  }
  if (request.method === "GET" && path === "/api/users") {
    const params = new URL(request.url).searchParams;
    const query = String(
      params.get("q") || ""
    ).trim();
    const result = await env.DB.prepare(`
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
      `).bind(
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
    const user = await env.DB.prepare(`
        SELECT
          id,
          username,
          psn_id,
          avatar_url,
          created_at
        FROM users
        WHERE id=?
      `).bind(id).first();
    if (!user) {
      return json(
        {
          error: "Jugador no encontrado."
        },
        404,
        headers
      );
    }
    const clans = await env.DB.prepare(`
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
      `).bind(id).all();
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
    const result = await env.DB.prepare(`
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
    `).bind(me.id).all();
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
    let sql = `
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
  if (request.method === "GET" && /^\/api\/clans\/\d+$/.test(path)) {
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
    const existingClan = await env.DB.prepare(`SELECT id FROM clans WHERE name=? AND league=?`).bind(name, league).first();
    if (existingClan) return json({ error: "Ese nombre ya existe en esa liga." }, 400, headers);
    const existingCode = await env.DB.prepare(`SELECT id FROM clans WHERE clan_code=?`).bind(clanCode).first();
    if (existingCode) return json({ error: "Esa insignia ya está utilizada." }, 400, headers);
    try {
      const created = await env.DB.prepare(`INSERT INTO clans (name,captain_id,league,clan_code,logo_url) VALUES (?,?,?,?,?)`).bind(name, me.id, league, clanCode, logoUrl).run();
      const clanId = created.meta.last_row_id;
      await env.DB.prepare(`INSERT INTO members (clan_id,user_id,role) VALUES (?,?,?)`).bind(clanId, me.id, "captain").run();
      await env.DB.prepare(`INSERT OR IGNORE INTO scores (clan_id,league) VALUES (?,?)`).bind(clanId, league).run();
      return json({
        ok: true,
        clanId,
        clanCode,
        clan: {
          id: clanId,
          name,
          clan_code: clanCode,
          league,
          captain_id: me.id,
          role: "captain"
        }
      }, 200, headers);
    } catch (error) {
      console.error("CREATE CLAN ERROR:", error);
      return json({ error: "No se pudo crear el clan.", detail: error.message }, 500, headers);
    }
  }
  if (request.method === "GET" && path === "/api/leaderboard") {
    const league = normalizeLeague(
      new URL(request.url).searchParams.get("league") || 4,
      4
    );
    if (![1, 2, 3, 4].includes(
      league
    )) {
      return json(
        {
          error: "Liga no v\xE1lida."
        },
        400,
        headers
      );
    }
    const result = await env.DB.prepare(`
        SELECT
          c.id,
          c.name,
          c.clan_code,
          c.logo_url,
          c.league,

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

        WHERE c.league=?

        ORDER BY
          points DESC,
        wins DESC,
          name
      `).bind(league).all();
    return json(
      result.results,
      200,
           headers
    );
  }
  if (request.method === "GET" && path === "/api/notifications") {
    const result = await env.DB.prepare(`
      SELECT id,user_id,title,message,type,target_type,target_id,is_read,created_at
      FROM notifications
      WHERE user_id=?
      ORDER BY id DESC
      LIMIT 100
    `).bind(me.id).all();
    return json(result.results,200,headers);
  }

  const notificationReadMatch = path.match(/^\/api\/notifications\/(\d+)\/read$/);
  if (request.method === "POST" && notificationReadMatch) {
    const id = Number(notificationReadMatch[1]);
    await env.DB.prepare(`
      UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?
    `).bind(id,me.id).run();
    return json({ok:true},200,headers);
  }

  if (request.method === "POST" && path === "/api/notifications/read-all") {
    await env.DB.prepare(`
      UPDATE notifications SET is_read=1 WHERE user_id=?
    `).bind(me.id).run();
    return json({ok:true},200,headers);
  }

  if (request.method === "POST" && path === "/api/invites") {
    const data = await body(request);
    const clanId = Number(data.clan_id);
    const inviteeId = Number(data.user_id);
    const clan = await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();
    if (!clan) return json({ error: "Clan no encontrado." }, 404, headers);
    if (clan.captain_id !== me.id && !isAdmin(me)) return json({ error: "Solo el capitán puede invitar jugadores." }, 403, headers);
    if (!inviteeId) return json({ error: "Jugador no válido." }, 400, headers);
    if (inviteeId === me.id) return json({ error: "No puedes invitarte a ti mismo." }, 400, headers);
    const user = await env.DB.prepare(`SELECT id,username FROM users WHERE id=? AND is_blocked=0`).bind(inviteeId).first();
    if (!user) return json({ error: "Jugador no encontrado." }, 404, headers);
    const member = await env.DB.prepare(`SELECT 1 FROM members WHERE clan_id=? AND user_id=?`).bind(clanId, inviteeId).first();
    if (member) return json({ error: "Ese jugador ya pertenece al clan." }, 400, headers);
    const pending = await env.DB.prepare(`SELECT id FROM invites WHERE clan_id=? AND invitee_id=? AND status='pending'`).bind(clanId, inviteeId).first();
    if (pending) return json({ error: "Ya existe una invitación pendiente." }, 400, headers);
    const created = await env.DB.prepare(`INSERT INTO invites (clan_id,inviter_id,invitee_id,status) VALUES (?,?,?,'pending')`).bind(clanId, me.id, inviteeId).run();
    await env.DB.prepare(`
      INSERT INTO notifications
      (user_id,title,message,type,target_type,target_id,is_read)
      VALUES (?,?,?,'clan_invite','clan',?,0)
    `).bind(
      inviteeId,
      "Invitación de clan",
      `Has recibido una invitación para unirte a ${clan.name}.`,
      clan.id
    ).run();
    return json({ ok:true, id:created.meta.last_row_id },200,headers);
  }
  if (request.method === "GET" && path === "/api/invites") {
    const result = await env.DB.prepare(`
      SELECT i.id,i.clan_id,i.inviter_id,i.invitee_id,i.status,i.created_at,c.name,c.clan_code,c.logo_url
      FROM invites i JOIN clans c ON c.id=i.clan_id
      WHERE i.invitee_id=? AND i.status='pending' ORDER BY i.id DESC
    `).bind(me.id).all();
    return json(result.results,200,headers);
  }
  const inviteAction = path.match(/^\/api\/invites\/(\d+)\/(accept|reject)$/);
  if (request.method === "POST" && inviteAction) {
    const inviteId=Number(inviteAction[1]); const action=inviteAction[2];
    const invite=await env.DB.prepare(`SELECT * FROM invites WHERE id=? AND invitee_id=? AND status='pending'`).bind(inviteId,me.id).first();
    if(!invite) return json({error:"Invitación no disponible."},404,headers);
    if(action==='reject') { await env.DB.prepare(`UPDATE invites SET status='rejected' WHERE id=?`).bind(inviteId).run(); return json({ok:true},200,headers); }
    const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(invite.clan_id).first();
    if(!clan) return json({error:"Clan no encontrado."},404,headers);
    const already=await getUserClan(env,me.id,Number(clan.league));
    if(already) return json({error:"Ya perteneces a un clan en esta liga."},400,headers);
    await env.DB.batch([
      env.DB.prepare(`INSERT OR IGNORE INTO members (clan_id,user_id,role) VALUES (?,?,?)`).bind(clan.id,me.id,"member"),
      env.DB.prepare(`UPDATE invites SET status='accepted' WHERE id=?`).bind(inviteId),
      env.DB.prepare(`
        INSERT INTO notifications
        (user_id,title,message,type,target_type,target_id,is_read)
        VALUES (?,?,?,'clan_invite_accepted','clan',?,0)
      `).bind(
        invite.inviter_id,
        "Invitación aceptada",
        `${me.username} ha aceptado la invitación para unirse a ${clan.name}.`,
        clan.id
      )
    ]);
    return json({ok:true},200,headers);
  }
  if (request.method === "POST" && path === "/api/challenges") {
    const data = await body(request);
    const league = normalizeLeague(
      data.league || 4,
      4
    );
    const teamSize = Number(
      data.team_size || league
    );
    if (![1, 2, 3, 4].includes(
      league
    ) || teamSize !== league) {
      return json(
        {
          error: "El formato del reto no coincide con la liga."
        },
        400,
        headers
      );
    }
    const clan = await getUserClan(
      env,
      me.id,
      league
    );
    if (!clan) {
      return json(
        {
          error: "No perteneces a ning\xFAn clan en esta liga."
        },
        400,
        headers
      );
    }
    if (clan.captain_id !== me.id) {
      return json(
        {
          error: "Solo el capit\xE1n puede publicar retos."
        },
        403,
        headers
      );
    }
    const active = await env.DB.prepare(`
        SELECT id
        FROM challenges

        WHERE
        (
          creator_clan_id=?
          OR accepter_clan_id=?
        )

        AND status IN(
          'open',
          'accepted'
        )

        LIMIT 1
      `).bind(
      clan.id,
      clan.id
    ).first();
    if (active) {
      return json(
        {
          error: "Tu clan ya tiene un reto activo."
        },
        400,
        headers
      );
    }
    const selectedMaps = randomMaps();
    const now = Date.now();
    const createdAt = new Date(
      now
    ).toISOString();
    const expiresAt = new Date(
      now + 30 * 60 * 1e3
    ).toISOString();
    const requestedMode = String(
      data.mode ||
      (Array.isArray(data.game_modes) ? data.game_modes[0] : "") ||
      (league === 1 ? "franco" : "snd")
    ).toLowerCase();

    const allowedModes = league === 1
      ? ["franco", "arma"]
      : ["snd", "ctf", "hardpoint"];

    if(!allowedModes.includes(requestedMode)){
      return json(
        { error: "Modalidad de reto no válida." },
        400,
        headers
      );
    }

    const modes = [requestedMode];
    const created = await env.DB.prepare(`
        INSERT INTO challenges
        (
          creator_clan_id,
          status,
          map1,
          map2,
          map3,
          team_size,
          game_modes,
          one_vs_one_mode,
          scheduled_at,
          expires_at
        )

        VALUES(
          ?,
          'open',
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?
        )
      `).bind(
      clan.id,
      selectedMaps[0],
      selectedMaps[1],
      selectedMaps[2],
      teamSize,
      JSON.stringify(modes),
      league === 1 ? requestedMode : null,
      createdAt,
      expiresAt
    ).run();
    return json(
      {
        ok: true,
        id: created.meta.last_row_id,
        expires_at: expiresAt,
        maps: selectedMaps
      },
      200,
      headers
    );
  }
  if (request.method === "GET" && path === "/api/challenges") {
    await expireChallenges(env);
    const params = new URL(request.url).searchParams;
    const league = normalizeLeague(params.get("league") || 4, 4);
    const clan = await getUserClan(env, me.id, league);
    const clanId = clan ? clan.id : -1;
    const result = await env.DB.prepare(`
      SELECT
        ch.*,
        NULL AS creator_name,
        NULL AS creator_code,
        CASE WHEN ch.creator_clan_id=? THEN 1 ELSE 0 END AS is_creator,
        accepter.name AS accepter_name,
        accepter.clan_code AS accepter_code
      FROM challenges ch
      JOIN clans creator ON creator.id=ch.creator_clan_id
      LEFT JOIN clans accepter ON accepter.id=ch.accepter_clan_id
      WHERE creator.league=?
        AND ch.status IN('open','accepted')
        AND (ch.status='open' OR ch.creator_clan_id=? OR ch.accepter_clan_id=?)
      ORDER BY ch.id DESC
    `).bind(clanId, league, clanId, clanId).all();
    const rows = result.results.map(x => ({
      ...x,
      league: Number(x.team_size || league),
      team_size: Number(x.team_size || league),
      mode: x.one_vs_one_mode || (() => {
        try {
          const parsed = JSON.parse(x.game_modes || "[]");
          return Array.isArray(parsed) && parsed[0] ? parsed[0] : "snd";
        } catch(e) { return "snd"; }
      })()
    }));
    return json(rows, 200, headers);
  }

  const detailMatch = path.match(/^\/api\/challenges\/(\d+)$/);
  if (request.method === "GET" && detailMatch) {
    const id = Number(detailMatch[1]);
    const result = await env.DB.prepare(`
      SELECT ch.*, creator.name AS creator_clan_name, creator.clan_code AS creator_clan_code,
             accepter.name AS accepter_clan_name, accepter.clan_code AS accepter_clan_code
      FROM challenges ch
      JOIN clans creator ON creator.id=ch.creator_clan_id
      LEFT JOIN clans accepter ON accepter.id=ch.accepter_clan_id
      WHERE ch.id=? LIMIT 1
    `).bind(id).first();
    if(!result) return json({error:"Reto no encontrado."},404,headers);
    let mode = result.one_vs_one_mode || "snd";
    if(!result.one_vs_one_mode){
      try { const parsed=JSON.parse(result.game_modes||"[]"); if(Array.isArray(parsed)&&parsed[0]) mode=parsed[0]; } catch(e) {}
    }
    return json({...result, league:Number(result.team_size||4), team_size:Number(result.team_size||4), mode},200,headers);
  }
  const cancelMatch = path.match(
    /^\/api\/challenges\/(\d+)\/cancel$/
  );
  if (request.method === "POST" && cancelMatch) {
    const challengeId = Number(cancelMatch[1]);
    const challenge = await env.DB.prepare(`SELECT * FROM challenges WHERE id=? AND status='open'`).bind(challengeId).first();
    if (!challenge) return json({ error: "El reto no está disponible para cancelar." }, 400, headers);
    const clan = await getUserClan(env, me.id, Number(challenge.team_size));
    if (!clan || clan.id !== challenge.creator_clan_id) return json({ error: "Solo el clan que publicó el reto puede cancelarlo." }, 403, headers);
    if (clan.captain_id !== me.id && !isAdmin(me)) return json({ error: "Solo el capitán puede cancelar el reto." }, 403, headers);
    const data = await body(request);
    const reason = String(data.reason || "Cancelado por el creador").trim().slice(0, 120);
    await env.DB.prepare(`UPDATE challenges SET status='cancelled', cancel_reason=?, cancelled_at=CURRENT_TIMESTAMP WHERE id=? AND status='open'`).bind(reason, challengeId).run();
    return json({ ok: true }, 200, headers);
  }

  const acceptMatch = path.match(
    /^\/api\/challenges\/(\d+)\/accept$/
  );
  if (request.method === "POST" && acceptMatch) {
    const challengeId = Number(
      acceptMatch[1]
    );
    const challenge = await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE
          id=?
          AND status='open'
      `).bind(
      challengeId
    ).first();
    if (!challenge) {
      return json(
        {
          error: "El reto ya no est\xE1 disponible."
        },
        400,
        headers
      );
    }
    if (challenge.expires_at && challenge.expires_at <= (/* @__PURE__ */ new Date()).toISOString()) {
      await env.DB.prepare(`
        UPDATE challenges

        SET
          status='expired',
          cancel_reason=
            'No aceptado en 30 minutos',
          cancelled_at=CURRENT_TIMESTAMP

        WHERE id=?
      `).bind(
        challengeId
      ).run();
      return json(
        {
          error: "El reto ha caducado."
        },
        400,
        headers
      );
    }
    const league = Number(
      challenge.team_size
    );
    const clan = await getUserClan(
      env,
      me.id,
      league
    );
    if (!clan) {
      return json(
        {
          error: "No perteneces a un clan en esta liga."
        },
        400,
        headers
      );
    }
    if (clan.id === challenge.creator_clan_id) {
      return json(
        {
          error: "No puedes aceptar tu propio reto."
        },
        400,
        headers
      );
    }
    if (clan.captain_id !== me.id) {
      return json(
        {
          error: "Solo el capit\xE1n puede aceptar un reto."
        },
        403,
        headers
      );
    }
    const active = await env.DB.prepare(`
        SELECT id
        FROM challenges

        WHERE
        (
          creator_clan_id=?
          OR accepter_clan_id=?
        )

        AND status IN(
          'open',
          'accepted'
        )

        AND id<>?

        LIMIT 1
      `).bind(
      clan.id,
      clan.id,
      challengeId
    ).first();
    if (active) {
      return json(
        {
          error: "Tu clan ya tiene otro reto activo."
        },
        400,
        headers
      );
    }
    await env.DB.prepare(`
      UPDATE challenges

      SET
        accepter_clan_id=?,
        status='accepted'

      WHERE
        id=?
        AND status='open'
    `).bind(
      clan.id,
      challengeId
    ).run();
    return json(
      {
        ok: true
      },
      200,
      headers
    );
  }
  const reportMatch = path.match(
    /^\/api\/challenges\/(\d+)\/report$/
  );
  if (request.method === "POST" && reportMatch) {
    const challengeId = Number(
      reportMatch[1]
    );
    const data = await body(request);
    const result = String(
      data.result || ""
    );
    if (result !== "win" && result !== "loss") {
      return json(
        {
          error: "Resultado no v\xE1lido."
        },
        400,
        headers
      );
    }
    const challenge = await env.DB.prepare(`
        SELECT *
        FROM challenges

        WHERE
          id=?
          AND status='accepted'
      `).bind(
      challengeId
    ).first();
    if (!challenge) {
      return json(
        {
          error: "El reto no est\xE1 disponible."
        },
        400,
        headers
      );
    }
    const clan = await getUserClan(
      env,
      me.id,
      Number(
        challenge.team_size
      )
    );
    if (!clan) {
      return json(
        {
          error: "No perteneces a un clan de esta liga."
        },
        403,
        headers
      );
    }
    if (![
      challenge.creator_clan_id,
      challenge.accepter_clan_id
    ].includes(clan.id)) {
      return json(
        {
          error: "No participas en este reto."
        },
        403,
                headers
      );
    }
    if (clan.captain_id !== me.id) {
      return json(
        {
          error: "Solo el capit\xE1n puede confirmar el resultado."
        },
        403,
        headers
      );
    }
    const winner = result === "win" ? clan.id : clan.id === challenge.creator_clan_id ? challenge.accepter_clan_id : challenge.creator_clan_id;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO reports
      (
        challenge_id,
        clan_id,
        winner_clan_id
      )

       VALUES(?,?,?)
    `).bind(
      challengeId,
      clan.id,
      winner
    ).run();
    const reports = await env.DB.prepare(`
        SELECT *
        FROM reports
        WHERE challenge_id=?
      `).bind(
      challengeId
    ).all();
    if (reports.results.length < 2) {
      return json(
        {
          ok: true,
          completed: false,
          message: "Resultado enviado. Falta el otro capit\xE1n."
        },
        200,
        headers
      );
    }
    const firstWinner = reports.results[0].winner_clan_id;
    const secondWinner = reports.results[1].winner_clan_id;
    if (firstWinner !== secondWinner) {
      return json(
        {
          ok: true,
          completed: false,
          conflict: true,
          message: "Los resultados no coinciden. Administraci\xF3n debe revisarlo."
        },
        200,
        headers
      );
    }
    const winnerClan = firstWinner;
    const loserClan = winnerClan === challenge.creator_clan_id ? challenge.accepter_clan_id : challenge.creator_clan_id;
    await env.DB.batch([
      env.DB.prepare(`
        UPDATE challenges

        SET
          status='completed',
          winner_clan_id=?,
          completed_at=CURRENT_TIMESTAMP

        WHERE id=?
      `).bind(
        winnerClan,
        challengeId
      ),
      env.DB.prepare(`
        UPDATE scores

        SET
          played=played+1,
          wins=wins+1,
          points=points+3

        WHERE clan_id=?
      `).bind(
        winnerClan
      ),
      env.DB.prepare(`
        UPDATE scores

        SET
          played=played+1,
          losses=losses+1

        WHERE clan_id=?
      `).bind(
        loserClan
      )
    ]);
    return json(
      {
        ok: true,
        completed: true
      },
      200,
      headers
    );
  }
  if (request.method === "GET" && path === "/api/history") {
    const clan = await getUserClan(
      env,
      me.id
    );
    const clanId = clan ? clan.id : -1;
    const result = await env.DB.prepare(`
        SELECT

          ch.*,

          creator.name
            AS creator_name,

          accepter.name
            AS accepter_name,

          winner.name
            AS winner_name

        FROM challenges ch

        JOIN clans creator
          ON creator.id=
             ch.creator_clan_id

        LEFT JOIN clans accepter
          ON accepter.id=
             ch.accepter_clan_id

        LEFT JOIN clans winner
          ON winner.id=
             ch.winner_clan_id

        WHERE
          ch.status='completed'

          AND
          (
            ch.creator_clan_id=?
            OR
            ch.accepter_clan_id=?
          )

        ORDER BY
          ch.id DESC

        LIMIT 100
      `).bind(
      clanId,
      clanId
    ).all();
    return json(
      result.results,
      200,
      headers
    );
  }
  if (isAdmin(me)) {
    if (request.method === "GET" && path === "/api/admin") {
      const [users, clans, challenges] = await Promise.all([
        env.DB.prepare(`SELECT id,username,psn_id,avatar_url,is_blocked,blocked_until,created_at FROM users ORDER BY id DESC LIMIT 500`).all(),
        env.DB.prepare(`SELECT c.*,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played FROM clans c LEFT JOIN scores s ON s.clan_id=c.id ORDER BY c.league,points DESC,c.name`).all(),
        env.DB.prepare(`SELECT ch.*,creator.name creator_clan_name,accepter.name accepter_clan_name FROM challenges ch JOIN clans creator ON creator.id=ch.creator_clan_id LEFT JOIN clans accepter ON accepter.id=ch.accepter_clan_id ORDER BY ch.id DESC LIMIT 500`).all()
      ]);
      return json({users:users.results,clans:clans.results,challenges:challenges.results},200,headers);
    }

    if (request.method === "DELETE" && /^\/api\/admin\/users\/\d+$/.test(path)) {
      const id=Number(path.split("/").pop());
      if(id===Number(me.id)) return json({error:"No puedes borrar tu propia cuenta de administrador."},400,headers);
      const target=await env.DB.prepare(`SELECT id FROM users WHERE id=?`).bind(id).first();
      if(!target) return json({error:"Usuario no encontrado."},404,headers);
      const owned=await env.DB.prepare(`SELECT id FROM clans WHERE captain_id=?`).bind(id).all();
      for(const clan of owned.results){
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM reports WHERE challenge_id IN (SELECT id FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?)`).bind(clan.id,clan.id),
          env.DB.prepare(`DELETE FROM chat_messages WHERE challenge_id IN (SELECT id FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?)`).bind(clan.id,clan.id),
          env.DB.prepare(`DELETE FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?`).bind(clan.id,clan.id),
          env.DB.prepare(`DELETE FROM invites WHERE clan_id=?`).bind(clan.id),
          env.DB.prepare(`DELETE FROM members WHERE clan_id=?`).bind(clan.id),
          env.DB.prepare(`DELETE FROM scores WHERE clan_id=?`).bind(clan.id),
          env.DB.prepare(`DELETE FROM clans WHERE id=?`).bind(clan.id)
        ]);
      }
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM invites WHERE inviter_id=? OR invitee_id=?`).bind(id,id),
        env.DB.prepare(`DELETE FROM members WHERE user_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM notifications WHERE user_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM chat_messages WHERE user_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id)
      ]);
      return json({ok:true},200,headers);
    }

    if (request.method === "DELETE" && /^\/api\/admin\/clans\/\d+$/.test(path)) {
      const id=Number(path.split("/").pop());
      const clan=await env.DB.prepare(`SELECT id FROM clans WHERE id=?`).bind(id).first();
      if(!clan) return json({error:"Clan no encontrado."},404,headers);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM reports WHERE challenge_id IN (SELECT id FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?)`).bind(id,id),
        env.DB.prepare(`DELETE FROM chat_messages WHERE challenge_id IN (SELECT id FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?)`).bind(id,id),
        env.DB.prepare(`DELETE FROM challenges WHERE creator_clan_id=? OR accepter_clan_id=?`).bind(id,id),
        env.DB.prepare(`DELETE FROM invites WHERE clan_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM members WHERE clan_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM scores WHERE clan_id=?`).bind(id),
        env.DB.prepare(`DELETE FROM clans WHERE id=?`).bind(id)
      ]);
      return json({ok:true},200,headers);
    }

    if (request.method === "GET" && path === "/api/admin/users") {
      const result = await env.DB.prepare(`
          SELECT
            id,
            username,
            psn_id,
            avatar_url,
            is_blocked,
            blocked_until,
            created_at
          FROM users
          ORDER BY id DESC
          LIMIT 500
        `).all();
      return json(
        result.results,
        200,
        headers
      );
    }
    if (request.method === "GET" && path === "/api/admin/challenges") {
      const result=await env.DB.prepare(`
        SELECT ch.*, creator.name AS creator_name, creator.clan_code AS creator_code, accepter.name AS accepter_name, accepter.clan_code AS accepter_code
        FROM challenges ch JOIN clans creator ON creator.id=ch.creator_clan_id LEFT JOIN clans accepter ON accepter.id=ch.accepter_clan_id
        ORDER BY ch.id DESC LIMIT 500
      `).all();
      return json(result.results,200,headers);
    }
    if (request.method === "GET" && path === "/api/admin/clans") {
      const result=await env.DB.prepare(`SELECT c.*,COALESCE(s.points,0) points,COALESCE(s.wins,0) wins,COALESCE(s.losses,0) losses,COALESCE(s.played,0) played FROM clans c LEFT JOIN scores s ON s.clan_id=c.id ORDER BY c.league,points DESC,c.name`).all();
      return json(result.results,200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/block") {
      const data = await body(request);
      const userId = Number(
        data.user_id
      );
      let blockedUntil;
      if (data.permanent) {
        blockedUntil = 0;
      } else {
        const minutes = Number(
          data.minutes || 60
        );
        blockedUntil = Date.now() + minutes * 6e4;
      }
      await env.DB.prepare(`
        UPDATE users

        SET
          is_blocked=1,
          blocked_until=?

        WHERE id=?
      `).bind(
        blockedUntil,
        userId
      ).run();
      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id=?
      `).bind(
        userId
      ).run();
      return json(
        {
          ok: true
        },
        200,
        headers
      );
    }
    if (request.method === "POST" && path === "/api/admin/unblock") {
      const data = await body(request);
      const userId = Number(
        data.user_id
      );
      await env.DB.prepare(`
        UPDATE users

        SET
          is_blocked=0,
          blocked_until=NULL

        WHERE id=?
      `).bind(
        userId
      ).run();
      return json(
        {
          ok: true
        },
        200,
        headers
      );
    }
    if (request.method === "POST" && path === "/api/admin/reset-ranking") {
      const data = await body(request);
      const league = normalizeLeague(
        data.league || 4,
        4
      );
      if (![2, 3, 4].includes(
        league
      )) {
        return json(
          {
            error: "Liga no v\xE1lida."
          },
          400,
          headers
        );
      }
      await env.DB.prepare(`
        UPDATE scores

        SET
          points=0,
          wins=0,
          losses=0,
          played=0

        WHERE league=?
      `).bind(
        league
      ).run();
      return json(
        {
          ok: true
        },
        200,
        headers
      );
    }
    if (request.method === "POST" && path === "/api/admin/set-psn") {
      const data=await body(request); const userId=Number(data.user_id); const psn=String(data.psn_id||"").trim().slice(0,32);
      const exists=await env.DB.prepare(`SELECT id FROM users WHERE id=?`).bind(userId).first();
      if(!exists) return json({error:"Usuario no encontrado."},404,headers);
      await env.DB.prepare(`UPDATE users SET psn_id=?, psn_changed_at=? WHERE id=?`).bind(psn,Date.now(),userId).run();
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/remove-member") {
      const data=await body(request); const clanId=Number(data.clan_id); const userId=Number(data.user_id);
      const clan=await env.DB.prepare(`SELECT * FROM clans WHERE id=?`).bind(clanId).first();
      if(!clan) return json({error:"Clan no encontrado."},404,headers);
      if(userId===clan.captain_id) return json({error:"No se puede expulsar al capitán sin cambiar el capitán primero."},400,headers);
      await env.DB.prepare(`DELETE FROM members WHERE clan_id=? AND user_id=?`).bind(clanId,userId).run();
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/change-captain") {
      const data=await body(request); const clanId=Number(data.clan_id); const userId=Number(data.user_id);
      const member=await env.DB.prepare(`SELECT 1 FROM members WHERE clan_id=? AND user_id=?`).bind(clanId,userId).first();
      if(!member) return json({error:"El jugador no pertenece al clan."},400,headers);
      await env.DB.batch([
        env.DB.prepare(`UPDATE clans SET captain_id=? WHERE id=?`).bind(userId,clanId),
        env.DB.prepare(`UPDATE members SET role='member' WHERE clan_id=?`).bind(clanId),
        env.DB.prepare(`UPDATE members SET role='captain' WHERE clan_id=? AND user_id=?`).bind(clanId,userId)
      ]);
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/remove-clan") {
      const data=await body(request); const clanId=Number(data.clan_id);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM members WHERE clan_id=?`).bind(clanId),
        env.DB.prepare(`DELETE FROM invites WHERE clan_id=?`).bind(clanId),
        env.DB.prepare(`DELETE FROM scores WHERE clan_id=?`).bind(clanId),
        env.DB.prepare(`DELETE FROM clans WHERE id=?`).bind(clanId)
      ]);
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/set-score") {
      const data=await body(request); const clanId=Number(data.clan_id); const points=Number(data.points); const wins=Number(data.wins); const losses=Number(data.losses); const played=Number(data.played);
      if([points,wins,losses,played].some(n=>!Number.isInteger(n)||n<0)) return json({error:"Estadísticas no válidas."},400,headers);
      await env.DB.prepare(`UPDATE scores SET points=?,wins=?,losses=?,played=? WHERE clan_id=?`).bind(points,wins,losses,played,clanId).run();
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/reset-league") {
      const data=await body(request); const league=Number(data.league); if(![2,3,4].includes(league)) return json({error:"Liga no válida."},400,headers);
      await env.DB.batch([
        env.DB.prepare(`UPDATE scores SET points=0,wins=0,losses=0,played=0 WHERE league=?`).bind(league),
        env.DB.prepare(`UPDATE challenges SET status='cancelled',cancel_reason='RESET_LEAGUE',cancelled_at=CURRENT_TIMESTAMP WHERE status IN ('open','accepted') AND team_size=?`).bind(league)
      ]);
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/edit-result") {
      const data=await body(request);
      const challengeId=Number(data.challenge_id);
      const winnerClanId=Number(data.winner_clan_id);
      const ch=await env.DB.prepare(`SELECT * FROM challenges WHERE id=?`).bind(challengeId).first();
      if(!ch) return json({error:"Reto no encontrado."},404,headers);
      if(![ch.creator_clan_id,ch.accepter_clan_id].includes(winnerClanId)) return json({error:"Ganador no válido."},400,headers);
      await env.DB.prepare(`UPDATE challenges SET status='completed',winner_clan_id=?,completed_at=COALESCE(completed_at,CURRENT_TIMESTAMP) WHERE id=?`).bind(winnerClanId,challengeId).run();
      const league=Number(ch.team_size);
      await env.DB.prepare(`UPDATE scores SET points=0,wins=0,losses=0,played=0 WHERE league=?`).bind(league).run();
      const all=await env.DB.prepare(`SELECT creator_clan_id,accepter_clan_id,winner_clan_id FROM challenges WHERE status='completed' AND team_size=? AND winner_clan_id IS NOT NULL`).bind(league).all();
      for(const match of all.results){
        const loser=match.winner_clan_id===match.creator_clan_id?match.accepter_clan_id:match.creator_clan_id;
        await env.DB.prepare(`UPDATE scores SET played=played+1,wins=wins+1,points=points+3 WHERE clan_id=?`).bind(match.winner_clan_id).run();
        await env.DB.prepare(`UPDATE scores SET played=played+1,losses=losses+1 WHERE clan_id=?`).bind(loser).run();
      }
      return json({ok:true},200,headers);
    }
    if (request.method === "POST" && path === "/api/admin/delete-challenge") {
      const data = await body(request);
      const challengeId = Number(
        data.challenge_id
      );
      await env.DB.prepare(`
        UPDATE challenges

        SET
          status='cancelled',
          cancel_reason='ADMIN',
          cancelled_at=CURRENT_TIMESTAMP

        WHERE id=?
      `).bind(
        challengeId
      ).run();
      return json(
        {
          ok: true
        },
        200,
        headers
      );
    }
  }
  return json(
    {
      error: "Ruta no encontrada."
        /* =====================================================
     MIS RETOS
  ===================================================== */

  if (
    request.method === "GET" &&
    path === "/api/my-challenges"
  ) {

    const result = await env.DB.prepare(`
      SELECT
        ch.*,

        creator.name AS creator_clan_name,
        creator.clan_code AS creator_clan_code,
        creator.league AS creator_league,

        accepter.name AS accepter_clan_name,
        accepter.clan_code AS accepter_clan_code,
        accepter.league AS accepter_league

      FROM challenges ch

      JOIN clans creator
        ON creator.id = ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id = ch.accepter_clan_id

      WHERE
        ch.creator_clan_id IN (
          SELECT clan_id
          FROM members
          WHERE user_id = ?
        )

        OR

        ch.accepter_clan_id IN (
          SELECT clan_id
          FROM members
          WHERE user_id = ?
        )

      ORDER BY ch.id DESC

      LIMIT 100
    `)
    .bind(
      me.id,
      me.id
    )
    .all();

    const rows = result.results.map(ch => {

      let mode = ch.one_vs_one_mode || "";

      if (!mode) {
        try {
          const parsed =
            JSON.parse(
              ch.game_modes || "[]"
            );

          if (
            Array.isArray(parsed) &&
            parsed.length
          ) {
            mode = parsed[0];
          }

        } catch (e) {
          mode = "";
        }
      }

      return {
        ...ch,

        league: Number(
          ch.league ||
          ch.team_size ||
          4
        ),

        team_size: Number(
          ch.team_size ||
          ch.league ||
          4
        ),

        mode
      };

    });

    return json(
      rows,
      200,
      headers
    );
  }
    },
    404,
    headers
  );
}
__name(api, "api");
async function handleRequest(request, env) {
  const url = new URL(
    request.url
  );
  if (url.pathname.startsWith(
    "/api/"
  )) {
    return api(
      request,
      env,
      url.pathname
    );
  }
  if (env.ASSETS) {
    return env.ASSETS.fetch(
      request
    );
  }
  return new Response(
    "BlackOpsLALIGA",
    {
      status: 200
    }
  );
}
__name(handleRequest, "handleRequest");
var worker_default = {
  async fetch(request, env) {
    try {
      return await handleRequest(
        request,
        env
      );
    } catch (error) {
      console.error(
        "WORKER ERROR:",
        error
      );
      return json(
        {
          error: "Error interno del servidor",
          detail: error.message
        },
        500,
        cors(request)
      );
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
