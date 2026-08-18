const COOKIE = "bol_session";
const SESSION_DAYS = 7;

const MAPS = [
  "Raid",
  "Standoff",
  "Slums",
  "Yemen",
  "Meltdown",
  "Express"
];

const ONE_VS_ONE_MAP = "Nuketown";

const json = (data, status = 200, headers = {}) =>
  new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json;charset=UTF-8",
        ...headers
      }
    }
  );

const body = async (request) => {
  try {
    return await request.json();
  } catch {
    return {};
  }
};

function cors(request) {

  const origin =
    request.headers.get("Origin");

  return {
    "Access-Control-Allow-Methods":
      "GET,POST,PUT,DELETE,OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type",

    "Access-Control-Allow-Credentials":
      "true",

    ...(origin
      ? {
          "Access-Control-Allow-Origin":
            origin,

          "Vary":
            "Origin"
        }
      : {})
  };
}

function sessionCookie(token) {

  return `${COOKIE}=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=${
    SESSION_DAYS * 86400
  }; HttpOnly; SameSite=Lax; Secure`;
}

function deleteSessionCookie() {

  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;
}

function getCookie(request) {

  const cookies =
    request.headers.get("Cookie") || "";

  const match =
    cookies.match(
      new RegExp(
        "(^|;\\s*)" +
        COOKIE +
        "=([^;]+)"
      )
    );

  return match
    ? decodeURIComponent(match[2])
    : null;
}


/* =====================================================
   CONTRASEÑAS
===================================================== */

async function hashPassword(
  password,
  salt = crypto.randomUUID()
) {

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt:
          new TextEncoder().encode(salt),
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  const encoded =
    btoa(
      String.fromCharCode(
        ...new Uint8Array(bits)
      )
    ).replaceAll("=", "");

  return `${salt}.${encoded}`;
}

async function verifyPassword(
  password,
  stored
) {

  if (
    !stored ||
    !stored.includes(".")
  ) {
    return false;
  }

  const [
    salt,
    hash
  ] =
    stored.split(".");

  const generated =
    await hashPassword(
      password,
      salt
    );

  return (
    generated ===
    `${salt}.${hash}`
  );
}


/* =====================================================
   BASE DE DATOS
===================================================== */

async function ensureColumn(
  env,
  table,
  column,
  definition
) {

  const result =
    await env.DB.prepare(
      `PRAGMA table_info(${table})`
    ).all();

  const exists =
    result.results.some(
      row =>
        row.name === column
    );

  if (!exists) {

    await env.DB.prepare(
      `ALTER TABLE ${table}
       ADD COLUMN ${column}
       ${definition}`
    ).run();

  }
}


async function initDatabase(env) {

  /* ===============================
     USUARIOS
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      psn_id TEXT,
      psn_changed_at INTEGER,
      avatar_url TEXT,
      is_blocked INTEGER DEFAULT 0,
      blocked_until INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  /* ===============================
     SESIONES
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires INTEGER NOT NULL
    )
  `).run();


  /* ===============================
     CLANES
     
     league:
     1 = 1v1
     2 = 2v2
     3 = 3v3
     4 = 4v4
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS clans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      captain_id INTEGER NOT NULL,
      league INTEGER NOT NULL DEFAULT 4,
      clan_code TEXT UNIQUE,
      logo_url TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  /* ===============================
     MIEMBROS
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS members(
      clan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT DEFAULT 'member',
      joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(clan_id,user_id)
    )
  `).run();


  /* ===============================
     INVITACIONES
  =============================== */

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


  /* ===============================
     RETOS

     open       = esperando rival
     accepted   = hay enfrentamiento
     completed  = resultado confirmado
     cancelled  = cancelado
     expired    = caducado
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS challenges(
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      creator_clan_id INTEGER NOT NULL,

      accepter_clan_id INTEGER,

      status TEXT DEFAULT 'open',

      league INTEGER NOT NULL DEFAULT 4,

      team_size INTEGER NOT NULL DEFAULT 4,

      game_modes TEXT DEFAULT '["snd"]',

      map1 TEXT,
      map2 TEXT,
      map3 TEXT,

      one_vs_one_mode TEXT,

      scheduled_at TEXT,

      expires_at TEXT,

      cancel_reason TEXT,

      cancelled_at TEXT,

      winner_clan_id INTEGER,

      created_at TEXT DEFAULT CURRENT_TIMESTAMP,

      completed_at TEXT
    )
  `).run();


  /* ===============================
     RESULTADOS
     
     Cada clan participante
     envía su propia confirmación.
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      challenge_id INTEGER NOT NULL,

      clan_id INTEGER NOT NULL,

      winner_clan_id INTEGER NOT NULL,

      created_at TEXT DEFAULT CURRENT_TIMESTAMP,

      UNIQUE(
        challenge_id,
        clan_id
      )
    )
  `).run();


  /* ===============================
     PUNTUACIÓN
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores(
      clan_id INTEGER PRIMARY KEY,

      league INTEGER NOT NULL DEFAULT 4,

      points INTEGER DEFAULT 0,

      wins INTEGER DEFAULT 0,

      losses INTEGER DEFAULT 0,

      played INTEGER DEFAULT 0
    )
  `).run();


  /* ===============================
     NOTIFICACIONES
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      user_id INTEGER NOT NULL,

      title TEXT NOT NULL,

      message TEXT NOT NULL,

      type TEXT DEFAULT 'general',

      related_id INTEGER,

      is_read INTEGER DEFAULT 0,

      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  /* ===============================
     CHAT
  =============================== */

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS chat_messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      challenge_id INTEGER NOT NULL,

      user_id INTEGER NOT NULL,

      message TEXT NOT NULL,

      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  /* ===============================
     MIGRACIONES PARA INSTALACIONES
     ANTERIORES
  =============================== */

  const migrations = [

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
      "league",
      "INTEGER DEFAULT 4"
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
      "challenges",
      "winner_clan_id",
      "INTEGER"
    ],

    [
      "challenges",
      "completed_at",
      "TEXT"
    ],

    [
      "reports",
      "created_at",
      "TEXT DEFAULT CURRENT_TIMESTAMP"
    ],

    [
      "notifications",
      "related_id",
      "INTEGER"
    ],

    [
      "scores",
      "league",
      "INTEGER DEFAULT 4"
    ]

  ];


  for (
    const [
      table,
      column,
      definition
    ]
    of migrations
  ) {

    try {

      await ensureColumn(
        env,
        table,
        column,
        definition
      );

    } catch(error) {

      console.log(
        "MIGRATION ERROR",
        table,
        column,
        error.message
      );

    }

  }

}


/* =====================================================
   USUARIO ACTUAL
===================================================== */

async function getCurrentUser(
  request,
  env
) {

  const token =
    getCookie(request);

  if (!token) {
    return null;
  }

  const user =
    await env.DB.prepare(`
      SELECT
        u.*
      FROM sessions s

      JOIN users u
        ON u.id=s.user_id

      WHERE
        s.token=?

        AND s.expires>?
    `)
      .bind(
        token,
        Date.now()
      )
      .first();

  return user || null;
}


/* =====================================================
   ADMIN
===================================================== */

function isAdmin(user) {

  return !!user &&
    String(
      user.username || ""
    )
      .toLowerCase() ===
      "admin";
}


/* =====================================================
   CLAN DEL USUARIO EN UNA LIGA
===================================================== */

async function getUserClan(
  env,
  userId,
  league
) {

  return await env.DB.prepare(`
    SELECT
      c.*,

      m.role AS member_role

    FROM members m

    JOIN clans c
      ON c.id=m.clan_id

    WHERE
      m.user_id=?

      AND c.league=?

    LIMIT 1
  `)
    .bind(
      userId,
      league
    )
    .first();
}


/* =====================================================
   TODOS LOS CLANES DEL USUARIO
===================================================== */

async function getUserClans(
  env,
  userId
) {

  const result =
    await env.DB.prepare(`
      SELECT

        c.id,

        c.name,

        c.clan_code,

        c.logo_url,

        c.league,

        c.captain_id,

        m.role,

        m.joined_at

      FROM members m

      JOIN clans c
        ON c.id=m.clan_id

      WHERE
        m.user_id=?

      ORDER BY
        c.league ASC
    `)
      .bind(
        userId
      )
      .all();

  return result.results;
}


/* =====================================================
   NÚMERO DE JUGADORES DEL CLAN
===================================================== */

async function getClanMemberCount(
  env,
  clanId
) {

  const row =
    await env.DB.prepare(`
      SELECT
        COUNT(*) AS total

      FROM members

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .first();

  return Number(
    row?.total || 0
  );
}


/* =====================================================
   MÍNIMO DE JUGADORES
===================================================== */

function minimumPlayers(
  league
) {

  if (
    Number(league) === 1
  ) {
    return 1;
  }

  return Number(league);
}


/* =====================================================
   MAPAS
===================================================== */

function randomMaps() {

  return [
    ...MAPS
  ]
    .sort(
      () =>
        Math.random() -
        0.5
    )
    .slice(
      0,
      3
    );
}


/* =====================================================
   CREAR NOTIFICACIÓN
===================================================== */

async function notify(
  env,
  userId,
  title,
  message,
  type = "general",
  relatedId = null
) {

  await env.DB.prepare(`
    INSERT INTO notifications
    (
      user_id,
      title,
      message,
      type,
      related_id
    )

    VALUES (?,?,?,?,?)
  `)
    .bind(
      userId,
      title,
      message,
      type,
      relatedId
    )
    .run();
}


/* =====================================================
   NOTIFICAR A TODOS LOS MIEMBROS DEL CLAN
===================================================== */

async function notifyClan(
  env,
  clanId,
  title,
  message,
  type,
  relatedId = null
) {

  const members =
    await env.DB.prepare(`
      SELECT
        user_id

      FROM members

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .all();

  for (
    const member
    of members.results
  ) {

    await notify(
      env,
      member.user_id,
      title,
      message,
      type,
      relatedId
    );

  }
}


/* =====================================================
   CADUCAR RETOS ABIERTOS
===================================================== */

async function expireChallenges(
  env
) {

  const now =
    new Date().toISOString();

  const expired =
    await env.DB.prepare(`
      SELECT
        id,
        creator_clan_id

      FROM challenges

      WHERE
        status='open'

        AND expires_at IS NOT NULL

        AND expires_at<=?
    `)
      .bind(
        now
      )
      .all();


  for (
    const challenge
    of expired.results
  ) {

    await env.DB.prepare(`
      UPDATE challenges

      SET
        status='expired',

        cancel_reason=
          'No aceptado en 30 minutos',

        cancelled_at=?

      WHERE
        id=?
    `)
      .bind(
        now,
        challenge.id
      )
      .run();


    await notifyClan(
      env,
      challenge.creator_clan_id,
      "⏰ Reto caducado",
      `El reto #${challenge.id} ha caducado porque ningún clan lo aceptó.`,
      "challenge_expired",
      challenge.id
    );

  }

}


/* =====================================================
   INICIO API
===================================================== */

async function api(
  request,
  env,
  path
) {

  const headers =
    cors(request);


  /* ===============================
     OPTIONS
  =============================== */

  if (
    request.method ===
    "OPTIONS"
  ) {

    return new Response(
      null,
      {
        status: 204,
        headers
      }
    );

  }


  /* ===============================
     BASE DE DATOS
  =============================== */

  await initDatabase(env);


  /* ===============================
     CADUCAR RETOS
  =============================== */

  await expireChallenges(
    env
  );


  /* ===============================
     ME
  =============================== */

  if (
    request.method === "GET" &&
    path === "/api/me"
  ) {

    const user =
      await getCurrentUser(
        request,
        env
      );

    if (!user) {

      return json(
        {
          user: null,
          admin: false,
          clans: []
        },
        200,
        headers
      );

    }

    const clans =
      await getUserClans(
        env,
        user.id
      );

    return json(
      {
        user,

        admin:
          isAdmin(user),

        clans
      },
      200,
      headers
    );

  }


  /* ===============================
     REGISTRO
  =============================== */

  if (
    request.method === "POST" &&
    path === "/api/register"
  ) {

    const data =
      await body(request);

    const username =
      String(
        data.username || ""
      )
        .trim();

    const password =
      String(
        data.password || ""
      );


    if (
      username.length < 3 ||
      username.length > 20
    ) {

      return json(
        {
          error:
            "El usuario debe tener entre 3 y 20 caracteres."
        },
        400,
        headers
      );

    }


    if (
      password.length < 6
    ) {

      return json(
        {
          error:
            "La contraseña debe tener al menos 6 caracteres."
        },
        400,
        headers
      );

    }


    const exists =
      await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE username=?
      `)
        .bind(
          username
        )
        .first();


    if (exists) {

      return json(
        {
          error:
            "Ese usuario ya existe."
        },
        400,
        headers
      );

    }


    const passwordHash =
      await hashPassword(
        password
      );


    const created =
      await env.DB.prepare(`
        INSERT INTO users
        (
          username,
          password_hash
        )

        VALUES (?,?)
      `)
        .bind(
          username,
          passwordHash
        )
        .run();


    const userId =
      created.meta.last_row_id;


    const token =
      crypto.randomUUID();


    await env.DB.prepare(`
      INSERT INTO sessions
      (
        token,
        user_id,
        expires
      )

      VALUES (?,?,?)
    `)
      .bind(
        token,
        userId,
        Date.now() +
          SESSION_DAYS *
          86400000
      )
      .run();


    return json(
      {
        ok: true,

        user: {
          id:
            userId,

          username
        },

        clans: []
      },
      200,
      {
        ...headers,

        "Set-Cookie":
          sessionCookie(
            token
          )
      }
    );

  }


  /* ===============================
     LOGIN
  =============================== */

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data =
      await body(request);

    const username =
      String(
        data.username || ""
      )
        .trim();

    const password =
      String(
        data.password || ""
      );


    const user =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE username=?
      `)
        .bind(
          username
        )
        .first();


    if (
      !user ||
      !await verifyPassword(
        password,
        user.password_hash
      )
    ) {

      return json(
        {
          error:
            "Usuario o contraseña incorrectos."
        },
        401,
        headers
      );

    }


    if (
      user.is_blocked &&
      (
        Number(
          user.blocked_until || 0
        ) === 0 ||

        Number(
          user.blocked_until
        ) > Date.now()
      )
    ) {

      return json(
        {
          error:
            "Usuario bloqueado."
        },
        403,
        headers
      );

    }


    const token =
      crypto.randomUUID();


    await env.DB.prepare(`
      INSERT INTO sessions
      (
        token,
        user_id,
        expires
      )

      VALUES (?,?,?)
    `)
      .bind(
        token,
        user.id,
        Date.now() +
          SESSION_DAYS *
          86400000
      )
      .run();


    const clans =
      await getUserClans(
        env,
        user.id
      );


    return json(
      {
        ok: true,

        user: {
          id:
            user.id,

          username:
            user.username,

          psn_id:
            user.psn_id,

          avatar_url:
            user.avatar_url
        },

        admin:
          isAdmin(user),

        clans
      },
      200,
      {
        ...headers,

        "Set-Cookie":
          sessionCookie(
            token
          )
      }
    );

  }


  /* ===============================
     LOGOUT
  =============================== */

  if (
    request.method === "POST" &&
    path === "/api/logout"
  ) {

    const token =
      getCookie(request);


    if (token) {

      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE token=?
      `)
        .bind(
          token
        )
        .run();

    }


    return json(
      {
        ok: true
      },
      200,
      {
        ...headers,

        "Set-Cookie":
          deleteSessionCookie()
      }
    );

  }


  /* ===============================
     USUARIO ACTUAL
  =============================== */

  const me =
    await getCurrentUser(
      request,
      env
    );


  /* ===============================
     RUTAS PÚBLICAS
  =============================== */

  const publicRoute =
    request.method === "GET" &&
    (
      path ===
        "/api/leaderboard" ||

      path ===
        "/api/clans" ||

      path ===
        "/api/users" ||

      /^\/api\/clans\/\d+$/
        .test(path) ||

      /^\/api\/users\/\d+$/
        .test(path)
    );


  if (
    !me &&
    !publicRoute
  ) {

    return json(
      {
        error:
          "Debes iniciar sesión."
      },
      401,
      headers
    );

  }


  /* ===============================
     BLOQUEO
  =============================== */

  if (
    me &&
    me.is_blocked &&
    (
      Number(
        me.blocked_until || 0
      ) === 0 ||

      Number(
        me.blocked_until
      ) > Date.now()
    )
  ) {

    return json(
      {
        error:
          "Usuario bloqueado."
      },
      403,
      headers
    );

  }


  /* ===============================
     FIN PARTE 1
  =============================== */
/* =====================================================
   PERFIL
===================================================== */

if (
  request.method === "PUT" &&
  path === "/api/profile"
) {

  const data =
    await body(request);

  const psn =
    String(
      data.psn_id || ""
    )
      .trim()
      .slice(0, 32);

  const avatar =
    String(
      data.avatar_url || ""
    )
      .trim()
      .slice(0, 500);

  const changingPsn =
    psn !==
    String(
      me.psn_id || ""
    );

  if (
    changingPsn &&
    !isAdmin(me) &&
    me.psn_changed_at &&
    Date.now() -
      Number(
        me.psn_changed_at
      ) <
      24 * 60 * 60 * 1000
  ) {

    return json(
      {
        error:
          "Solo puedes cambiar tu ID una vez cada 24 horas."
      },
      400,
      headers
    );

  }

  await env.DB.prepare(`
    UPDATE users

    SET
      psn_id=?,
      avatar_url=?,
      psn_changed_at=?

    WHERE id=?
  `)
    .bind(
      psn,

      avatar,

      changingPsn &&
      !isAdmin(me)
        ? Date.now()
        : (
            me.psn_changed_at ||
            null
          ),

      me.id
    )
    .run();

  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   USUARIOS
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/users"
) {

  const params =
    new URL(
      request.url
    ).searchParams;

  const query =
    String(
      params.get("q") || ""
    )
      .trim();


  const result =
    await env.DB.prepare(`
      SELECT

        id,

        username,

        psn_id,

        avatar_url,

        created_at

      FROM users

      WHERE
        username LIKE ?

      ORDER BY
        username ASC

      LIMIT 50
    `)
      .bind(
        "%" +
        query +
        "%"
      )
      .all();


  return json(
    result.results,
    200,
    headers
  );

}


/* =====================================================
   PERFIL PÚBLICO DE JUGADOR
   Incluye los clanes en los que está registrado.
===================================================== */

if (
  request.method === "GET" &&
  /^\/api\/users\/\d+$/
    .test(path)
) {

  const userId =
    Number(
      path.split("/").pop()
    );


  const user =
    await env.DB.prepare(`
      SELECT

        id,

        username,

        psn_id,

        avatar_url,

        created_at

      FROM users

      WHERE id=?
    `)
      .bind(
        userId
      )
      .first();


  if (!user) {

    return json(
      {
        error:
          "Jugador no encontrado."
      },
      404,
      headers
    );

  }


  const clans =
    await getUserClans(
      env,
      userId
    );


  return json(
    {
      user,

      clans
    },
    200,
    headers
  );

}


/* =====================================================
   CREAR CLAN
===================================================== */

if (
  request.method === "POST" &&
  path === "/api/clans"
) {

  const data =
    await body(request);


  const name =
    String(
      data.name || ""
    )
      .trim();


  const clanCode =
    String(
      data.clan_code || ""
    )
      .trim()
      .toUpperCase();


  const logoUrl =
    String(
      data.logo_url || ""
    )
      .trim()
      .slice(0, 500);


  const league =
    Number(
      data.league || 0
    );


  /* ===============================
     LIGA VÁLIDA
  =============================== */

  if (
    ![1,2,3,4].includes(
      league
    )
  ) {

    return json(
      {
        error:
          "Liga no válida."
      },
      400,
      headers
    );

  }


  /* ===============================
     NOMBRE
  =============================== */

  if (
    name.length < 2 ||
    name.length > 24
  ) {

    return json(
      {
        error:
          "El nombre del clan debe tener entre 2 y 24 caracteres."
      },
      400,
      headers
    );

  }


  /* ===============================
     INSIGNIA
  =============================== */

  if (
    !/^[A-Z]{4}$/.test(
      clanCode
    )
  ) {

    return json(
      {
        error:
          "La insignia debe tener exactamente 4 letras."
      },
      400,
      headers
    );

  }


  /* ===============================
     UN CLAN POR LIGA
     
     El mismo usuario puede estar:
     
     1 clan 1v1
     1 clan 2v2
     1 clan 3v3
     1 clan 4v4
  =============================== */

  const existingMembership =
    await getUserClan(
      env,
      me.id,
      league
    );


  if (
    existingMembership
  ) {

    return json(
      {
        error:
          "Ya perteneces a un clan en esta liga."
      },
      400,
      headers
    );

  }


  /* ===============================
     NOMBRE ÚNICO POR LIGA
  =============================== */

  const existingName =
    await env.DB.prepare(`
      SELECT id

      FROM clans

      WHERE
        LOWER(name)=LOWER(?)

        AND league=?
    `)
      .bind(
        name,
        league
      )
      .first();


  if (
    existingName
  ) {

    return json(
      {
        error:
          "Ese nombre ya existe en esa liga."
      },
      400,
      headers
    );

  }


  /* ===============================
     INSIGNIA ÚNICA
  =============================== */

  const existingCode =
    await env.DB.prepare(`
      SELECT id

      FROM clans

      WHERE
        UPPER(clan_code)=?
    `)
      .bind(
        clanCode
      )
      .first();


  if (
    existingCode
  ) {

    return json(
      {
        error:
          "Esa insignia ya está utilizada."
      },
      400,
      headers
    );

  }


  try {

    const created =
      await env.DB.prepare(`
        INSERT INTO clans
        (
          name,

          captain_id,

          league,

          clan_code,

          logo_url
        )

        VALUES (?,?,?,?,?)
      `)
        .bind(
          name,

          me.id,

          league,

          clanCode,

          logoUrl
        )
        .run();


    const clanId =
      created.meta.last_row_id;


    /* ===============================
       CAPITÁN
    =============================== */

    await env.DB.prepare(`
      INSERT INTO members
      (
        clan_id,

        user_id,

        role
      )

      VALUES (?,?,?)
    `)
      .bind(
        clanId,

        me.id,

        "captain"
      )
      .run();


    /* ===============================
       CLASIFICACIÓN
    =============================== */

    await env.DB.prepare(`
      INSERT OR IGNORE INTO scores
      (
        clan_id,

        league,

        points,

        wins,

        losses,

        played
      )

      VALUES (?, ?, 0, 0, 0, 0)
    `)
      .bind(
        clanId,

        league
      )
      .run();


    return json(
      {
        ok: true,

        clanId,

        clan: {
          id:
            clanId,

          name,

          clan_code:
            clanCode,

          league,

          captain_id:
            me.id,

          role:
            "captain"
        }
      },
      200,
      headers
    );


  } catch(error) {

    console.error(
      "CREATE CLAN ERROR",
      error
    );


    return json(
      {
        error:
          "No se pudo crear el clan.",

        detail:
          error.message
      },
      500,
      headers
    );

  }

}


/* =====================================================
   LISTADO DE CLANES
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/clans"
) {

  const params =
    new URL(
      request.url
    ).searchParams;


  const query =
    String(
      params.get("q") || ""
    )
      .trim();


  const league =
    Number(
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

      u.username
        AS captain_username,

      COALESCE(
        s.points,
        0
      ) AS points,

      COALESCE(
        s.wins,
        0
      ) AS wins,

      COALESCE(
        s.losses,
        0
      ) AS losses,

      COALESCE(
        s.played,
        0
      ) AS played,

      (
        SELECT COUNT(*)

        FROM members m

        WHERE
          m.clan_id=c.id

      ) AS member_count

    FROM clans c

    JOIN users u
      ON u.id=c.captain_id

    LEFT JOIN scores s
      ON s.clan_id=c.id

    WHERE
      c.name LIKE ?
  `;


  const values = [
    "%" +
    query +
    "%"
  ];


  if (
    [1,2,3,4].includes(
      league
    )
  ) {

    sql +=
      " AND c.league=?";

    values.push(
      league
    );

  }


  sql += `
    ORDER BY

      points DESC,

      wins DESC,

      name ASC

    LIMIT 200
  `;


  const result =
    await env.DB.prepare(
      sql
    )
      .bind(
        ...values
      )
      .all();


  return json(
    result.results,
    200,
    headers
  );

}


/* =====================================================
   CLAN INDIVIDUAL
===================================================== */

if (
  request.method === "GET" &&
  /^\/api\/clans\/\d+$/
    .test(path)
) {

  const clanId =
    Number(
      path.split("/").pop()
    );


  const clan =
    await env.DB.prepare(`
      SELECT

        c.*,

        u.username
          AS captain_username,

        COALESCE(
          s.points,
          0
        ) AS points,

        COALESCE(
          s.wins,
          0
        ) AS wins,

        COALESCE(
          s.losses,
          0
        ) AS losses,

        COALESCE(
          s.played,
          0
        ) AS played

      FROM clans c

      JOIN users u
        ON u.id=c.captain_id

      LEFT JOIN scores s
        ON s.clan_id=c.id

      WHERE
        c.id=?
    `)
      .bind(
        clanId
      )
      .first();


  if (!clan) {

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  const members =
    await env.DB.prepare(`
      SELECT

        u.id,

        u.username,

        u.psn_id,

        u.avatar_url,

        m.role,

        m.joined_at

      FROM members m

      JOIN users u
        ON u.id=m.user_id

      WHERE
        m.clan_id=?

      ORDER BY

        CASE

          WHEN m.role='captain'
          THEN 0

          ELSE 1

        END,

        u.username ASC
    `)
      .bind(
        clanId
      )
      .all();


  return json(
    {
      clan,

      members:
        members.results
    },
    200,
    headers
  );

}


/* =====================================================
   MIS CLANES
===================================================== */

if (
  request.method === "GET" &&
  (
    path === "/api/my-clans" ||

    path === "/api/me/clans"
  )
) {

  const clans =
    await getUserClans(
      env,
      me.id
    );


  for (
    const clan
    of clans
  ) {

    clan.member_count =
      await getClanMemberCount(
        env,
        clan.id
      );

  }


  return json(
    {
      clans
    },
    200,
    headers
  );

}


/* =====================================================
   INVITAR JUGADOR
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/clans\/\d+\/invite$/
    .test(path)
) {

  const clanId =
    Number(
      path.split("/")[3]
    );


  const data =
    await body(request);


  const targetUserId =
    Number(
      data.user_id || 0
    );


  const targetUsername =
    String(
      data.username || ""
    )
      .trim();


  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(
        clanId
      )
      .first();


  if (!clan) {

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if (
    Number(
      clan.captain_id
    ) !==
    Number(
      me.id
    )
  ) {

    return json(
      {
        error:
          "Solo el capitán puede invitar jugadores."
      },
      403,
      headers
    );

  }


  let targetUser = null;


  if (
    targetUserId
  ) {

    targetUser =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE id=?
      `)
        .bind(
          targetUserId
        )
        .first();

  } else if (
    targetUsername
  ) {

    targetUser =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE LOWER(username)=LOWER(?)
      `)
        .bind(
          targetUsername
        )
        .first();

  }


  if (!targetUser) {

    return json(
      {
        error:
          "Jugador no encontrado."
      },
      404,
      headers
    );

  }


  if (
    Number(
      targetUser.id
    ) ===
    Number(
      me.id
    )
  ) {

    return json(
      {
        error:
          "No puedes invitarte a ti mismo."
      },
      400,
      headers
    );

  }


  /* ===============================
     YA ESTÁ EN CLAN DE ESTA LIGA
  =============================== */

  const alreadyMember =
    await getUserClan(
      env,
      targetUser.id,
      clan.league
    );


  if (
    alreadyMember
  ) {

    return json(
      {
        error:
          "Ese jugador ya pertenece a un clan de esta liga."
      },
      400,
      headers
    );

  }


  /* ===============================
     INVITACIÓN PENDIENTE
  =============================== */

  const pending =
    await env.DB.prepare(`
      SELECT id

      FROM invites

      WHERE

        clan_id=?

        AND invitee_id=?

        AND status='pending'
    `)
      .bind(
        clanId,

        targetUser.id
      )
      .first();


  if (
    pending
  ) {

    return json(
      {
        error:
          "Ya tiene una invitación pendiente."
      },
      400,
      headers
    );

  }


  const created =
    await env.DB.prepare(`
      INSERT INTO invites
      (
        clan_id,

        inviter_id,

        invitee_id,

        status
      )

      VALUES (?,?,?,'pending')
    `)
      .bind(
        clanId,

        me.id,

        targetUser.id
      )
      .run();


  await notify(
    env,

    targetUser.id,

    "🛡️ Invitación a clan",

    `${me.username} te ha invitado al clan ${clan.name}.`,

    "clan_invite",

    created.meta.last_row_id
  );


  return json(
    {
      ok: true,

      inviteId:
        created.meta.last_row_id
    },
    200,
    headers
  );

}


/* =====================================================
   NOTIFICACIONES + INVITACIONES
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/notifications"
) {

  const notifications =
    await env.DB.prepare(`
      SELECT

        n.*,

        i.id
          AS invite_id,

        i.clan_id,

        i.status
          AS invite_status,

        c.name
          AS clan_name,

        c.clan_code,

        c.league,

        u.username
          AS inviter_username

      FROM notifications n

      LEFT JOIN invites i
        ON i.id=n.related_id

      LEFT JOIN clans c
        ON c.id=i.clan_id

      LEFT JOIN users u
        ON u.id=i.inviter_id

      WHERE
        n.user_id=?

      ORDER BY
        n.created_at DESC

      LIMIT 100
    `)
      .bind(
        me.id
      )
      .all();


  const invites =
    await env.DB.prepare(`
      SELECT

        i.id,

        i.clan_id,

        i.inviter_id,

        i.invitee_id,

        i.status,

        i.created_at,

        c.name
          AS clan_name,

        c.clan_code,

        c.league,

        c.logo_url,

        u.username
          AS inviter_username

      FROM invites i

      JOIN clans c
        ON c.id=i.clan_id

      JOIN users u
        ON u.id=i.inviter_id

      WHERE

        i.invitee_id=?

        AND i.status='pending'

      ORDER BY
        i.created_at DESC
    `)
      .bind(
        me.id
      )
      .all();


  return json(
    {
      notifications:
        notifications.results,

      invites:
        invites.results
    },
    200,
    headers
  );

}


/* =====================================================
   ACEPTAR INVITACIÓN
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/invites\/\d+\/accept$/
    .test(path)
) {

  const inviteId =
    Number(
      path.split("/")[3]
    );


  const invite =
    await env.DB.prepare(`
      SELECT

        i.*,

        c.name
          AS clan_name,

        c.league,

        c.captain_id

      FROM invites i

      JOIN clans c
        ON c.id=i.clan_id

      WHERE

        i.id=?

        AND i.invitee_id=?

        AND i.status='pending'
    `)
      .bind(
        inviteId,

        me.id
      )
      .first();


  if (!invite) {

    return json(
      {
        error:
          "Invitación no encontrada."
      },
      404,
      headers
    );

  }


  const existing =
    await getUserClan(
      env,
      me.id,
      invite.league
    );


  if (
    existing
  ) {

    return json(
      {
        error:
          "Ya perteneces a un clan de esta liga."
      },
      400,
      headers
    );

  }


  await env.DB.prepare(`
    INSERT INTO members
    (
      clan_id,

      user_id,

      role
    )

    VALUES (?,?,?)
  `)
    .bind(
      invite.clan_id,

      me.id,

      "member"
    )
    .run();


  await env.DB.prepare(`
    UPDATE invites

    SET
      status='accepted'

    WHERE
      id=?
  `)
    .bind(
      inviteId
    )
    .run();


  await env.DB.prepare(`
    UPDATE notifications

    SET
      is_read=1

    WHERE

      user_id=?

      AND related_id=?
  `)
    .bind(
      me.id,

      inviteId
    )
    .run();


  await notify(
    env,

    invite.captain_id,

    "👤 Nuevo jugador",

    `${me.username} ha aceptado la invitación al clan ${invite.clan_name}.`,

    "clan_member",

    invite.clan_id
  );


  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   RECHAZAR INVITACIÓN
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/invites\/\d+\/reject$/
    .test(path)
) {

  const inviteId =
    Number(
      path.split("/")[3]
    );


  const invite =
    await env.DB.prepare(`
      SELECT *

      FROM invites

      WHERE

        id=?

        AND invitee_id=?

        AND status='pending'
    `)
      .bind(
        inviteId,

        me.id
      )
      .first();


  if (!invite) {

    return json(
      {
        error:
          "Invitación no encontrada."
      },
      404,
      headers
    );

  }


  await env.DB.prepare(`
    UPDATE invites

    SET
      status='rejected'

    WHERE
      id=?
  `)
    .bind(
      inviteId
    )
    .run();


  await env.DB.prepare(`
    UPDATE notifications

    SET
      is_read=1

    WHERE

      user_id=?

      AND related_id=?
  `)
    .bind(
      me.id,

      inviteId
    )
    .run();


  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   LEER NOTIFICACIÓN
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/notifications\/\d+\/read$/
    .test(path)
) {

  const notificationId =
    Number(
      path.split("/")[3]
    );


  await env.DB.prepare(`
    UPDATE notifications

    SET
      is_read=1

    WHERE

      id=?

      AND user_id=?
  `)
    .bind(
      notificationId,

      me.id
    )
    .run();


  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   FIN PARTE 2
===================================================== */
/* =====================================================
   ABANDONAR CLAN
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/clans\/\d+\/leave$/.test(path)
) {

  const clanId =
    Number(
      path.split("/")[3]
    );

  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(clanId)
      .first();

  if (!clan) {
    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );
  }

  const membership =
    await env.DB.prepare(`
      SELECT *
      FROM members
      WHERE
        clan_id=?
        AND user_id=?
    `)
      .bind(
        clanId,
        me.id
      )
      .first();

  if (!membership) {
    return json(
      {
        error:
          "No perteneces a este clan."
      },
      400,
      headers
    );
  }

  if (
    Number(clan.captain_id) ===
    Number(me.id)
  ) {
    return json(
      {
        error:
          "El capitán no puede abandonar el clan. Debe eliminarlo o transferir el cargo."
      },
      400,
      headers
    );
  }

  await env.DB.prepare(`
    DELETE FROM members
    WHERE
      clan_id=?
      AND user_id=?
  `)
    .bind(
      clanId,
      me.id
    )
    .run();

  return json(
    {
      ok: true
    },
    200,
    headers
  );
}


/* =====================================================
   ELIMINAR CLAN
   Capitán o administrador
===================================================== */

if (
  request.method === "DELETE" &&
  /^\/api\/clans\/\d+$/.test(path)
) {

  const clanId =
    Number(
      path.split("/").pop()
    );

  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(clanId)
      .first();

  if (!clan) {
    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );
  }

  if (
    !isAdmin(me) &&
    Number(clan.captain_id) !==
      Number(me.id)
  ) {
    return json(
      {
        error:
          "Solo el capitán o el administrador pueden eliminar el clan."
      },
      403,
      headers
    );
  }

  /* Eliminar retos relacionados */

  const challenges =
    await env.DB.prepare(`
      SELECT id
      FROM challenges
      WHERE
        creator_clan_id=?
        OR accepter_clan_id=?
    `)
      .bind(
        clanId,
        clanId
      )
      .all();

  for (
    const challenge
    of challenges.results
  ) {

    await env.DB.prepare(`
      DELETE FROM reports
      WHERE challenge_id=?
    `)
      .bind(
        challenge.id
      )
      .run();

    await env.DB.prepare(`
      DELETE FROM chat_messages
      WHERE challenge_id=?
    `)
      .bind(
        challenge.id
      )
      .run();

  }

  await env.DB.prepare(`
    DELETE FROM challenges
    WHERE
      creator_clan_id=?
      OR accepter_clan_id=?
  `)
    .bind(
      clanId,
      clanId
    )
    .run();

  await env.DB.prepare(`
    DELETE FROM invites
    WHERE clan_id=?
  `)
    .bind(
      clanId
    )
    .run();

  await env.DB.prepare(`
    DELETE FROM members
    WHERE clan_id=?
  `)
    .bind(
      clanId
    )
    .run();

  await env.DB.prepare(`
    DELETE FROM scores
    WHERE clan_id=?
  `)
    .bind(
      clanId
    )
    .run();

  await env.DB.prepare(`
    DELETE FROM clans
    WHERE id=?
  `)
    .bind(
      clanId
    )
    .run();

  return json(
    {
      ok: true
    },
    200,
    headers
  );
}


/* =====================================================
   EDITAR CLAN
===================================================== */

if (
  request.method === "PUT" &&
  /^\/api\/clans\/\d+$/.test(path)
) {

  const clanId =
    Number(
      path.split("/").pop()
    );

  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(
        clanId
      )
      .first();

  if (!clan) {
    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );
  }

  if (
    !isAdmin(me) &&
    Number(clan.captain_id) !==
      Number(me.id)
  ) {
    return json(
      {
        error:
          "Solo el capitán o el administrador pueden modificar el clan."
      },
      403,
      headers
    );
  }

  const data =
    await body(request);

  const name =
    String(
      data.name ??
      clan.name
    )
      .trim();

  const clanCode =
    String(
      data.clan_code ??
      clan.clan_code ??
      ""
    )
      .trim()
      .toUpperCase();

  const logoUrl =
    String(
      data.logo_url ??
      clan.logo_url ??
      ""
    )
      .trim()
      .slice(0,500);

  if (
    name.length < 2 ||
    name.length > 24
  ) {
    return json(
      {
        error:
          "El nombre debe tener entre 2 y 24 caracteres."
      },
      400,
      headers
    );
  }

  if (
    !/^[A-Z]{4}$/.test(
      clanCode
    )
  ) {
    return json(
      {
        error:
          "La insignia debe tener exactamente 4 letras."
      },
      400,
      headers
    );
  }

  const duplicateName =
    await env.DB.prepare(`
      SELECT id
      FROM clans
      WHERE
        LOWER(name)=LOWER(?)
        AND league=?
        AND id!=?
    `)
      .bind(
        name,
        clan.league,
        clanId
      )
      .first();

  if (duplicateName) {
    return json(
      {
        error:
          "Ese nombre ya existe en esta liga."
      },
      400,
      headers
    );
  }

  const duplicateCode =
    await env.DB.prepare(`
      SELECT id
      FROM clans
      WHERE
        UPPER(clan_code)=?
        AND id!=?
    `)
      .bind(
        clanCode,
        clanId
      )
      .first();

  if (duplicateCode) {
    return json(
      {
        error:
          "Esa insignia ya está utilizada."
      },
      400,
      headers
    );
  }

  await env.DB.prepare(`
    UPDATE clans

    SET
      name=?,
      clan_code=?,
      logo_url=?

    WHERE id=?
  `)
    .bind(
      name,
      clanCode,
      logoUrl,
      clanId
    )
    .run();

  return json(
    {
      ok: true
    },
    200,
    headers
  );
}


/* =====================================================
   EXPULSAR JUGADOR
===================================================== */

if (
  request.method === "DELETE" &&
  /^\/api\/clans\/\d+\/members\/\d+$/.test(path)
) {

  const parts =
    path.split("/");

  const clanId =
    Number(parts[3]);

  const userId =
    Number(parts[5]);

  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(
        clanId
      )
      .first();

  if (!clan) {
    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );
  }

  if (
    !isAdmin(me) &&
    Number(clan.captain_id) !==
      Number(me.id)
  ) {
    return json(
      {
        error:
          "Solo el capitán o el administrador pueden expulsar jugadores."
      },
      403,
      headers
    );
  }

  if (
    Number(userId) ===
    Number(clan.captain_id)
  ) {
    return json(
      {
        error:
          "No puedes expulsar al capitán."
      },
      400,
      headers
    );
  }

  const member =
    await env.DB.prepare(`
      SELECT *
      FROM members
      WHERE
        clan_id=?
        AND user_id=?
    `)
      .bind(
        clanId,
        userId
      )
      .first();

  if (!member) {
    return json(
      {
        error:
          "Ese jugador no pertenece al clan."
      },
      400,
      headers
    );
  }

  await env.DB.prepare(`
    DELETE FROM members
    WHERE
      clan_id=?
      AND user_id=?
  `)
    .bind(
      clanId,
      userId
    )
    .run();

  await notify(
    env,
    userId,
    "🚫 Has salido del clan",
    `Has sido expulsado del clan ${clan.name}.`,
    "clan_removed",
    clanId
  );

  return json(
    {
      ok: true
    },
    200,
    headers
  );
}


/* =====================================================
   CREAR RETO
===================================================== */

if (
  request.method === "POST" &&
  path === "/api/challenges"
) {

  const data =
    await body(request);

  const league =
    Number(
      data.league ||
      data.team_size ||
      4
    );

  if (
    ![1,2,3,4].includes(
      league
    )
  ) {
    return json(
      {
        error:
          "Liga no válida."
      },
      400,
      headers
    );
  }

  const clan =
    await getUserClan(
      env,
      me.id,
      league
    );

  if (!clan) {
    return json(
      {
        error:
          "Necesitas tener un clan en esta liga."
      },
      400,
      headers
    );
  }

  /* =========================================
     COMPROBAR MÍNIMO DE JUGADORES
  ========================================= */

  const memberCount =
    await getClanMemberCount(
      env,
      clan.id
    );

  const minimum =
    minimumPlayers(
      league
    );

  if (
    memberCount <
    minimum
  ) {
    return json(
      {
        error:
          `Tu clan necesita al menos ${minimum} jugador${minimum === 1 ? "" : "es"} inscrito${minimum === 1 ? "" : "s"} para poder poner un reto.`
      },
      400,
      headers
    );
  }

  /* =========================================
     NO MÁS DE UN RETO ABIERTO
  ========================================= */

  const active =
    await env.DB.prepare(`
      SELECT id
      FROM challenges

      WHERE

        creator_clan_id=?

        AND status='open'
    `)
      .bind(
        clan.id
      )
      .first();

  if (active) {
    return json(
      {
        error:
          "Tu clan ya tiene un reto abierto."
      },
      400,
      headers
    );
  }

  /* =========================================
     1V1
  ========================================= */

  let maps = [
    null,
    null,
    null
  ];

  let oneVsOneMode =
    null;

  let gameModes =
    ["snd"];

  if (
    league === 1
  ) {

    const mode =
      String(
        data.one_vs_one_mode ||
        data.mode ||
        ""
      )
        .trim()
        .toLowerCase();

    if (
      ![
        "franco",
        "arma"
      ].includes(
        mode
      )
    ) {
      return json(
        {
          error:
            "En 1v1 debes elegir Franco o Arma."
        },
        400,
        headers
      );
    }

    oneVsOneMode =
      mode;

    maps = [
      ONE_VS_ONE_MAP,
      ONE_VS_ONE_MAP,
      ONE_VS_ONE_MAP
    ];

    gameModes = [
      mode
    ];

  } else {

    maps =
      randomMaps();

    const requestedMode =
      String(
        data.mode ||
        "snd"
      )
        .trim()
        .toLowerCase();

    gameModes = [
      requestedMode
    ];

  }

  /* =========================================
     EXPIRACIÓN 30 MINUTOS
  ========================================= */

  const createdAt =
    new Date();

  const expiresAt =
    new Date(
      createdAt.getTime() +
      30 * 60 * 1000
    );

  /* =========================================
     CREAR
  ========================================= */

  const created =
    await env.DB.prepare(`
      INSERT INTO challenges
      (
        creator_clan_id,

        status,

        league,

        team_size,

        game_modes,

        map1,

        map2,

        map3,

        one_vs_one_mode,

        scheduled_at,

        expires_at,

        created_at
      )

      VALUES
      (
        ?,
        'open',
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?
      )
    `)
      .bind(

        clan.id,

        league,

        league === 1
          ? 1
          : league,

        JSON.stringify(
          gameModes
        ),

        maps[0],

        maps[1],

        maps[2],

        oneVsOneMode,

        data.scheduled_at ||
          null,

        expiresAt.toISOString(),

        createdAt.toISOString()

      )
      .run();

  const challengeId =
    created.meta.last_row_id;

  return json(
    {
      ok: true,

      challengeId,

      challenge: {
        id:
          challengeId,

        creator_clan_id:
          clan.id,

        creator_clan_name:
          clan.name,

        league,

        team_size:
          league === 1
            ? 1
            : league,

        map1:
          maps[0],

        map2:
          maps[1],

        map3:
          maps[2],

        one_vs_one_mode:
          oneVsOneMode,

        game_modes:
          gameModes,

        status:
          "open",

        expires_at:
          expiresAt.toISOString()
      }
    },
    200,
    headers
  );
}


/* =====================================================
   LISTADO DE RETOS DISPONIBLES
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/challenges"
) {

  const params =
    new URL(
      request.url
    ).searchParams;

  const league =
    Number(
      params.get("league") || 0
    );


  /*
     IMPORTANTE:

     NO devolvemos todos los retos
     a todos los usuarios.

     Solo devolvemos retos que:
     - estén abiertos
     - sean de una liga donde
       el usuario tenga clan
     - NO sean de su propio clan
     - tengan suficientes jugadores
  */


  if (
    ![1,2,3,4].includes(
      league
    )
  ) {
    return json(
      [],
      200,
      headers
    );
  }


  const myClan =
    await getUserClan(
      env,
      me.id,
      league
    );


  if (!myClan) {
    return json(
      [],
      200,
      headers
    );
  }


  const myCount =
    await getClanMemberCount(
      env,
      myClan.id
    );


  if (
    myCount <
    minimumPlayers(
      league
    )
  ) {
    return json(
      [],
      200,
      headers
    );
  }


  const result =
    await env.DB.prepare(`
      SELECT

        ch.id,

        ch.status,

        ch.league,

        ch.team_size,

        ch.game_modes,

        ch.map1,

        ch.map2,

        ch.map3,

        ch.one_vs_one_mode,

        ch.created_at,

        ch.expires_at,

        ch.creator_clan_id,

        c.name
          AS creator_clan_name,

        c.clan_code
          AS creator_clan_code,

        c.logo_url
          AS creator_clan_logo,

        (
          SELECT COUNT(*)

          FROM members mm

          WHERE
            mm.clan_id=
            c.id

        ) AS creator_member_count

      FROM challenges ch

      JOIN clans c
        ON c.id=
           ch.creator_clan_id

      WHERE

        ch.status='open'

        AND ch.league=?

        AND ch.creator_clan_id!=?

        AND ch.expires_at>?

      ORDER BY
        ch.created_at DESC

      LIMIT 100
    `)
      .bind(
        league,

        myClan.id,

        new Date()
          .toISOString()
      )
      .all();


  const challenges =
    result.results
      .filter(
        challenge =>
          Number(
            challenge.creator_member_count
          ) >=
          minimumPlayers(
            league
          )
      )
      .map(
        challenge => ({
          ...challenge,

          game_modes:
            JSON.parse(
              challenge.game_modes ||
              "[]"
            )
        })
      );


  return json(
    challenges,
    200,
    headers
  );
}


/* =====================================================
   MIS RETOS
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/my-challenges"
) {

  const result =
    await env.DB.prepare(`
      SELECT

        ch.id,

        ch.status,

        ch.league,

        ch.team_size,

        ch.game_modes,

        ch.map1,

        ch.map2,

        ch.map3,

        ch.one_vs_one_mode,

        ch.created_at,

        ch.expires_at,

        ch.completed_at,

        ch.winner_clan_id,

        ch.cancel_reason,

        creator.id
          AS creator_clan_id,

        creator.name
          AS creator_clan_name,

        creator.clan_code
          AS creator_clan_code,

        creator.logo_url
          AS creator_clan_logo,

        accepter.id
          AS accepter_clan_id,

        accepter.name
          AS accepter_clan_name,

        accepter.clan_code
          AS accepter_clan_code,

        accepter.logo_url
          AS accepter_clan_logo

      FROM challenges ch

      JOIN members mymember
        ON
          (
            mymember.clan_id=
              ch.creator_clan_id

            OR

            mymember.clan_id=
              ch.accepter_clan_id
          )

        AND mymember.user_id=?

      JOIN clans creator
        ON creator.id=
           ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id=
           ch.accepter_clan_id

      WHERE
        ch.status IN
        (
          'open',
          'accepted',
          'completed',
          'cancelled',
          'expired'
        )

      ORDER BY
        ch.created_at DESC

      LIMIT 200
    `)
      .bind(
        me.id
      )
      .all();


  return json(
    result.results.map(
      challenge => ({
        ...challenge,

        game_modes:
          JSON.parse(
            challenge.game_modes ||
            "[]"
          )
      })
    ),
    200,
    headers
  );
}


/* =====================================================
   ACEPTAR RETO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/accept$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const challenge =
    await env.DB.prepare(`
      SELECT

        ch.*,

        c.name
          AS creator_clan_name,

        c.clan_code
          AS creator_clan_code,

        c.logo_url
          AS creator_clan_logo

      FROM challenges ch

      JOIN clans c
        ON c.id=
           ch.creator_clan_id

      WHERE
        ch.id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if (!challenge) {
    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );
  }


  if (
    challenge.status !==
    "open"
  ) {
    return json(
      {
        error:
          "Este reto ya no está disponible."
      },
      400,
      headers
    );
  }


  if (
    challenge.expires_at &&
    challenge.expires_at <=
      new Date().toISOString()
  ) {

    await env.DB.prepare(`
      UPDATE challenges

      SET
        status='expired',

        cancel_reason=
          'No aceptado en 30 minutos',

        cancelled_at=?

      WHERE id=?
    `)
      .bind(
        new Date().toISOString(),
        challengeId
      )
      .run();

    return json(
      {
        error:
          "Este reto ha caducado."
      },
      400,
      headers
    );
  }


  const myClan =
    await getUserClan(
      env,
      me.id,
      challenge.league
    );


  if (!myClan) {
    return json(
      {
        error:
          "No tienes clan en esta liga."
      },
      400,
      headers
    );
  }


  if (
    Number(myClan.id) ===
    Number(
      challenge.creator_clan_id
    )
  ) {
    return json(
      {
        error:
          "No puedes aceptar tu propio reto."
      },
      400,
      headers
    );
  }


  const memberCount =
    await getClanMemberCount(
      env,
      myClan.id
    );


  if (
    memberCount <
    minimumPlayers(
      challenge.league
    )
  ) {
    return json(
      {
        error:
          `Tu clan necesita al menos ${minimumPlayers(challenge.league)} jugador${minimumPlayers(challenge.league) === 1 ? "" : "es"} para aceptar el reto.`
      },
      400,
      headers
    );
  }


  const update =
    await env.DB.prepare(`
      UPDATE challenges

      SET

        accepter_clan_id=?,

        status='accepted'

      WHERE

        id=?

        AND status='open'
    `)
      .bind(
        myClan.id,

        challengeId
      )
      .run();


  if (
    !update.success &&
    update.meta?.changes === 0
  ) {
    return json(
      {
        error:
          "El reto ya ha sido aceptado por otro clan."
      },
      409,
      headers
    );
  }


  await notifyClan(
    env,

    challenge.creator_clan_id,

    "⚔️ Reto aceptado",

    `${myClan.name} ha aceptado tu reto.`,

    "challenge_accepted",

    challengeId
  );


  await notifyClan(
    env,

    myClan.id,

    "⚔️ Reto aceptado",

    `Has aceptado el reto contra ${challenge.creator_clan_name}.`,

    "challenge_accepted",

    challengeId
  );


  return json(
    {
      ok: true,

      challenge: {
        ...challenge,

        accepter_clan_id:
          myClan.id,

        accepter_clan_name:
          myClan.name,

        accepter_clan_code:
          myClan.clan_code,

        status:
          "accepted",

        game_modes:
          JSON.parse(
            challenge.game_modes ||
            "[]"
          )
      }
    },
    200,
    headers
  );
}


/* =====================================================
   FIN PARTE 3
===================================================== */
/* =====================================================
   CANCELAR RETO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/cancel$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );

  const challenge =
    await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
    `)
      .bind(
        challengeId
      )
      .first();

  if (!challenge) {

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }

  const myClan =
    await getUserClan(
      env,
      me.id,
      challenge.league
    );

  if (
    !isAdmin(me) &&
    (
      !myClan ||
      Number(myClan.id) !==
        Number(
          challenge.creator_clan_id
        )
    )
  ) {

    return json(
      {
        error:
          "Solo el clan que publicó el reto o el administrador puede cancelarlo."
      },
      403,
      headers
    );

  }

  if (
    challenge.status !==
    "open"
  ) {

    return json(
      {
        error:
          "Este reto ya no está abierto."
      },
      400,
      headers
    );

  }

  const now =
    new Date().toISOString();

  await env.DB.prepare(`
    UPDATE challenges

    SET
      status='cancelled',

      cancel_reason=
        'Cancelado por el clan',

      cancelled_at=?

    WHERE id=?
  `)
    .bind(
      now,
      challengeId
    )
    .run();


  await notifyClan(
    env,

    challenge.creator_clan_id,

    "❌ Reto cancelado",

    `El reto #${challengeId} ha sido cancelado.`,

    "challenge_cancelled",

    challengeId
  );


  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   VER RETO INDIVIDUAL
===================================================== */

if (
  request.method === "GET" &&
  /^\/api\/challenges\/\d+$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const challenge =
    await env.DB.prepare(`
      SELECT

        ch.*,

        creator.name
          AS creator_clan_name,

        creator.clan_code
          AS creator_clan_code,

        creator.logo_url
          AS creator_clan_logo,

        accepter.name
          AS accepter_clan_name,

        accepter.clan_code
          AS accepter_clan_code,

        accepter.logo_url
          AS accepter_clan_logo

      FROM challenges ch

      JOIN clans creator
        ON creator.id=
           ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id=
           ch.accepter_clan_id

      WHERE
        ch.id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if (!challenge) {

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  /* Solo participantes o admin */

  const participant =
    await env.DB.prepare(`
      SELECT 1

      FROM members

      WHERE
        user_id=?

        AND
        (
          clan_id=?
          OR
          clan_id=?
        )

      LIMIT 1
    `)
      .bind(
        me.id,

        challenge.creator_clan_id,

        challenge.accepter_clan_id ||
          0
      )
      .first();


  if (
    !participant &&
    !isAdmin(me)
  ) {

    return json(
      {
        error:
          "No tienes acceso a este reto."
      },
      403,
      headers
    );

  }


  const reports =
    await env.DB.prepare(`
      SELECT

        r.id,

        r.clan_id,

        r.winner_clan_id,

        r.created_at,

        c.name
          AS clan_name

      FROM reports r

      JOIN clans c
        ON c.id=r.clan_id

      WHERE
        r.challenge_id=?

      ORDER BY
        r.created_at ASC
    `)
      .bind(
        challengeId
      )
      .all();


  return json(
    {
      ...challenge,

      game_modes:
        JSON.parse(
          challenge.game_modes ||
          "[]"
        ),

      reports:
        reports.results
    },
    200,
    headers
  );

}


/* =====================================================
   PUBLICAR RESULTADO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/report$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const data =
    await body(request);


  const winnerClanId =
    Number(
      data.winner_clan_id
    );


  const challenge =
    await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if (!challenge) {

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  if (
    challenge.status !==
    "accepted"
  ) {

    return json(
      {
        error:
          "El reto no está activo."
      },
      400,
      headers
    );

  }


  const myClan =
    await getUserClan(
      env,
      me.id,
      challenge.league
    );


  if (!myClan) {

    return json(
      {
        error:
          "No perteneces a un clan de esta liga."
      },
      400,
      headers
    );

  }


  const creatorId =
    Number(
      challenge.creator_clan_id
    );

  const accepterId =
    Number(
      challenge.accepter_clan_id
    );


  if (
    Number(myClan.id) !==
      creatorId &&
    Number(myClan.id) !==
      accepterId
  ) {

    return json(
      {
        error:
          "Tu clan no participa en este reto."
      },
      403,
      headers
    );

  }


  if (
    winnerClanId !==
      creatorId &&
    winnerClanId !==
      accepterId
  ) {

    return json(
      {
        error:
          "Debes seleccionar uno de los dos clanes."
      },
      400,
      headers
    );

  }


  /* =========================================
     NO PERMITIR DOS REPORTES DEL MISMO CLAN
  ========================================= */

  const existing =
    await env.DB.prepare(`
      SELECT id

      FROM reports

      WHERE
        challenge_id=?

        AND clan_id=?
    `)
      .bind(
        challengeId,

        myClan.id
      )
      .first();


  if (existing) {

    return json(
      {
        error:
          "Tu clan ya ha publicado su resultado."
      },
      400,
      headers
    );

  }


  await env.DB.prepare(`
    INSERT INTO reports
    (
      challenge_id,

      clan_id,

      winner_clan_id
    )

    VALUES (?,?,?)
  `)
    .bind(
      challengeId,

      myClan.id,

      winnerClanId
    )
    .run();


  /* =========================================
     COMPROBAR SI LOS DOS COINCIDEN
  ========================================= */

  const reports =
    await env.DB.prepare(`
      SELECT

        clan_id,

        winner_clan_id

      FROM reports

      WHERE
        challenge_id=?
    `)
      .bind(
        challengeId
      )
      .all();


  const rows =
    reports.results;


  if (
    rows.length >= 2
  ) {

    const firstWinner =
      Number(
        rows[0].winner_clan_id
      );

    const secondWinner =
      Number(
        rows[1].winner_clan_id
      );


    if (
      firstWinner ===
      secondWinner
    ) {

      const winnerId =
        firstWinner;

      const loserId =
        winnerId === creatorId
          ? accepterId
          : creatorId;


      await finishChallenge(
        env,

        challenge,

        winnerId,

        loserId
      );


      return json(
        {
          ok: true,

          completed: true,

          winner_clan_id:
            winnerId
        },
        200,
        headers
      );

    }

    /* Resultados diferentes */

    await notifyClan(
      env,

      creatorId,

      "⚠️ Resultado diferente",

      `Los resultados publicados para el reto #${challengeId} no coinciden.`,

      "result_conflict",

      challengeId
    );


    await notifyClan(
      env,

      accepterId,

      "⚠️ Resultado diferente",

      `Los resultados publicados para el reto #${challengeId} no coinciden.`,

      "result_conflict",

      challengeId
    );

  }


  /* =========================================
     AVISAR AL RIVAL
  ========================================= */

  const opponentClanId =
    Number(myClan.id) ===
      creatorId
      ? accepterId
      : creatorId;


  await notifyClan(
    env,

    opponentClanId,

    "📋 Resultado publicado",

    `${myClan.name} ha publicado el resultado del reto #${challengeId}.`,

    "result_reported",

    challengeId
  );


  return json(
    {
      ok: true,

      completed: false,

      message:
        "Resultado guardado. Falta la confirmación del rival."
    },
    200,
    headers
  );

}


/* =====================================================
   FUNCIÓN FINALIZAR RETO
===================================================== */

async function finishChallenge(
  env,
  challenge,
  winnerId,
  loserId
) {

  const now =
    new Date().toISOString();


  await env.DB.prepare(`
    UPDATE challenges

    SET

      status='completed',

      winner_clan_id=?,

      completed_at=?

    WHERE id=?
  `)
    .bind(
      winnerId,

      now,

      challenge.id
    )
    .run();


  await updateScore(
    env,

    winnerId,

    true,

    challenge.league
  );


  await updateScore(
    env,

    loserId,

    false,

    challenge.league
  );


  await notifyClan(
    env,

    winnerId,

    "🏆 Victoria",

    `Tu clan ha ganado el reto #${challenge.id}.`,

    "challenge_result",

    challenge.id
  );


  await notifyClan(
    env,

    loserId,

    "❌ Derrota",

    `Tu clan ha perdido el reto #${challenge.id}.`,

    "challenge_result",

    challenge.id
  );

}


/* =====================================================
   PUNTUACIÓN
===================================================== */

async function updateScore(
  env,
  clanId,
  won,
  league
) {

  await env.DB.prepare(`
    INSERT OR IGNORE INTO scores
    (
      clan_id,

      league,

      points,

      wins,

      losses,

      played
    )

    VALUES
    (
      ?,
      ?,
      0,
      0,
      0,
      0
    )
  `)
    .bind(
      clanId,

      league
    )
    .run();


  if (won) {

    await env.DB.prepare(`
      UPDATE scores

      SET

        points=
          points+3,

        wins=
          wins+1,

        played=
          played+1

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  } else {

    await env.DB.prepare(`
      UPDATE scores

      SET

        losses=
          losses+1,

        played=
          played+1

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }

}


/* =====================================================
   RANKING
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/leaderboard"
) {

  const params =
    new URL(
      request.url
    ).searchParams;


  const league =
    Number(
      params.get("league") || 4
    );


  if (
    ![1,2,3,4].includes(
      league
    )
  ) {

    return json(
      [],
      200,
      headers
    );

  }


  const result =
    await env.DB.prepare(`
      SELECT

        c.id,

        c.name,

        c.clan_code,

        c.logo_url,

        c.league,

        COALESCE(
          s.points,
          0
        ) AS points,

        COALESCE(
          s.wins,
          0
        ) AS wins,

        COALESCE(
          s.losses,
          0
        ) AS losses,

        COALESCE(
          s.played,
          0
        ) AS played,

        (
          SELECT COUNT(*)

          FROM members m

          WHERE
            m.clan_id=c.id

        ) AS member_count

      FROM clans c

      LEFT JOIN scores s
        ON s.clan_id=c.id

      WHERE
        c.league=?

      ORDER BY

        points DESC,

        wins DESC,

        losses ASC,

        c.name ASC
    `)
      .bind(
        league
      )
      .all();


  return json(
    result.results,
    200,
    headers
  );

}


/* =====================================================
   HISTORIAL DE RETOS
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/history"
) {

  const result =
    await env.DB.prepare(`
      SELECT

        ch.id,

        ch.status,

        ch.league,

        ch.team_size,

        ch.map1,

        ch.map2,

        ch.map3,

        ch.one_vs_one_mode,

        ch.created_at,

        ch.completed_at,

        ch.winner_clan_id,

        creator.id
          AS creator_clan_id,

        creator.name
          AS creator_clan_name,

        accepter.id
          AS accepter_clan_id,

        accepter.name
          AS accepter_clan_name

      FROM challenges ch

      JOIN members mine
        ON
          (
            mine.clan_id=
              ch.creator_clan_id

            OR

            mine.clan_id=
              ch.accepter_clan_id
          )

        AND mine.user_id=?

      JOIN clans creator
        ON creator.id=
           ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id=
           ch.accepter_clan_id

      WHERE
        ch.status='completed'

      ORDER BY
        ch.completed_at DESC

      LIMIT 200
    `)
      .bind(
        me.id
      )
      .all();


  return json(
    result.results,
    200,
    headers
  );

}


/* =====================================================
   CHAT DE RETO
===================================================== */

if (
  request.method === "GET" &&
  /^\/api\/challenges\/\d+\/chat$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const challenge =
    await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if (!challenge) {

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  const participant =
    await env.DB.prepare(`
      SELECT 1

      FROM members

      WHERE

        user_id=?

        AND
        (
          clan_id=?
          OR
          clan_id=?
        )

      LIMIT 1
    `)
      .bind(
        me.id,

        challenge.creator_clan_id,

        challenge.accepter_clan_id ||
          0
      )
      .first();


  if (
    !participant &&
    !isAdmin(me)
  ) {

    return json(
      {
        error:
          "No tienes acceso al chat."
      },
      403,
      headers
    );

  }


  const messages =
    await env.DB.prepare(`
      SELECT

        cm.id,

        cm.message,

        cm.created_at,

        u.id
          AS user_id,

        u.username

      FROM chat_messages cm

      JOIN users u
        ON u.id=cm.user_id

      WHERE
        cm.challenge_id=?

      ORDER BY
        cm.created_at ASC

      LIMIT 300
    `)
      .bind(
        challengeId
      )
      .all();


  return json(
    messages.results,
    200,
    headers
  );

}


if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/chat$/
    .test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const data =
    await body(request);


  const message =
    String(
      data.message || ""
    )
      .trim()
      .slice(0,500);


  if (!message) {

    return json(
      {
        error:
          "Mensaje vacío."
      },
      400,
      headers
    );

  }


  const challenge =
    await env.DB.prepare(`
      SELECT *
      FROM challenges
      WHERE id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if (!challenge) {

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  const myClan =
    await getUserClan(
      env,
      me.id,
      challenge.league
    );


  if (
    !myClan ||
    (
      Number(myClan.id) !==
        Number(
          challenge.creator_clan_id
        ) &&

      Number(myClan.id) !==
        Number(
          challenge.accepter_clan_id
        )
    )
  ) {

    return json(
      {
        error:
          "No participas en este reto."
      },
      403,
      headers
    );

  }


  await env.DB.prepare(`
    INSERT INTO chat_messages
    (
      challenge_id,

      user_id,

      message
    )

    VALUES (?,?,?)
  `)
    .bind(
      challengeId,

      me.id,

      message
    )
    .run();


  return json(
    {
      ok: true
    },
    200,
    headers
  );

}


/* =====================================================
   ADMIN — USUARIOS
===================================================== */

if (
  path.startsWith(
    "/api/admin/"
  )
) {

  if (
    !isAdmin(me)
  ) {

    return json(
      {
        error:
          "Acceso de administrador requerido."
      },
      403,
      headers
    );

  }


  /* =========================================
     LISTAR USUARIOS
  ========================================= */

  if (
    request.method === "GET" &&
    path === "/api/admin/users"
  ) {

    const users =
      await env.DB.prepare(`
        SELECT

          id,

          username,

          psn_id,

          avatar_url,

          is_blocked,

          blocked_until,

          created_at

        FROM users

        ORDER BY
          created_at DESC

        LIMIT 500
      `)
        .all();


    return json(
      users.results,
      200,
      headers
    );

  }


  /* =========================================
     BLOQUEAR
  ========================================= */

  if (
    request.method === "POST" &&
    /^\/api\/admin\/users\/\d+\/block$/
      .test(path)
  ) {

    const userId =
      Number(
        path.split("/")[4]
      );


    await env.DB.prepare(`
      UPDATE users

      SET
        is_blocked=1,

        blocked_until=0

      WHERE id=?
    `)
      .bind(
        userId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM sessions

      WHERE
        user_id=?
    `)
      .bind(
        userId
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     DESBLOQUEAR
  ========================================= */

  if (
    request.method === "POST" &&
    /^\/api\/admin\/users\/\d+\/unblock$/
      .test(path)
  ) {

    const userId =
      Number(
        path.split("/")[4]
      );


    await env.DB.prepare(`
      UPDATE users

      SET

        is_blocked=0,

        blocked_until=NULL

      WHERE id=?
    `)
      .bind(
        userId
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     BORRAR USUARIO
  ========================================= */

  if (
    request.method === "DELETE" &&
    /^\/api\/admin\/users\/\d+$/
      .test(path)
  ) {

    const userId =
      Number(
        path.split("/").pop()
      );


    if (
      Number(userId) ===
      Number(me.id)
    ) {

      return json(
        {
          error:
            "No puedes borrar tu propia cuenta de administrador."
        },
        400,
        headers
      );

    }


    const clans =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE captain_id=?
      `)
        .bind(
          userId
        )
        .all();


    for (
      const clan
      of clans.results
    ) {

      await deleteClanData(
        env,
        clan.id
      );

    }


    await env.DB.prepare(`
      DELETE FROM invites

      WHERE
        inviter_id=?
        OR invitee_id=?
    `)
      .bind(
        userId,

        userId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM notifications

      WHERE
        user_id=?
    `)
      .bind(
        userId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM sessions

      WHERE
        user_id=?
    `)
      .bind(
        userId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM users

      WHERE id=?
    `)
      .bind(
        userId
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     LISTAR CLANES ADMIN
  ========================================= */

  if (
    request.method === "GET" &&
    path === "/api/admin/clans"
  ) {

    const clans =
      await env.DB.prepare(`
        SELECT

          c.*,

          u.username
            AS captain_username,

          (
            SELECT COUNT(*)

            FROM members m

            WHERE
              m.clan_id=c.id

          ) AS member_count

        FROM clans c

        JOIN users u
          ON u.id=c.captain_id

        ORDER BY
          c.league ASC,

          c.name ASC

        LIMIT 500
      `)
        .all();


    return json(
      clans.results,
      200,
      headers
    );

  }


  /* =========================================
     BORRAR CLAN ADMIN
  ========================================= */

  if (
    request.method === "DELETE" &&
    /^\/api\/admin\/clans\/\d+$/
      .test(path)
  ) {

    const clanId =
      Number(
        path.split("/")[4]
      );


    await deleteClanData(
      env,
      clanId
    );


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     RETOS ADMIN
  ========================================= */

  if (
    request.method === "GET" &&
    path === "/api/admin/challenges"
  ) {

    const challenges =
      await env.DB.prepare(`
        SELECT

          ch.*,

          creator.name
            AS creator_clan_name,

          accepter.name
            AS accepter_clan_name

        FROM challenges ch

        JOIN clans creator
          ON creator.id=
             ch.creator_clan_id

        LEFT JOIN clans accepter
          ON accepter.id=
             ch.accepter_clan_id

        ORDER BY
          ch.created_at DESC

        LIMIT 500
      `)
        .all();


    return json(
      challenges.results,
      200,
      headers
    );

  }


  /* =========================================
     CANCELAR RETO ADMIN
  ========================================= */

  if (
    request.method === "DELETE" &&
    /^\/api\/admin\/challenges\/\d+$/
      .test(path)
  ) {

    const challengeId =
      Number(
        path.split("/").pop()
      );


    await env.DB.prepare(`
      DELETE FROM reports

      WHERE
        challenge_id=?
    `)
      .bind(
        challengeId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM chat_messages

      WHERE
        challenge_id=?
    `)
      .bind(
        challengeId
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM challenges

      WHERE
        id=?
    `)
      .bind(
        challengeId
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     ADMIN CAMBIAR RESULTADO
  ========================================= */

  if (
    request.method === "POST" &&
    /^\/api\/admin\/challenges\/\d+\/result$/
      .test(path)
  ) {

    const challengeId =
      Number(
        path.split("/")[4]
      );


    const data =
      await body(request);


    const winnerId =
      Number(
        data.winner_clan_id
      );


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE id=?
      `)
        .bind(
          challengeId
        )
        .first();


    if (!challenge) {

      return json(
        {
          error:
            "Reto no encontrado."
        },
        404,
        headers
      );

    }


    const creatorId =
      Number(
        challenge.creator_clan_id
      );

    const accepterId =
      Number(
        challenge.accepter_clan_id
      );


    if (
      winnerId !== creatorId &&
      winnerId !== accepterId
    ) {

      return json(
        {
          error:
            "Ganador no válido."
        },
        400,
        headers
      );

    }


    /* Si ya estaba completado,
       primero quitamos los puntos
       del resultado anterior. */

    if (
      challenge.status ===
        "completed" &&
      challenge.winner_clan_id
    ) {

      const oldWinner =
        Number(
          challenge.winner_clan_id
        );

      const oldLoser =
        oldWinner === creatorId
          ? accepterId
          : creatorId;


      await removeScoreResult(
        env,
        oldWinner,
        true
      );

      await removeScoreResult(
        env,
        oldLoser,
        false
      );

    }


    await env.DB.prepare(`
      DELETE FROM reports

      WHERE
        challenge_id=?
    `)
      .bind(
        challengeId
      )
      .run();


    await env.DB.prepare(`
      UPDATE challenges

      SET

        status='completed',

        winner_clan_id=?,

        completed_at=?

      WHERE id=?
    `)
      .bind(
        winnerId,

        new Date().toISOString(),

        challengeId
      )
      .run();


    await updateScore(
      env,
      winnerId,
      true,
      challenge.league
    );


    const loserId =
      winnerId === creatorId
        ? accepterId
        : creatorId;


    if (loserId) {

      await updateScore(
        env,
        loserId,
        false,
        challenge.league
      );

    }


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     DESHACER RESULTADO ADMIN
  ========================================= */

  if (
    request.method === "POST" &&
    /^\/api\/admin\/challenges\/\d+\/undo$/
      .test(path)
  ) {

    const challengeId =
      Number(
        path.split("/")[4]
      );


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE id=?
      `)
        .bind(
          challengeId
        )
        .first();


    if (!challenge) {

      return json(
        {
          error:
            "Reto no encontrado."
        },
        404,
        headers
      );

    }


    if (
      challenge.status !==
        "completed" ||
      !challenge.winner_clan_id
    ) {

      return json(
        {
          error:
            "Este reto no tiene un resultado que deshacer."
        },
        400,
        headers
      );

    }


    const winnerId =
      Number(
        challenge.winner_clan_id
      );


    const creatorId =
      Number(
        challenge.creator_clan_id
      );


    const accepterId =
      Number(
        challenge.accepter_clan_id
      );


    const loserId =
      winnerId === creatorId
        ? accepterId
        : creatorId;


    await removeScoreResult(
      env,
      winnerId,
      true
    );


    if (loserId) {

      await removeScoreResult(
        env,
        loserId,
        false
      );

    }


    await env.DB.prepare(`
      DELETE FROM reports

      WHERE
        challenge_id=?
    `)
      .bind(
        challengeId
      )
      .run();


    await env.DB.prepare(`
      UPDATE challenges

      SET

        status='accepted',

        winner_clan_id=NULL,

        completed_at=NULL

      WHERE id=?
    `)
      .bind(
        challengeId
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  /* =========================================
     REINICIAR LIGA
  ========================================= */

  if (
    request.method === "POST" &&
    /^\/api\/admin\/leagues\/\d+\/reset$/
      .test(path)
  ) {

    const league =
      Number(
        path.split("/")[4]
      );


    if (
      ![1,2,3,4].includes(
        league
      )
    ) {

      return json(
        {
          error:
            "Liga no válida."
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

      WHERE
        league=?
    `)
      .bind(
        league
      )
      .run();


    return json(
      {
        ok: true
      },
      200,
      headers
    );

  }


  return json(
    {
      error:
        "Ruta de administración no encontrada."
    },
    404,
    headers
  );

}


/* =====================================================
   BORRAR DATOS DE UN CLAN
===================================================== */

async function deleteClanData(
  env,
  clanId
) {

  const challenges =
    await env.DB.prepare(`
      SELECT id
      FROM challenges

      WHERE

        creator_clan_id=?

        OR

        accepter_clan_id=?
    `)
      .bind(
        clanId,

        clanId
      )
      .all();


  for (
    const challenge
    of challenges.results
  ) {

    await env.DB.prepare(`
      DELETE FROM reports

      WHERE
        challenge_id=?
    `)
      .bind(
        challenge.id
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM chat_messages

      WHERE
        challenge_id=?
    `)
      .bind(
        challenge.id
      )
      .run();

  }


  await env.DB.prepare(`
    DELETE FROM challenges

    WHERE

      creator_clan_id=?

      OR

      accepter_clan_id=?
  `)
    .bind(
      clanId,

      clanId
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM invites

    WHERE
      clan_id=?
  `)
    .bind(
      clanId
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM members

    WHERE
      clan_id=?
  `)
    .bind(
      clanId
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM scores

    WHERE
      clan_id=?
  `)
    .bind(
      clanId
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM clans

    WHERE
      id=?
  `)
    .bind(
      clanId
    )
    .run();

}


/* =====================================================
   QUITAR RESULTADO DE CLASIFICACIÓN
===================================================== */

async function removeScoreResult(
  env,
  clanId,
  won
) {

  if (won) {

    await env.DB.prepare(`
      UPDATE scores

      SET

        points=
          MAX(
            points-3,
            0
          ),

        wins=
          MAX(
            wins-1,
            0
          ),

        played=
          MAX(
            played-1,
            0
          )

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  } else {

    await env.DB.prepare(`
      UPDATE scores

      SET

        losses=
          MAX(
            losses-1,
            0
          ),

        played=
          MAX(
            played-1,
            0
          )

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }

}


/* =====================================================
   RUTA NO ENCONTRADA
===================================================== */

return json(
  {
    error:
      "Ruta no encontrada."
  },
  404,
  headers
);

}


/* =====================================================
   WORKER
===================================================== */

export default {

  async fetch(
    request,
    env
  ) {

    try {

      const url =
        new URL(
          request.url
        );


      return await api(
        request,

        env,

        url.pathname
      );

    } catch (
      error
    ) {

      console.error(
        "WORKER ERROR:",
        error
      );


      return json(
        {
          error:
            "Error interno del servidor.",

          detail:
            error.message
        },
        500,
        cors(request)
      );

    }

  }

};
