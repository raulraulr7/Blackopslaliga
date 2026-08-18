// ======================================================
// BLACKOPS2LALIGA
// WORKER COMPLETO - PARTE 1/3
// ======================================================

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

const MAP_1V1 = "Nuketown";


function json(
  data,
  status = 200,
  headers = {}
) {

  return new Response(
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

}


async function body(
  request
) {

  try {

    return await request.json();

  } catch {

    return {};

  }

}


function cors(
  request
) {

  const origin =
    request.headers.get(
      "Origin"
    );

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


function sessionCookie(
  token
) {

  return `${COOKIE}=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=${
    SESSION_DAYS * 86400
  }; HttpOnly; SameSite=Lax; Secure`;

}


function deleteSessionCookie() {

  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;

}


function getCookie(
  request
) {

  const cookies =
    request.headers.get(
      "Cookie"
    ) || "";

  const match =
    cookies.match(
      new RegExp(
        "(^|;\\s*)" +
        COOKIE +
        "=([^;]+)"
      )
    );

  return match
    ? decodeURIComponent(
        match[2]
      )
    : null;

}


// ======================================================
// PASSWORD
// ======================================================

async function hashPassword(
  password,
  salt = crypto.randomUUID()
) {

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      "PBKDF2",
      false,
      [
        "deriveBits"
      ]
    );


  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",

        salt:
          new TextEncoder().encode(
            salt
          ),

        iterations:
          100000,

        hash:
          "SHA-256"
      },

      key,

      256
    );


  const encoded =
    btoa(
      String.fromCharCode(
        ...new Uint8Array(
          bits
        )
      )
    ).replaceAll(
      "=",
      ""
    );


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


  const parts =
    stored.split(
      "."
    );


  const salt =
    parts[0];

  const hash =
    parts[1];


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


// ======================================================
// DATABASE
// ======================================================

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


async function initDatabase(
  env
) {

  // USERS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      username
        TEXT
        UNIQUE
        NOT NULL,

      password_hash
        TEXT
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // SESSIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions(

      token
        TEXT
        PRIMARY KEY,

      user_id
        INTEGER
        NOT NULL,

      expires
        INTEGER
        NOT NULL
    )
  `).run();


  // CLANS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS clans(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      name
        TEXT
        NOT NULL,

      captain_id
        INTEGER
        NOT NULL,

      league
        INTEGER
        DEFAULT 4,

      clan_code
        TEXT,

      logo_url
        TEXT,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // MEMBERS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS members(

      clan_id
        INTEGER
        NOT NULL,

      user_id
        INTEGER
        NOT NULL,

      role
        TEXT
        DEFAULT 'member',

      joined_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      PRIMARY KEY(
        clan_id,
        user_id
      )
    )
  `).run();


  // INVITES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS invites(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      clan_id
        INTEGER
        NOT NULL,

      inviter_id
        INTEGER
        NOT NULL,

      invitee_id
        INTEGER
        NOT NULL,

      status
        TEXT
        DEFAULT 'pending',

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // NOTIFICATIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS notifications(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      user_id
        INTEGER
        NOT NULL,

      title
        TEXT
        NOT NULL,

      message
        TEXT
        NOT NULL,

      type
        TEXT
        DEFAULT 'general',

      is_read
        INTEGER
        DEFAULT 0,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // CHALLENGES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS challenges(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      creator_clan_id
        INTEGER
        NOT NULL,

      accepter_clan_id
        INTEGER,

      status
        TEXT
        DEFAULT 'open',

      team_size
        INTEGER
        DEFAULT 4,

      game_modes
        TEXT
        DEFAULT '["snd"]',

      map1
        TEXT,

      map2
        TEXT,

      map3
        TEXT,

      scheduled_at
        TEXT,

      expires_at
        TEXT,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      completed_at
        TEXT,

      winner_clan_id
        INTEGER
    )
  `).run();


  // REPORTS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS reports(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      challenge_id
        INTEGER
        NOT NULL,

      clan_id
        INTEGER
        NOT NULL,

      winner_clan_id
        INTEGER
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      UNIQUE(
        challenge_id,
        clan_id
      )
    )
  `).run();


  // SCORES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores(

      clan_id
        INTEGER
        PRIMARY KEY,

      league
        INTEGER
        DEFAULT 4,

      points
        INTEGER
        DEFAULT 0,

      wins
        INTEGER
        DEFAULT 0,

      losses
        INTEGER
        DEFAULT 0,

      played
        INTEGER
        DEFAULT 0
    )
  `).run();


  // CHAT
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS chat_messages(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      challenge_id
        INTEGER
        NOT NULL,

      user_id
        INTEGER
        NOT NULL,

      message
        TEXT
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // ==================================================
  // MIGRACIONES DE USUARIOS
  // ==================================================

  const userColumns = [

    [
      "psn_id",
      "TEXT"
    ],

    [
      "psn_changed_at",
      "INTEGER"
    ],

    [
      "avatar_url",
      "TEXT"
    ],

    [
      "is_blocked",
      "INTEGER DEFAULT 0"
    ],

    [
      "blocked_until",
      "INTEGER"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of userColumns
  ) {

    try {

      await ensureColumn(
        env,
        "users",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIONES DE CLANES
  // ==================================================

  const clanColumns = [

    [
      "league",
      "INTEGER DEFAULT 4"
    ],

    [
      "clan_code",
      "TEXT"
    ],

    [
      "logo_url",
      "TEXT"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of clanColumns
  ) {

    try {

      await ensureColumn(
        env,
        "clans",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIONES DE MIEMBROS
  // ==================================================

  try {

    await ensureColumn(
      env,
      "members",
      "role",
      "TEXT DEFAULT 'member'"
    );

  } catch {}


  // ==================================================
  // MIGRACIONES DE RETOS
  // ==================================================

  const challengeColumns = [

    [
      "team_size",
      "INTEGER DEFAULT 4"
    ],

    [
      "game_modes",
      `TEXT DEFAULT '["snd"]'`
    ],

    [
      "scheduled_at",
      "TEXT"
    ],

    [
      "expires_at",
      "TEXT"
    ],

    [
      "completed_at",
      "TEXT"
    ],

    [
      "winner_clan_id",
      "INTEGER"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of challengeColumns
  ) {

    try {

      await ensureColumn(
        env,
        "challenges",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIÓN SCORES
  // ==================================================

  try {

    await ensureColumn(
      env,
      "scores",
      "league",
      "INTEGER DEFAULT 4"
    );

  } catch {}


  // ==================================================
  // COMPLETAR CLANES ANTIGUOS
  // ==================================================

  try {

    const clans =
      await env.DB.prepare(`
        SELECT
          id,
          clan_code
        FROM clans
        WHERE
          clan_code IS NULL
          OR clan_code=''
          OR clan_code='TEMP'
          OR clan_code LIKE 'BOL-%'
      `).all();


    for (
      const clan
      of clans.results
    ) {

      let n =
        Number(
          clan.id
        );


      let code =
        "";


      for (
        let i=0;
        i<4;
        i++
      ) {

        code =
          String.fromCharCode(
            65 +
            (
              n %
              26
            )
          ) +
          code;


        n =
          Math.floor(
            n /
            26
          );

      }


      await env.DB.prepare(`
        UPDATE clans
        SET
          clan_code=?
        WHERE
          id=?
      `)
      .bind(
        code,
        clan.id
      )
      .run();

    }

  } catch {}


  // ==================================================
  // ASEGURAR SCORES
  // ==================================================

  try {

    const clans =
      await env.DB.prepare(`
        SELECT
          id,
          league
        FROM clans
      `).all();


    for (
      const clan
      of clans.results
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
        clan.id,
        clan.league || 4
      )
      .run();

    }

  } catch {}

}


async function getCurrentUser(
  request,
  env
) {

  const token =
    getCookie(
      request
    );


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


function isAdmin(
  user
) {

  return !!user &&
    String(
      user.username || ""
    ).toLowerCase()
    ===
    "admin";

}


async function getUserClan(
  env,
  userId,
  league
) {

  if (
    league !== undefined &&
    league !== null
  ) {

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
    `)
    .bind(
      userId,
      league
    )
    .first();

  }


  return await env.DB.prepare(`
    SELECT
      c.*
    FROM clans c

    JOIN members m
      ON m.clan_id=c.id

    WHERE
      m.user_id=?

    LIMIT 1
  `)
  .bind(
    userId
  )
  .first();

}


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


async function countClanMembers(
  env,
  clanId
) {

  const result =
    await env.DB.prepare(`
      SELECT
        COUNT(*) AS total
      FROM members
      WHERE clan_id=?
    `)
    .bind(
      clanId
    )
    .first();


  return Number(
    result?.total || 0
  );

}


// ======================================================
// BORRAR RETOS ABIERTOS CADUCADOS
// ======================================================

async function expireChallenges(
  env
) {

  const now =
    new Date().toISOString();


  await env.DB.prepare(`
    DELETE FROM challenges

    WHERE
      status='open'

      AND expires_at IS NOT NULL

      AND expires_at<=?
  `)
  .bind(
    now
  )
  .run();

}


// ======================================================
// FETCH PRINCIPAL
// ======================================================

async function fetch(
  request,
  env,
  ctx
) {

  const url =
    new URL(
      request.url
    );


  if (
    url.pathname.startsWith(
      "/api/"
    )
  ) {

    return api(
      request,
      env,
      url.pathname
    );

  }


  if (
    url.pathname === "/" ||
    url.pathname === "/index.html"
  ) {

    return new Response(
      "BlackOps2Liga Worker activo.",
      {
        status:200,

        headers:{
          "content-type":
            "text/plain;charset=UTF-8"
        }
      }
    );

  }


  return new Response(
    "Ruta no encontrada.",
    {
      status:404
    }
  );

}


// ======================================================
// API
// ======================================================

async function api(
  request,
  env,
  path
) {

  const headers =
    cors(
      request
    );


  if (
    request.method ===
    "OPTIONS"
  ) {

    return new Response(
      null,
      {
        status:204,
        headers
      }
    );

  }


  await initDatabase(
    env
  );


  await expireChallenges(
    env
  );


  // ====================================================
  // REGISTER
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/register"
  ) {

    const data =
      await body(
        request
      );


    const username =
      String(
        data.username || ""
      ).trim();


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

        VALUES
        (
          ?,
          ?
        )
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

      VALUES
      (
        ?,
        ?,
        ?
      )
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
        ok:true,

        user:{
          id:userId,
          username
        }
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


  // ====================================================
  // LOGIN
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data =
      await body(
        request
      );


    const username =
      String(
        data.username || ""
      ).trim();


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
        user.blocked_until === 0 ||
        user.blocked_until > Date.now()
      )
    ) {

      return json(
        {
          error:
            "Tu cuenta está bloqueada."
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

      VALUES
      (
        ?,
        ?,
        ?
      )
    `)
    .bind(
      token,
      user.id,
      Date.now() +
      SESSION_DAYS *
      86400000
    )
    .run();


    return json(
      {
        ok:true,

        user:{
          id:user.id,
          username:user.username,
          psn_id:user.psn_id,
          avatar_url:user.avatar_url
        }
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


  // ====================================================
  // LOGOUT
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/logout"
  ) {

    const token =
      getCookie(
        request
      );


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
        ok:true
      },

      200,

      {
        ...headers,

        "Set-Cookie":
          deleteSessionCookie()
      }
    );

  }


  // ====================================================
  // SESIÓN ACTUAL
  // ====================================================

  const me =
    await getCurrentUser(
      request,
      env
    );


  // Rutas públicas
  const publicRoute =
    (
      request.method === "GET" &&
      (
        path === "/api/leaderboard" ||
        path === "/api/clans" ||
        path === "/api/users" ||
        /^\/api\/clans\/\d+$/.test(path) ||
        /^\/api\/users\/\d+$/.test(path)
      )
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


  if (
    me &&
    me.is_blocked &&
    (
      me.blocked_until === 0 ||
      me.blocked_until > Date.now()
    )
  ) {

    return json(
      {
        error:
          "Tu cuenta está bloqueada."
      },
      403,
      headers
    );

  }


  // ====================================================
  // ME
  // ====================================================

  if (
    request.method === "GET" &&
    path === "/api/me"
  ) {

    return json(
      {
        user: me
          ? {
              id:me.id,
              username:me.username,
              psn_id:me.psn_id,
              avatar_url:
                me.avatar_url
            }
          : null,

        admin:
          isAdmin(me)
      },
      200,
      headers
    );

  }


  // ====================================================
  // PERFIL
  // ====================================================

  if (
    request.method === "PUT" &&
    path === "/api/profile"
  ) {

    const data =
      await body(
        request
      );


    const psn =
      String(
        data.psn_id || ""
      )
      .trim()
      .slice(
        0,
        32
      );


    const avatar =
      String(
        data.avatar_url || ""
      )
      .trim()
      .slice(
        0,
        500
      );


    const current =
      await env.DB.prepare(`
        SELECT
          psn_id,
          psn_changed_at
        FROM users
        WHERE id=?
      `)
      .bind(
        me.id
      )
      .first();


    if (
      psn !==
      String(
        current?.psn_id || ""
      )
    ) {

      if (
        current?.psn_changed_at &&
        Date.now() -
        Number(
          current.psn_changed_at
        ) <
        86400000
      ) {

        return json(
          {
            error:
              "El ID solo puede cambiarse cada 24 horas."
          },
          400,
          headers
        );

      }


      await env.DB.prepare(`
        UPDATE users

        SET
          psn_id=?,
          psn_changed_at=?

        WHERE id=?
      `)
      .bind(
        psn,
        Date.now(),
        me.id
      )
      .run();

    }


    await env.DB.prepare(`
      UPDATE users
      SET avatar_url=?
      WHERE id=?
    `)
    .bind(
      avatar,
      me.id
    )
    .run();


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }
  // ======================================================
// BLACKOPS2LALIGA
// WORKER COMPLETO - PARTE 1/3
// ======================================================

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

const MAP_1V1 = "Nuketown";


function json(
  data,
  status = 200,
  headers = {}
) {

  return new Response(
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

}


async function body(
  request
) {

  try {

    return await request.json();

  } catch {

    return {};

  }

}


function cors(
  request
) {

  const origin =
    request.headers.get(
      "Origin"
    );

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


function sessionCookie(
  token
) {

  return `${COOKIE}=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=${
    SESSION_DAYS * 86400
  }; HttpOnly; SameSite=Lax; Secure`;

}


function deleteSessionCookie() {

  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;

}


function getCookie(
  request
) {

  const cookies =
    request.headers.get(
      "Cookie"
    ) || "";

  const match =
    cookies.match(
      new RegExp(
        "(^|;\\s*)" +
        COOKIE +
        "=([^;]+)"
      )
    );

  return match
    ? decodeURIComponent(
        match[2]
      )
    : null;

}


// ======================================================
// PASSWORD
// ======================================================

async function hashPassword(
  password,
  salt = crypto.randomUUID()
) {

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      "PBKDF2",
      false,
      [
        "deriveBits"
      ]
    );


  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",

        salt:
          new TextEncoder().encode(
            salt
          ),

        iterations:
          100000,

        hash:
          "SHA-256"
      },

      key,

      256
    );


  const encoded =
    btoa(
      String.fromCharCode(
        ...new Uint8Array(
          bits
        )
      )
    ).replaceAll(
      "=",
      ""
    );


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


  const parts =
    stored.split(
      "."
    );


  const salt =
    parts[0];

  const hash =
    parts[1];


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


// ======================================================
// DATABASE
// ======================================================

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


async function initDatabase(
  env
) {

  // USERS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      username
        TEXT
        UNIQUE
        NOT NULL,

      password_hash
        TEXT
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // SESSIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions(

      token
        TEXT
        PRIMARY KEY,

      user_id
        INTEGER
        NOT NULL,

      expires
        INTEGER
        NOT NULL
    )
  `).run();


  // CLANS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS clans(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      name
        TEXT
        NOT NULL,

      captain_id
        INTEGER
        NOT NULL,

      league
        INTEGER
        DEFAULT 4,

      clan_code
        TEXT,

      logo_url
        TEXT,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // MEMBERS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS members(

      clan_id
        INTEGER
        NOT NULL,

      user_id
        INTEGER
        NOT NULL,

      role
        TEXT
        DEFAULT 'member',

      joined_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      PRIMARY KEY(
        clan_id,
        user_id
      )
    )
  `).run();


  // INVITES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS invites(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      clan_id
        INTEGER
        NOT NULL,

      inviter_id
        INTEGER
        NOT NULL,

      invitee_id
        INTEGER
        NOT NULL,

      status
        TEXT
        DEFAULT 'pending',

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // NOTIFICATIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS notifications(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      user_id
        INTEGER
        NOT NULL,

      title
        TEXT
        NOT NULL,

      message
        TEXT
        NOT NULL,

      type
        TEXT
        DEFAULT 'general',

      is_read
        INTEGER
        DEFAULT 0,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // CHALLENGES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS challenges(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      creator_clan_id
        INTEGER
        NOT NULL,

      accepter_clan_id
        INTEGER,

      status
        TEXT
        DEFAULT 'open',

      team_size
        INTEGER
        DEFAULT 4,

      game_modes
        TEXT
        DEFAULT '["snd"]',

      map1
        TEXT,

      map2
        TEXT,

      map3
        TEXT,

      scheduled_at
        TEXT,

      expires_at
        TEXT,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      completed_at
        TEXT,

      winner_clan_id
        INTEGER
    )
  `).run();


  // REPORTS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS reports(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      challenge_id
        INTEGER
        NOT NULL,

      clan_id
        INTEGER
        NOT NULL,

      winner_clan_id
        INTEGER
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP,

      UNIQUE(
        challenge_id,
        clan_id
      )
    )
  `).run();


  // SCORES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores(

      clan_id
        INTEGER
        PRIMARY KEY,

      league
        INTEGER
        DEFAULT 4,

      points
        INTEGER
        DEFAULT 0,

      wins
        INTEGER
        DEFAULT 0,

      losses
        INTEGER
        DEFAULT 0,

      played
        INTEGER
        DEFAULT 0
    )
  `).run();


  // CHAT
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS chat_messages(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      challenge_id
        INTEGER
        NOT NULL,

      user_id
        INTEGER
        NOT NULL,

      message
        TEXT
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  // ==================================================
  // MIGRACIONES DE USUARIOS
  // ==================================================

  const userColumns = [

    [
      "psn_id",
      "TEXT"
    ],

    [
      "psn_changed_at",
      "INTEGER"
    ],

    [
      "avatar_url",
      "TEXT"
    ],

    [
      "is_blocked",
      "INTEGER DEFAULT 0"
    ],

    [
      "blocked_until",
      "INTEGER"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of userColumns
  ) {

    try {

      await ensureColumn(
        env,
        "users",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIONES DE CLANES
  // ==================================================

  const clanColumns = [

    [
      "league",
      "INTEGER DEFAULT 4"
    ],

    [
      "clan_code",
      "TEXT"
    ],

    [
      "logo_url",
      "TEXT"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of clanColumns
  ) {

    try {

      await ensureColumn(
        env,
        "clans",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIONES DE MIEMBROS
  // ==================================================

  try {

    await ensureColumn(
      env,
      "members",
      "role",
      "TEXT DEFAULT 'member'"
    );

  } catch {}


  // ==================================================
  // MIGRACIONES DE RETOS
  // ==================================================

  const challengeColumns = [

    [
      "team_size",
      "INTEGER DEFAULT 4"
    ],

    [
      "game_modes",
      `TEXT DEFAULT '["snd"]'`
    ],

    [
      "scheduled_at",
      "TEXT"
    ],

    [
      "expires_at",
      "TEXT"
    ],

    [
      "completed_at",
      "TEXT"
    ],

    [
      "winner_clan_id",
      "INTEGER"
    ]

  ];


  for (
    const [
      column,
      definition
    ]
    of challengeColumns
  ) {

    try {

      await ensureColumn(
        env,
        "challenges",
        column,
        definition
      );

    } catch {}

  }


  // ==================================================
  // MIGRACIÓN SCORES
  // ==================================================

  try {

    await ensureColumn(
      env,
      "scores",
      "league",
      "INTEGER DEFAULT 4"
    );

  } catch {}


  // ==================================================
  // COMPLETAR CLANES ANTIGUOS
  // ==================================================

  try {

    const clans =
      await env.DB.prepare(`
        SELECT
          id,
          clan_code
        FROM clans
        WHERE
          clan_code IS NULL
          OR clan_code=''
          OR clan_code='TEMP'
          OR clan_code LIKE 'BOL-%'
      `).all();


    for (
      const clan
      of clans.results
    ) {

      let n =
        Number(
          clan.id
        );


      let code =
        "";


      for (
        let i=0;
        i<4;
        i++
      ) {

        code =
          String.fromCharCode(
            65 +
            (
              n %
              26
            )
          ) +
          code;


        n =
          Math.floor(
            n /
            26
          );

      }


      await env.DB.prepare(`
        UPDATE clans
        SET
          clan_code=?
        WHERE
          id=?
      `)
      .bind(
        code,
        clan.id
      )
      .run();

    }

  } catch {}


  // ==================================================
  // ASEGURAR SCORES
  // ==================================================

  try {

    const clans =
      await env.DB.prepare(`
        SELECT
          id,
          league
        FROM clans
      `).all();


    for (
      const clan
      of clans.results
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
        clan.id,
        clan.league || 4
      )
      .run();

    }

  } catch {}

}


async function getCurrentUser(
  request,
  env
) {

  const token =
    getCookie(
      request
    );


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


function isAdmin(
  user
) {

  return !!user &&
    String(
      user.username || ""
    ).toLowerCase()
    ===
    "admin";

}


async function getUserClan(
  env,
  userId,
  league
) {

  if (
    league !== undefined &&
    league !== null
  ) {

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
    `)
    .bind(
      userId,
      league
    )
    .first();

  }


  return await env.DB.prepare(`
    SELECT
      c.*
    FROM clans c

    JOIN members m
      ON m.clan_id=c.id

    WHERE
      m.user_id=?

    LIMIT 1
  `)
  .bind(
    userId
  )
  .first();

}


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


async function countClanMembers(
  env,
  clanId
) {

  const result =
    await env.DB.prepare(`
      SELECT
        COUNT(*) AS total
      FROM members
      WHERE clan_id=?
    `)
    .bind(
      clanId
    )
    .first();


  return Number(
    result?.total || 0
  );

}


// ======================================================
// BORRAR RETOS ABIERTOS CADUCADOS
// ======================================================

async function expireChallenges(
  env
) {

  const now =
    new Date().toISOString();


  await env.DB.prepare(`
    DELETE FROM challenges

    WHERE
      status='open'

      AND expires_at IS NOT NULL

      AND expires_at<=?
  `)
  .bind(
    now
  )
  .run();

}


// ======================================================
// FETCH PRINCIPAL
// ======================================================

async function fetch(
  request,
  env,
  ctx
) {

  const url =
    new URL(
      request.url
    );


  if (
    url.pathname.startsWith(
      "/api/"
    )
  ) {

    return api(
      request,
      env,
      url.pathname
    );

  }


  if (
    url.pathname === "/" ||
    url.pathname === "/index.html"
  ) {

    return new Response(
      "BlackOps2Liga Worker activo.",
      {
        status:200,

        headers:{
          "content-type":
            "text/plain;charset=UTF-8"
        }
      }
    );

  }


  return new Response(
    "Ruta no encontrada.",
    {
      status:404
    }
  );

}


// ======================================================
// API
// ======================================================

async function api(
  request,
  env,
  path
) {

  const headers =
    cors(
      request
    );


  if (
    request.method ===
    "OPTIONS"
  ) {

    return new Response(
      null,
      {
        status:204,
        headers
      }
    );

  }


  await initDatabase(
    env
  );


  await expireChallenges(
    env
  );


  // ====================================================
  // REGISTER
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/register"
  ) {

    const data =
      await body(
        request
      );


    const username =
      String(
        data.username || ""
      ).trim();


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

        VALUES
        (
          ?,
          ?
        )
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

      VALUES
      (
        ?,
        ?,
        ?
      )
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
        ok:true,

        user:{
          id:userId,
          username
        }
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


  // ====================================================
  // LOGIN
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data =
      await body(
        request
      );


    const username =
      String(
        data.username || ""
      ).trim();


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
        user.blocked_until === 0 ||
        user.blocked_until > Date.now()
      )
    ) {

      return json(
        {
          error:
            "Tu cuenta está bloqueada."
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

      VALUES
      (
        ?,
        ?,
        ?
      )
    `)
    .bind(
      token,
      user.id,
      Date.now() +
      SESSION_DAYS *
      86400000
    )
    .run();


    return json(
      {
        ok:true,

        user:{
          id:user.id,
          username:user.username,
          psn_id:user.psn_id,
          avatar_url:user.avatar_url
        }
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


  // ====================================================
  // LOGOUT
  // ====================================================

  if (
    request.method === "POST" &&
    path === "/api/logout"
  ) {

    const token =
      getCookie(
        request
      );


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
        ok:true
      },

      200,

      {
        ...headers,

        "Set-Cookie":
          deleteSessionCookie()
      }
    );

  }


  // ====================================================
  // SESIÓN ACTUAL
  // ====================================================

  const me =
    await getCurrentUser(
      request,
      env
    );


  // Rutas públicas
  const publicRoute =
    (
      request.method === "GET" &&
      (
        path === "/api/leaderboard" ||
        path === "/api/clans" ||
        path === "/api/users" ||
        /^\/api\/clans\/\d+$/.test(path) ||
        /^\/api\/users\/\d+$/.test(path)
      )
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


  if (
    me &&
    me.is_blocked &&
    (
      me.blocked_until === 0 ||
      me.blocked_until > Date.now()
    )
  ) {

    return json(
      {
        error:
          "Tu cuenta está bloqueada."
      },
      403,
      headers
    );

  }


  // ====================================================
  // ME
  // ====================================================

  if (
    request.method === "GET" &&
    path === "/api/me"
  ) {

    return json(
      {
        user: me
          ? {
              id:me.id,
              username:me.username,
              psn_id:me.psn_id,
              avatar_url:
                me.avatar_url
            }
          : null,

        admin:
          isAdmin(me)
      },
      200,
      headers
    );

  }


  // ====================================================
  // PERFIL
  // ====================================================

  if (
    request.method === "PUT" &&
    path === "/api/profile"
  ) {

    const data =
      await body(
        request
      );


    const psn =
      String(
        data.psn_id || ""
      )
      .trim()
      .slice(
        0,
        32
      );


    const avatar =
      String(
        data.avatar_url || ""
      )
      .trim()
      .slice(
        0,
        500
      );


    const current =
      await env.DB.prepare(`
        SELECT
          psn_id,
          psn_changed_at
        FROM users
        WHERE id=?
      `)
      .bind(
        me.id
      )
      .first();


    if (
      psn !==
      String(
        current?.psn_id || ""
      )
    ) {

      if (
        current?.psn_changed_at &&
        Date.now() -
        Number(
          current.psn_changed_at
        ) <
        86400000
      ) {

        return json(
          {
            error:
              "El ID solo puede cambiarse cada 24 horas."
          },
          400,
          headers
        );

      }


      await env.DB.prepare(`
        UPDATE users

        SET
          psn_id=?,
          psn_changed_at=?

        WHERE id=?
      `)
      .bind(
        psn,
        Date.now(),
        me.id
      )
      .run();

    }


    await env.DB.prepare(`
      UPDATE users
      SET avatar_url=?
      WHERE id=?
    `)
    .bind(
      avatar,
      me.id
    )
    .run();


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }
  // ======================================================
// BLACKOPS2LALIGA
// WORKER COMPLETO - PARTE 3/3
// ======================================================


// ======================================================
// ADMIN — RESULTADOS
// ======================================================

async function adminSetResult(
  env,
  challengeId,
  winnerClanId
) {

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

    throw new Error(
      "Reto no encontrado."
    );

  }


  if (
    challenge.status !==
    "completed"
  ) {

    throw new Error(
      "El reto todavía no está terminado."
    );

  }


  const home =
    Number(
      challenge.creator_clan_id
    );


  const away =
    Number(
      challenge.accepter_clan_id
    );


  const winner =
    Number(
      winnerClanId
    );


  if (
    winner !== home &&
    winner !== away
  ) {

    throw new Error(
      "Clan ganador no válido."
    );

  }


  const loser =
    winner === home
      ? away
      : home;


  // Recalcular estadísticas
  // desde cero para evitar
  // duplicar puntos.

  await env.DB.prepare(`
    UPDATE scores

    SET
      points=0,
      wins=0,
      losses=0,
      played=0

    WHERE
      clan_id IN (?,?)
  `)
  .bind(
    home,
    away
  )
  .run();


  const previous =
    await env.DB.prepare(`
      SELECT
        clan_id,
        winner_clan_id

      FROM admin_result_history

      WHERE
        challenge_id=?
    `)
    .bind(
      challengeId
    )
    .all();


  if (
    previous.results.length
  ) {

    return;

  }


  await env.DB.prepare(`
    INSERT INTO admin_result_history
    (
      challenge_id,
      winner_clan_id
    )

    VALUES
    (
      ?,
      ?
    )
  `)
  .bind(
    challengeId,
    winner
  )
  .run();

}


// ======================================================
// ADMIN — CAMBIAR RESULTADO
// ======================================================

async function adminChangeResult(
  env,
  challengeId,
  winnerClanId
) {

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

    throw new Error(
      "Reto no encontrado."
    );

  }


  const home =
    Number(
      challenge.creator_clan_id
    );


  const away =
    Number(
      challenge.accepter_clan_id
    );


  const winner =
    Number(
      winnerClanId
    );


  if (
    winner !== home &&
    winner !== away
  ) {

    throw new Error(
      "Ganador no válido."
    );

  }


  const loser =
    winner === home
      ? away
      : home;


  // Quitar resultado anterior
  // de este reto.

  await env.DB.prepare(`
    DELETE FROM reports
    WHERE challenge_id=?
  `)
  .bind(
    challengeId
  )
  .run();


  // Guardamos el resultado
  // directamente mediante dos
  // confirmaciones administrativas.

  await env.DB.batch([

    env.DB.prepare(`
      INSERT INTO reports
      (
        challenge_id,
        clan_id,
        winner_clan_id
      )

      VALUES
      (
        ?,
        ?,
        ?
      )
    `)
    .bind(
      challengeId,
      home,
      winner
    ),

    env.DB.prepare(`
      INSERT INTO reports
      (
        challenge_id,
        clan_id,
        winner_clan_id
      )

      VALUES
      (
        ?,
        ?,
        ?
      )
    `)
    .bind(
      challengeId,
      away,
      winner
    )

  ]);


  await env.DB.prepare(`
    UPDATE challenges

    SET
      status='completed',
      winner_clan_id=?,
      completed_at=?

    WHERE id=?
  `)
  .bind(
    winner,
    new Date().toISOString(),
    challengeId
  )
  .run();


  return {
    winner,
    loser
  };

}


// ======================================================
// ADMIN — LISTADO DE RETOS
// ======================================================

async function getAdminChallenges(
  env
) {

  const rows =
    await env.DB.prepare(`
      SELECT

        ch.id,
        ch.status,
        ch.team_size,
        ch.map1,
        ch.map2,
        ch.map3,
        ch.game_modes,
        ch.created_at,
        ch.completed_at,
        ch.winner_clan_id,

        home.name
          AS home_name,

        home.clan_code
          AS home_code,

        away.name
          AS away_name,

        away.clan_code
          AS away_code

      FROM challenges ch

      LEFT JOIN clans home
        ON home.id=
           ch.creator_clan_id

      LEFT JOIN clans away
        ON away.id=
           ch.accepter_clan_id

      ORDER BY
        ch.id DESC

      LIMIT 500
    `)
    .all();


  return rows.results || [];

}


// ======================================================
// ADMIN — REINICIAR LIGA
// ======================================================

async function resetLeague(
  env,
  league
) {

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


  await env.DB.prepare(`
    DELETE FROM reports

    WHERE challenge_id IN(

      SELECT ch.id

      FROM challenges ch

      JOIN clans c
        ON c.id=
           ch.creator_clan_id

      WHERE
        c.league=?
    )
  `)
  .bind(
    league
  )
  .run();


  await env.DB.prepare(`
    DELETE FROM challenges

    WHERE creator_clan_id IN(

      SELECT id
      FROM clans
      WHERE league=?
    )

    OR accepter_clan_id IN(

      SELECT id
      FROM clans
      WHERE league=?
    )
  `)
  .bind(
    league,
    league
  )
  .run();


  return true;

}


// ======================================================
// ADMIN — EXPULSAR MIEMBRO
// ======================================================

async function adminRemoveMember(
  env,
  clanId,
  userId
) {

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


  return true;

}


// ======================================================
// ADMIN — BORRAR CLAN
// ======================================================

async function adminDeleteClan(
  env,
  clanId
) {

  await env.DB.batch([

    env.DB.prepare(`
      DELETE FROM reports

      WHERE challenge_id IN(

        SELECT id

        FROM challenges

        WHERE
          creator_clan_id=?
          OR accepter_clan_id=?
      )
    `)
    .bind(
      clanId,
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM chat_messages

      WHERE challenge_id IN(

        SELECT id

        FROM challenges

        WHERE
          creator_clan_id=?
          OR accepter_clan_id=?
      )
    `)
    .bind(
      clanId,
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM challenges

      WHERE
        creator_clan_id=?
        OR accepter_clan_id=?
    `)
    .bind(
      clanId,
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM invites
      WHERE clan_id=?
    `)
    .bind(
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM members
      WHERE clan_id=?
    `)
    .bind(
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM scores
      WHERE clan_id=?
    `)
    .bind(
      clanId
    ),

    env.DB.prepare(`
      DELETE FROM clans
      WHERE id=?
    `)
    .bind(
      clanId
    )

  ]);


  return true;

}


// ======================================================
// ADMIN — CAMBIAR PSN
// ======================================================

async function adminSetPSN(
  env,
  userId,
  psn
) {

  await env.DB.prepare(`
    UPDATE users

    SET
      psn_id=?,
      psn_changed_at=?

    WHERE id=?
  `)
  .bind(
    psn,
    Date.now(),
    userId
  )
  .run();


  return true;

}


// ======================================================
// ADMIN — CAMBIAR CLAN
// ======================================================

async function adminEditClan(
  env,
  clanId,
  data
) {

  const name =
    String(
      data.name || ""
    )
    .trim()
    .slice(
      0,
      24
    );


  const code =
    String(
      data.clan_code || ""
    )
    .trim()
    .toUpperCase();


  const league =
    Number(
      data.league
    );


  const logo =
    String(
      data.logo_url || ""
    )
    .trim()
    .slice(
      0,
      500
    );


  if (
    name.length < 2
  ) {

    throw new Error(
      "Nombre de clan no válido."
    );

  }


  if (
    !/^[A-Z]{4}$/.test(
      code
    )
  ) {

    throw new Error(
      "La insignia debe tener 4 letras."
    );

  }


  if (
    ![1,2,3,4].includes(
      league
    )
  ) {

    throw new Error(
      "Liga no válida."
    );

  }


  await env.DB.prepare(`
    UPDATE clans

    SET
      name=?,
      clan_code=?,
      league=?,
      logo_url=?

    WHERE id=?
  `)
  .bind(
    name,
    code,
    league,
    logo,
    clanId
  )
  .run();


  return true;

}


// ======================================================
// ADMIN — USUARIOS
// ======================================================

async function getAdminUsers(
  env
) {

  const rows =
    await env.DB.prepare(`
      SELECT

        id,
        username,
        psn_id,
        psn_changed_at,
        avatar_url,
        is_blocked,
        blocked_until,
        created_at

      FROM users

      ORDER BY
        id DESC

      LIMIT 500
    `)
    .all();


  return rows.results || [];

}


// ======================================================
// ADMIN — BLOQUEAR USUARIO
// ======================================================

async function blockUser(
  env,
  userId,
  minutes
) {

  const blockedUntil =
    Number(
      minutes
    ) > 0

      ? Date.now() +
        Number(minutes) *
        60000

      : 0;


  await env.DB.batch([

    env.DB.prepare(`
      UPDATE users

      SET
        is_blocked=1,
        blocked_until=?

      WHERE id=?
    `)
    .bind(
      blockedUntil,
      userId
    ),

    env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id=?
    `)
    .bind(
      userId
    )

  ]);


  return true;

}


// ======================================================
// ADMIN — DESBLOQUEAR
// ======================================================

async function unblockUser(
  env,
  userId
) {

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


  return true;

}


// ======================================================
// ADMIN — REINICIAR ESTADÍSTICAS
// ======================================================

async function resetScores(
  env,
  league
) {

  await env.DB.prepare(`
    UPDATE scores

    SET
      points=0,
      wins=0,
      losses=0,
      played=0

    WHERE league=?
  `)
  .bind(
    league
  )
  .run();


  return true;

}


// ======================================================
// MIGRACIÓN ADMIN
// ======================================================

async function ensureAdminTables(
  env
) {

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS
    admin_result_history(

      id
        INTEGER
        PRIMARY KEY
        AUTOINCREMENT,

      challenge_id
        INTEGER
        NOT NULL,

      winner_clan_id
        INTEGER
        NOT NULL,

      created_at
        TEXT
        DEFAULT CURRENT_TIMESTAMP
    )
  `)
  .run();

}


// ======================================================
// INICIALIZACIÓN EXTRA
// ======================================================

async function boot(
  env
) {

  await ensureAdminTables(
    env
  );

}


// ======================================================
// WRAPPER FETCH
// ======================================================

const originalFetch =
  fetch;


async function start(
  request,
  env,
  ctx
) {

  try {

    await boot(
      env
    );


    return await originalFetch(
      request,
      env,
      ctx
    );

  } catch (
    error
  ) {

    console.error(
      error
    );


    return json(
      {
        error:
          "Error interno del servidor.",
        detail:
          String(
            error?.message ||
            error
          )
      },
      500,
      cors(
        request
      )
    );

  }

}


// ======================================================
// EXPORT FINAL
// ======================================================

export default {
  fetch: start
};
