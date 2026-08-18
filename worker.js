// ==========================================
// BLACKOPS2LIGA - WORKER
// PARTE 1/3
// ==========================================

var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", {
    value,
    configurable: true
  });

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

const json = __name(
  (data, status = 200, headers = {}) =>
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
    ),
  "json"
);


const body = __name(
  async request => {

    try {
      return await request.json();
    } catch {
      return {};
    }

  },
  "body"
);


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

__name(cors, "cors");


function sessionCookie(token) {

  return `${COOKIE}=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=${
    SESSION_DAYS * 86400
  }; HttpOnly; SameSite=Lax; Secure`;

}

__name(sessionCookie, "sessionCookie");


function deleteSessionCookie() {

  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;

}

__name(
  deleteSessionCookie,
  "deleteSessionCookie"
);


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

__name(getCookie, "getCookie");


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

__name(
  hashPassword,
  "hashPassword"
);


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
  ] = stored.split(".");

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

__name(
  verifyPassword,
  "verifyPassword"
);


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
      item =>
        item.name === column
    );

  if (!exists) {

    await env.DB.prepare(
      `ALTER TABLE ${table}
       ADD COLUMN ${column}
       ${definition}`
    ).run();

  }

}

__name(
  ensureColumn,
  "ensureColumn"
);


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


  for (
    const [
      table,
      column,
      definition
    ] of columns
  ) {

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


  // Convertir códigos antiguos
  // BOL-00001 a códigos de 4 letras.
  try {

    const oldClans =
      await env.DB.prepare(`
        SELECT
          id,
          clan_code
        FROM clans
        WHERE
          clan_code IS NULL
          OR clan_code=''
          OR clan_code LIKE 'BOL-%'
      `).all();


    for (
      const clan
      of oldClans.results
    ) {

      let n =
        Number(clan.id);

      let code = "";

      for (
        let i = 0;
        i < 4;
        i++
      ) {

        code =
          String.fromCharCode(
            65 + (n % 26)
          ) +
          code;

        n =
          Math.floor(
            n / 26
          );

      }


      await env.DB.prepare(`
        UPDATE clans
        SET clan_code=?
        WHERE id=?
      `)
      .bind(
        code,
        clan.id
      )
      .run();

    }

  } catch (error) {

    console.log(
      "CLAN CODE MIGRATION",
      error.message
    );

  }

}

__name(
  initDatabase,
  "initDatabase"
);


async function getCurrentUser(
  request,
  env
) {

  const token =
    getCookie(request);

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
  `)
  .bind(
    token,
    Date.now()
  )
  .first();

}

__name(
  getCurrentUser,
  "getCurrentUser"
);


function isAdmin(user) {

  return !!user &&
    user.username
      .toLowerCase() ===
    "admin";

}

__name(isAdmin, "isAdmin");


async function getUserClan(
  env,
  userId,
  league = null
) {

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
    ORDER BY
      c.league
    LIMIT 1
  `)
  .bind(
    userId
  )
  .first();

}

__name(
  getUserClan,
  "getUserClan"
);


function randomMaps() {

  return [
    ...MAPS
  ]
  .sort(
    () => Math.random() - 0.5
  )
  .slice(
    0,
    3
  );

}

__name(
  randomMaps,
  "randomMaps"
);


// ==========================================
// IMPORTANTE:
// LOS RETOS ABIERTOS CADUCADOS SE BORRAN.
// NO SE GUARDAN COMO "EXPIRED".
// ==========================================

async function expireChallenges(env) {

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

__name(
  expireChallenges,
  "expireChallenges"
);


async function api(
  request,
  env,
  path
) {

  const headers =
    cors(request);


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


  await initDatabase(env);

  // Borra retos abiertos
  // que hayan pasado de 30 minutos.
  await expireChallenges(env);


  // ========================================
  // ME
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/me"
  ) {

    const user =
      await getCurrentUser(
        request,
        env
      );


    return json(
      {
        user,
        admin:
          isAdmin(user)
      },
      200,
      headers
    );

  }


  // ========================================
  // REGISTER
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/register"
  ) {

    const data =
      await body(request);


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
      username.length > 20 ||
      password.length < 6
    ) {

      return json(
        {
          error:
            "Usuario 3-20 caracteres y contraseña mínimo 6."
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


    try {

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


    } catch (error) {

      return json(
        {
          error:
            "No se pudo crear la cuenta.",
          detail:
            error.message
        },
        500,
        headers
      );

    }

  }


  // ========================================
  // LOGIN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data =
      await body(request);


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
        user.blocked_until >
          Date.now()
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


    return json(
      {
        ok:true,

        user:{
          id:user.id,
          username:user.username,
          psn_id:user.psn_id,
          avatar_url:
            user.avatar_url
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


  // ========================================
  // LOGOUT
  // ========================================

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


  // ========================================
  // USUARIO ACTUAL
  // ========================================

  const me =
    await getCurrentUser(
      request,
      env
    );


  const publicRoute =
    request.method === "GET" &&
    (
      path === "/api/leaderboard" ||
      path === "/api/clans" ||
      path === "/api/users" ||
      /^\/api\/clans\/\d+$/.test(path) ||
      /^\/api\/users\/\d+$/.test(path)
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
      me.blocked_until >
        Date.now()
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


  // ========================================
  // PERFIL
  // ========================================

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
      .slice(0,32);


    const avatar =
      String(
        data.avatar_url || ""
      )
      .trim()
      .slice(0,500);


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
        current.psn_id || ""
      )
    ) {

      if (
        current.psn_changed_at &&
        Date.now() -
          Number(
            current.psn_changed_at
          ) <
          86400000
      ) {

        return json(
          {
            error:
              "Solo puedes cambiar tu ID cada 24 horas."
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


  // ========================================
  // USUARIOS
  // ========================================

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
      ).trim();


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
          username
        LIMIT 50
      `)
      .bind(
        "%" + query + "%"
      )
      .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  // ========================================
  // PERFIL DE USUARIO
  // ========================================

  if (
    request.method === "GET" &&
    /^\/api\/users\/\d+$/.test(path)
  ) {

    const id =
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
        id
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
      await env.DB.prepare(`
        SELECT
          c.id,
          c.name,
          c.clan_code,
          c.logo_url,
          c.league
        FROM clans c
        JOIN members m
          ON m.clan_id=c.id
        WHERE
          m.user_id=?
        ORDER BY
          c.league
      `)
      .bind(
        id
      )
      .all();


    return json(
      {
        user,
        clans:
          clans.results
      },
      200,
      headers
    );

  }
    // ========================================
  // CLANES
  // ========================================

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
      );

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

      WHERE
        c.name LIKE ?
    `;


    const values = [
      "%" + query + "%"
    ];


    if (
      [2,3,4].includes(
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
        name

      LIMIT 100
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


  // ========================================
  // VER CLAN
  // ========================================

  if (
    request.method === "GET" &&
    /^\/api\/clans\/\d+$/.test(path)
  ) {

    const id =
      Number(
        path.split("/").pop()
      );


    const clan =
      await env.DB.prepare(`
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

        WHERE
          c.id=?
      `)
      .bind(
        id
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
          m.role

        FROM members m

        JOIN users u
          ON u.id=m.user_id

        WHERE
          m.clan_id=?

        ORDER BY
          m.role DESC,
          u.username
      `)
      .bind(
        id
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


  // ========================================
  // CREAR CLAN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/clans"
  ) {

    const data =
      await body(request);


    const name =
      String(
        data.name || ""
      ).trim();


    const league =
      Number(
        data.league
      );


    const logoUrl =
      String(
        data.logo_url || ""
      )
      .trim()
      .slice(0,500);


    if (
      name.length < 2 ||
      name.length > 24 ||
      ![2,3,4].includes(
        league
      )
    ) {

      return json(
        {
          error:
            "Nombre 2-24 caracteres y liga 2v2, 3v3 o 4v4."
        },
        400,
        headers
      );

    }


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


    const existingClan =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE
          name=?
          AND league=?
      `)
      .bind(
        name,
        league
      )
      .first();


    if (existingClan) {

      return json(
        {
          error:
            "Ese nombre ya existe en esa liga."
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

          VALUES
          (
            ?,
            ?,
            ?,
            'TEMP',
            ?
          )
        `)
        .bind(
          name,
          me.id,
          league,
          logoUrl
        )
        .run();


      const clanId =
        created.meta.last_row_id;


      // Código de 4 letras
      let n =
        Number(
          clanId
        );

      let clanCode = "";


      for (
        let i=0;
        i<4;
        i++
      ) {

        clanCode =
          String.fromCharCode(
            65 + (n % 26)
          ) +
          clanCode;

        n =
          Math.floor(
            n / 26
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
        clanCode,
        clanId
      )
      .run();


      await env.DB.prepare(`
        INSERT INTO members
        (
          clan_id,
          user_id,
          role
        )

        VALUES
        (
          ?,
          ?,
          ?
        )
      `)
      .bind(
        clanId,
        me.id,
        "captain"
      )
      .run();


      await env.DB.prepare(`
        INSERT OR IGNORE INTO scores
        (
          clan_id,
          league
        )

        VALUES
        (
          ?,
          ?
        )
      `)
      .bind(
        clanId,
        league
      )
      .run();


      return json(
        {
          ok:true,

          clanId,

          clanCode
        },
        200,
        headers
      );


    } catch (error) {

      console.error(
        "CREATE CLAN ERROR:",
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


  // ========================================
  // ABANDONAR CLAN
  // ========================================
  //
  // Un miembro normal puede salir.
  //
  // El capitán NO puede salir directamente.
  // Primero tiene que nombrar otro capitán.
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/clans/leave"
  ) {

    const data =
      await body(request);


    const league =
      Number(
        data.league || 4
      );


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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id === me.id
    ) {

      return json(
        {
          error:
            "El capitán no puede abandonar el clan. Nombra primero a otro capitán."
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
      clan.id,
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


  // ========================================
  // NOMBRAR NUEVO CAPITÁN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/clans/promote"
  ) {

    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    const league =
      Number(
        data.league || 4
      );


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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id !== me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán puede nombrar a otro capitán."
        },
        403,
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
        clan.id,
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


    await env.DB.batch([

      env.DB.prepare(`
        UPDATE clans
        SET
          captain_id=?
        WHERE
          id=?
      `)
      .bind(
        userId,
        clan.id
      ),

      env.DB.prepare(`
        UPDATE members
        SET
          role='member'
        WHERE
          clan_id=?
      `)
      .bind(
        clan.id
      ),

      env.DB.prepare(`
        UPDATE members
        SET
          role='captain'
        WHERE
          clan_id=?
          AND user_id=?
      `)
      .bind(
        clan.id,
        userId
      )

    ]);


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // INVITAR JUGADOR
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/invites"
  ) {

    const data =
      await body(request);


    const inviteeId =
      Number(
        data.user_id ||
        data.invitee_id
      );


    const league =
      Number(
        data.league || 4
      );


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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id !== me.id
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


    const invitee =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE id=?
      `)
      .bind(
        inviteeId
      )
      .first();


    if (!invitee) {

      return json(
        {
          error:
            "Jugador no encontrado."
        },
        404,
        headers
      );

    }


    const already =
      await getUserClan(
        env,
        inviteeId,
        league
      );


    if (already) {

      return json(
        {
          error:
            "Ese jugador ya pertenece a un clan en esta liga."
        },
        400,
        headers
      );

    }


    const pending =
      await env.DB.prepare(`
        SELECT id
        FROM invites
        WHERE
          clan_id=?
          AND invitee_id=?
          AND status='pending'
        LIMIT 1
      `)
      .bind(
        clan.id,
        inviteeId
      )
      .first();


    if (pending) {

      return json(
        {
          error:
            "Ya existe una invitación pendiente."
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

        VALUES
        (
          ?,
          ?,
          ?,
          'pending'
        )
      `)
      .bind(
        clan.id,
        me.id,
        inviteeId
      )
      .run();


    await env.DB.prepare(`
      INSERT INTO notifications
      (
        user_id,
        title,
        message,
        type
      )

      VALUES
      (
        ?,
        ?,
        ?,
        'clan_invite'
      )
    `)
    .bind(
      inviteeId,
      "Invitación de clan",
      `Has recibido una invitación para unirte a ${clan.name}.`
    )
    .run();


    return json(
      {
        ok:true,
        id:
          created.meta.last_row_id
      },
      200,
      headers
    );

  }


  // ========================================
  // VER INVITACIONES
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/invites"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT
          i.id,
          i.clan_id,
          i.inviter_id,
          i.invitee_id,
          i.status,
          i.created_at,

          c.name,
          c.clan_code,
          c.logo_url

        FROM invites i

        JOIN clans c
          ON c.id=i.clan_id

        WHERE
          i.invitee_id=?
          AND i.status='pending'

        ORDER BY
          i.id DESC
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


  // ========================================
  // ACEPTAR / RECHAZAR INVITACIÓN
  // ========================================

  const inviteAction =
    path.match(
      /^\/api\/invites\/(\d+)\/(accept|reject)$/
    );


  if (
    request.method === "POST" &&
    inviteAction
  ) {

    const inviteId =
      Number(
        inviteAction[1]
      );


    const action =
      inviteAction[2];


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
            "Invitación no disponible."
        },
        404,
        headers
      );

    }


    if (
      action === "reject"
    ) {

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


      return json(
        {
          ok:true
        },
        200,
        headers
      );

    }


    const clan =
      await env.DB.prepare(`
        SELECT *
        FROM clans
        WHERE id=?
      `)
      .bind(
        invite.clan_id
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


    const already =
      await getUserClan(
        env,
        me.id,
        Number(
          clan.league
        )
      );


    if (already) {

      return json(
        {
          error:
            "Ya perteneces a un clan en esta liga."
        },
        400,
        headers
      );

    }


    await env.DB.batch([

      env.DB.prepare(`
        INSERT OR IGNORE INTO members
        (
          clan_id,
          user_id,
          role
        )

        VALUES
        (
          ?,
          ?,
          'member'
        )
      `)
      .bind(
        clan.id,
        me.id
      ),

      env.DB.prepare(`
        UPDATE invites
        SET
          status='accepted'
        WHERE
          id=?
      `)
      .bind(
        inviteId
      )

    ]);


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // CREAR RETO
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/challenges"
  ) {

    const data =
      await body(request);


    const league =
      Number(
        data.league || 4
      );


    const teamSize =
      Number(
        data.team_size || league
      );


    if (
      ![2,3,4].includes(
        league
      ) ||
      teamSize !== league
    ) {

      return json(
        {
          error:
            "El formato del reto no coincide con la liga."
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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id !== me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán puede publicar retos."
        },
        403,
        headers
      );

    }


    const active =
      await env.DB.prepare(`
        SELECT id
        FROM challenges

        WHERE
          (
            creator_clan_id=?
            OR
            accepter_clan_id=?
          )

          AND status IN(
            'open',
            'accepted'
          )

        LIMIT 1
      `)
      .bind(
        clan.id,
        clan.id
      )
      .first();


    if (active) {

      return json(
        {
          error:
            "Tu clan ya tiene un reto activo."
        },
        400,
        headers
      );

    }


    const selectedMaps =
      randomMaps();


    const now =
      Date.now();


    const createdAt =
      new Date(
        now
      ).toISOString();


    const expiresAt =
      new Date(
        now +
        30 * 60 * 1000
      ).toISOString();


    const modes =
      Array.isArray(
        data.game_modes
      )
        ? data.game_modes
        : ["snd"];


    const created =
      await env.DB.prepare(`
        INSERT INTO challenges
        (
          creator_clan_id,
          status,
          map1,
          map2,
          map3,
          team_size,
          game_modes,
          scheduled_at,
          expires_at
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
          ?
        )
      `)
      .bind(
        clan.id,
        selectedMaps[0],
        selectedMaps[1],
        selectedMaps[2],
        teamSize,
        JSON.stringify(
          modes
        ),
        createdAt,
        expiresAt
      )
      .run();


    return json(
      {
        ok:true,

        id:
          created.meta.last_row_id,

        expires_at:
          expiresAt,

        maps:
          selectedMaps
      },
      200,
      headers
    );

  }


  // ========================================
  // LISTAR RETOS
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/challenges"
  ) {

    await expireChallenges(
      env
    );


    const params =
      new URL(
        request.url
      ).searchParams;


    const league =
      Number(
        params.get("league") || 4
      );


    const clan =
      await getUserClan(
        env,
        me.id,
        league
      );


    const clanId =
      clan
        ? clan.id
        : -1;


    const result =
      await env.DB.prepare(`
        SELECT
          ch.*,

          creator.clan_code
            AS creator_code,

          accepter.name
            AS accepter_name,

          accepter.clan_code
            AS accepter_code

        FROM challenges ch

        JOIN clans creator
          ON creator.id=
             ch.creator_clan_id

        LEFT JOIN clans accepter
          ON accepter.id=
             ch.accepter_clan_id

        WHERE
          creator.league=?

          AND ch.status IN(
            'open',
            'accepted'
          )

          AND
          (
            ch.status='open'

            OR

            ch.creator_clan_id=?

            OR

            ch.accepter_clan_id=?
          )

        ORDER BY
          ch.id DESC
      `)
      .bind(
        league,
        clanId,
        clanId
      )
      .all();


    // IMPORTANTE:
    // En retos OPEN NO enviamos
    // creator_name.
    //
    // Así el nombre del clan
    // permanece oculto hasta aceptar.

    return json(
      result.results,
      200,
      headers
    );

  }


  // ========================================
  // ACEPTAR RETO
  // ========================================

  const acceptMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/accept$/
    );


  if (
    request.method === "POST" &&
    acceptMatch
  ) {

    const challengeId =
      Number(
        acceptMatch[1]
      );


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges

        WHERE
          id=?
          AND status='open'
      `)
      .bind(
        challengeId
      )
      .first();


    if (!challenge) {

      return json(
        {
          error:
            "El reto ya no está disponible."
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

      // Si ya caducó,
      // SE BORRA de verdad.
      await env.DB.prepare(`
        DELETE FROM challenges
        WHERE id=?
      `)
      .bind(
        challengeId
      )
      .run();


      return json(
        {
          error:
            "El reto ha caducado."
        },
        400,
        headers
      );

    }


    const league =
      Number(
        challenge.team_size
      );


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
            "No perteneces a un clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.id ===
      challenge.creator_clan_id
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


    if (
      clan.captain_id !== me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán puede aceptar un reto."
        },
        403,
        headers
      );

    }


    const active =
      await env.DB.prepare(`
        SELECT id
        FROM challenges

        WHERE
          (
            creator_clan_id=?
            OR
            accepter_clan_id=?
          )

          AND status IN(
            'open',
            'accepted'
          )

          AND id<>?

        LIMIT 1
      `)
      .bind(
        clan.id,
        clan.id,
        challengeId
      )
      .first();


    if (active) {

      return json(
        {
          error:
            "Tu clan ya tiene otro reto activo."
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
    `)
    .bind(
      clan.id,
      challengeId
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
    // ========================================
  // CANCELAR RETO
  // ========================================

  const cancelMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/cancel$/
    );


  if (
    request.method === "POST" &&
    cancelMatch
  ) {

    const challengeId =
      Number(
        cancelMatch[1]
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
      "open"
    ) {

      return json(
        {
          error:
            "Este reto ya ha sido aceptado o no está disponible."
        },
        400,
        headers
      );

    }


    const clan =
      await env.DB.prepare(`
        SELECT *
        FROM clans
        WHERE id=?
      `)
      .bind(
        challenge.creator_clan_id
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
      clan.captain_id !==
      me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán que creó el reto puede cancelarlo."
        },
        403,
        headers
      );

    }


    // IMPORTANTE:
    // No lo marcamos como cancelled.
    // Lo borramos directamente.

    await env.DB.prepare(`
      DELETE FROM challenges
      WHERE id=?
    `)
    .bind(
      challengeId
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


  // ========================================
  // MI CLAN
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/my-clan"
  ) {

    const params =
      new URL(
        request.url
      ).searchParams;


    const league =
      Number(
        params.get("league") || 4
      );


    const clan =
      await getUserClan(
        env,
        me.id,
        league
      );


    if (!clan) {

      return json(
        {
          clan:null,
          members:[]
        },
        200,
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
          u.username
      `)
      .bind(
        clan.id
      )
      .all();


    const score =
      await env.DB.prepare(`
        SELECT
          points,
          wins,
          losses,
          played

        FROM scores

        WHERE
          clan_id=?
          AND league=?
      `)
      .bind(
        clan.id,
        clan.league
      )
      .first();


    return json(
      {
        clan:{
          ...clan,

          points:
            score?.points || 0,

          wins:
            score?.wins || 0,

          losses:
            score?.losses || 0,

          played:
            score?.played || 0
        },

        members:
          members.results
      },
      200,
      headers
    );

  }


  // ========================================
  // EXPULSAR MIEMBRO
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/clans/remove-member"
  ) {

    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    const league =
      Number(
        data.league || 4
      );


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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id !== me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán puede expulsar jugadores."
        },
        403,
        headers
      );

    }


    if (
      userId === me.id
    ) {

      return json(
        {
          error:
            "No puedes expulsarte a ti mismo."
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
        clan.id,
        userId
      )
      .first();


    if (!member) {

      return json(
        {
          error:
            "Ese jugador no pertenece al clan."
        },
        404,
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
      clan.id,
      userId
    )
    .run();


    await env.DB.prepare(`
      INSERT INTO notifications
      (
        user_id,
        title,
        message,
        type
      )

      VALUES
      (
        ?,
        ?,
        ?,
        'clan_removed'
      )
    `)
    .bind(
      userId,
      "Has salido del clan",
      `Has sido expulsado de ${clan.name}.`
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


  // ========================================
  // MODIFICAR CLAN
  // ========================================

  if (
    request.method === "PUT" &&
    path === "/api/clans/edit"
  ) {

    const data =
      await body(request);


    const league =
      Number(
        data.league || 4
      );


    const name =
      String(
        data.name || ""
      )
      .trim()
      .slice(0,24);


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
      .slice(0,500);


    if (
      name.length < 2
    ) {

      return json(
        {
          error:
            "Nombre de clan no válido."
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
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );

    }


    if (
      clan.captain_id !== me.id
    ) {

      return json(
        {
          error:
            "Solo el capitán puede modificar el clan."
        },
        403,
        headers
      );

    }


    const duplicated =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE
          clan_code=?
          AND id<>?
      `)
      .bind(
        clanCode,
        clan.id
      )
      .first();


    if (duplicated) {

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
      WHERE
        id=?
    `)
    .bind(
      name,
      clanCode,
      logoUrl,
      clan.id
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


  // ========================================
  // LEADERBOARD
  // ========================================

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
          AND s.league=c.league

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


  // ========================================
  // CHAT DE RETO
  // ========================================

  const chatMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/chat$/
    );


  if (
    request.method === "GET" &&
    chatMatch
  ) {

    const challengeId =
      Number(
        chatMatch[1]
      );


    const result =
      await env.DB.prepare(`
        SELECT
          cm.id,
          cm.user_id,
          cm.message,
          cm.created_at,
          u.username,
          u.avatar_url

        FROM chat_messages cm

        JOIN users u
          ON u.id=cm.user_id

        WHERE
          cm.challenge_id=?

        ORDER BY
          cm.id ASC

        LIMIT 200
      `)
      .bind(
        challengeId
      )
      .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  if (
    request.method === "POST" &&
    chatMatch
  ) {

    const challengeId =
      Number(
        chatMatch[1]
      );


    const data =
      await body(request);


    const message =
      String(
        data.message || ""
      )
      .trim()
      .slice(0,1000);


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
        WHERE
          id=?
          AND status='accepted'
          AND
          (
            creator_clan_id IN(
              SELECT clan_id
              FROM members
              WHERE user_id=?
            )

            OR

            accepter_clan_id IN(
              SELECT clan_id
              FROM members
              WHERE user_id=?
            )
          )
      `)
      .bind(
        challengeId,
        me.id,
        me.id
      )
      .first();


    if (!challenge) {

      return json(
        {
          error:
            "No puedes acceder a este chat."
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

      VALUES
      (
        ?,
        ?,
        ?
      )
    `)
    .bind(
      challengeId,
      me.id,
      message
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


  // ========================================
  // ADMIN - USUARIOS
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/admin/users"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos de administrador."
        },
        403,
        headers
      );

    }


    const result =
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
      `)
      .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - CLANES
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/admin/clans"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos de administrador."
        },
        403,
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
          c.captain_id,

          u.username
            AS captain_name,

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

        LEFT JOIN users u
          ON u.id=c.captain_id

        LEFT JOIN scores s
          ON s.clan_id=c.id
          AND s.league=c.league

        ORDER BY
          c.league,
          points DESC,
          c.name
      `)
      .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - RETOS
  // ========================================

  if (
    request.method === "GET" &&
    path === "/api/admin/challenges"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos de administrador."
        },
        403,
        headers
      );

    }


    const result =
      await env.DB.prepare(`
        SELECT
          ch.*,

          creator.name
            AS creator_name,

          creator.clan_code
            AS creator_code,

          accepter.name
            AS accepter_name,

          accepter.clan_code
            AS accepter_code

        FROM challenges ch

        LEFT JOIN clans creator
          ON creator.id=
             ch.creator_clan_id

        LEFT JOIN clans accepter
          ON accepter.id=
             ch.accepter_clan_id

        ORDER BY
          ch.id DESC

        LIMIT 500
      `)
      .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - CAMBIAR ID
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/set-psn"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    const psn =
      String(
        data.psn_id || ""
      )
      .trim()
      .slice(0,32);


    const user =
      await env.DB.prepare(`
        SELECT id
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
            "Usuario no encontrado."
        },
        404,
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
      userId
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


  // ========================================
  // ADMIN - BLOQUEAR
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/block"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    const permanent =
      !!data.permanent;


    const minutes =
      Number(
        data.minutes || 60
      );


    const blockedUntil =
      permanent
        ? 0
        : Date.now() +
          minutes *
          60000;


    await env.DB.prepare(`
      UPDATE users
      SET
        is_blocked=1,
        blocked_until=?
      WHERE
        id=?
    `)
    .bind(
      blockedUntil,
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
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - DESBLOQUEAR
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/unblock"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    await env.DB.prepare(`
      UPDATE users
      SET
        is_blocked=0,
        blocked_until=NULL
      WHERE
        id=?
    `)
    .bind(
      userId
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


  // ========================================
  // ADMIN - MODIFICAR RESULTADO
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/set-score"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const clanId =
      Number(
        data.clan_id
      );


    const points =
      Number(
        data.points || 0
      );


    const wins =
      Number(
        data.wins || 0
      );


    const losses =
      Number(
        data.losses || 0
      );


    const played =
      Number(
        data.played || 0
      );


    const clan =
      await env.DB.prepare(`
        SELECT
          id,
          league
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


    await env.DB.prepare(`
      INSERT INTO scores
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
        ?,
        ?,
        ?,
        ?
      )

      ON CONFLICT(clan_id)
      DO UPDATE SET

        points=excluded.points,
        wins=excluded.wins,
        losses=excluded.losses,
        played=excluded.played
    `)
    .bind(
      clan.id,
      clan.league,
      points,
      wins,
      losses,
      played
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


  // ========================================
  // ADMIN - ELIMINAR CLAN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/remove-clan"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const clanId =
      Number(
        data.clan_id
      );


    const clan =
      await env.DB.prepare(`
        SELECT
          id,
          name
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


    await env.DB.batch([

      env.DB.prepare(`
        DELETE FROM members
        WHERE clan_id=?
      `)
      .bind(
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


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - ELIMINAR / CANCELAR RETO
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/delete-challenge"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const challengeId =
      Number(
        data.challenge_id
      );


    await env.DB.prepare(`
      DELETE FROM challenges
      WHERE id=?
    `)
    .bind(
      challengeId
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


  // ========================================
  // ADMIN - REINICIAR LIGA
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/reset-league"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const league =
      Number(
        data.league
      );


    if (
      ![2,3,4].includes(
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


    // Los retos de esa liga
    // también se eliminan.
    await env.DB.prepare(`
      DELETE FROM challenges
      WHERE
        creator_clan_id IN(
          SELECT id
          FROM clans
          WHERE league=?
        )

        OR

        accepter_clan_id IN(
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


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - CAMBIAR DATOS DEL CLAN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/edit-clan"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const clanId =
      Number(
        data.clan_id
      );


    const name =
      String(
        data.name || ""
      )
      .trim()
      .slice(0,24);


    const clanCode =
      String(
        data.clan_code || ""
      )
      .trim()
      .toUpperCase()
      .slice(0,4);


    const league =
      Number(
        data.league
      );


    const logoUrl =
      String(
        data.logo_url || ""
      )
      .trim()
      .slice(0,500);


    if (
      name.length < 2 ||
      !/^[A-Z]{4}$/.test(
        clanCode
      ) ||
      ![2,3,4].includes(
        league
      )
    ) {

      return json(
        {
          error:
            "Datos del clan no válidos."
        },
        400,
        headers
      );

    }


    const duplicate =
      await env.DB.prepare(`
        SELECT
          id
        FROM clans
        WHERE
          clan_code=?
          AND id<>?
      `)
      .bind(
        clanCode,
        clanId
      )
      .first();


    if (duplicate) {

      return json(
        {
          error:
            "La insignia ya está utilizada."
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
        league=?,
        logo_url=?
      WHERE
        id=?
    `)
    .bind(
      name,
      clanCode,
      league,
      logoUrl,
      clanId
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


  // ========================================
  // ADMIN - CAMBIAR CAPITÁN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/set-captain"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const clanId =
      Number(
        data.clan_id
      );


    const userId =
      Number(
        data.user_id
      );


    const member =
      await env.DB.prepare(`
        SELECT
          user_id
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
            "El jugador no pertenece al clan."
        },
        400,
        headers
      );

    }


    await env.DB.batch([

      env.DB.prepare(`
        UPDATE clans
        SET
          captain_id=?
        WHERE
          id=?
      `)
      .bind(
        userId,
        clanId
      ),

      env.DB.prepare(`
        UPDATE members
        SET
          role='member'
        WHERE
          clan_id=?
      `)
      .bind(
        clanId
      ),

      env.DB.prepare(`
        UPDATE members
        SET
          role='captain'
        WHERE
          clan_id=?
          AND user_id=?
      `)
      .bind(
        clanId,
        userId
      )

    ]);


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - EXPULSAR JUGADOR DEL CLAN
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/remove-member"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const clanId =
      Number(
        data.clan_id
      );


    const userId =
      Number(
        data.user_id
      );


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


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - ELIMINAR USUARIO
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/remove-user"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const userId =
      Number(
        data.user_id
      );


    if (
      userId === me.id
    ) {

      return json(
        {
          error:
            "No puedes eliminar tu propia cuenta de administrador."
        },
        400,
        headers
      );

    }


    await env.DB.batch([

      env.DB.prepare(`
        DELETE FROM members
        WHERE user_id=?
      `)
      .bind(
        userId
      ),

      env.DB.prepare(`
        DELETE FROM invites
        WHERE
          inviter_id=?
          OR invitee_id=?
      `)
      .bind(
        userId,
        userId
      ),

      env.DB.prepare(`
        DELETE FROM notifications
        WHERE user_id=?
      `)
      .bind(
        userId
      ),

      env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id=?
      `)
      .bind(
        userId
      ),

      env.DB.prepare(`
        DELETE FROM users
        WHERE id=?
      `)
      .bind(
        userId
      )

    ]);


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // ADMIN - REINICIO TOTAL DE UNA LIGA
  // ========================================

  if (
    request.method === "POST" &&
    path === "/api/admin/reset-results"
  ) {

    if (
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "No tienes permisos."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const league =
      Number(
        data.league
      );


    if (
      ![2,3,4].includes(
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
        ok:true
      },
      200,
      headers
    );

  }


  // ========================================
  // RUTA NO ENCONTRADA
  // ========================================

  return json(
    {
      error:
        "Ruta no encontrada.",
      path
    },
    404,
    headers
  );

}


// ==========================================
// FETCH
// ==========================================

async function fetch(
  request,
  env,
  ctx
) {

  const url =
    new URL(
      request.url
    );


  // API
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


  // ========================================
  // PÁGINA DEL WORKER
  // ========================================

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
      status:404,

      headers:{
        "content-type":
          "text/plain;charset=UTF-8"
      }
    }
  );

}


export default {
  fetch
};
