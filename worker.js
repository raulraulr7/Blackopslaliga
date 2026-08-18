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

var json = /* @__PURE__ */ __name(
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

var body = /* @__PURE__ */ __name(
  async (request) => {
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
      new TextEncoder().encode(
        password
      ),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt:
          new TextEncoder().encode(
            salt
          ),
        iterations: 1e5,
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


  try {

    const oldClans =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE clan_code IS NULL
        OR clan_code=''
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


      await env.DB.prepare(
        `UPDATE clans
         SET clan_code=?
         WHERE id=?`
      )
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

__name(
  isAdmin,
  "isAdmin"
);


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
    ORDER BY c.league
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


async function expireChallenges(
  env
) {

  const now =
    new Date().toISOString();

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
  `)
  .bind(
    now,
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

  await expireChallenges(
    env
  );


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
          864e5
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

      console.error(
        "REGISTER ERROR:",
        error
      );


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
        864e5
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


  const me =
    await getCurrentUser(
      request,
      env
    );


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


  /* =========================
     LEADERBOARD
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/leaderboard"
  ) {

    const url =
      new URL(
        request.url
      );


    const league =
      Number(
        url.searchParams.get(
          "league"
        ) || 4
      );


    const rows =
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
          ) AS played
        FROM clans c
        LEFT JOIN scores s
          ON s.clan_id=c.id
        AND s.league=?
        WHERE c.league=?
        ORDER BY
          points DESC,
          wins DESC,
          losses ASC,
          c.name ASC
      `)
      .bind(
        league,
        league
      )
      .all();


    return json(
      rows.results,
      200,
      headers
    );

  }


  /* =========================
     LISTA DE CLANES
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/clans"
  ) {

    const url =
      new URL(
        request.url
      );


    const q =
      String(
        url.searchParams.get(
          "q"
        ) || ""
      ).trim();


    const league =
      url.searchParams.get(
        "league"
      );


    let rows;


    if (league) {

      rows =
        await env.DB.prepare(`
          SELECT
            c.id,
            c.name,
            c.captain_id,
            c.league,
            c.clan_code,
            c.logo_url,
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
          LEFT JOIN scores s
            ON s.clan_id=c.id
          AND s.league=c.league
          WHERE
            c.league=?
            AND (
              ?=''
              OR LOWER(c.name)
                LIKE LOWER(?)
              OR LOWER(
                c.clan_code
              )
                LIKE LOWER(?)
            )
          ORDER BY
            c.name ASC
        `)
        .bind(
          Number(league),
          q,
          `%${q}%`,
          `%${q}%`
        )
        .all();

    } else {

      rows =
        await env.DB.prepare(`
          SELECT
            c.id,
            c.name,
            c.captain_id,
            c.league,
            c.clan_code,
            c.logo_url,
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
          LEFT JOIN scores s
            ON s.clan_id=c.id
          AND s.league=c.league
          WHERE
            ?=''
            OR LOWER(c.name)
              LIKE LOWER(?)
            OR LOWER(
              c.clan_code
            )
              LIKE LOWER(?)
          ORDER BY
            c.name ASC
        `)
        .bind(
          q,
          `%${q}%`,
          `%${q}%`
        )
        .all();

    }


    return json(
      rows.results,
      200,
      headers
    );

  }


  /* =========================
     VER CLAN
  ========================= */

  const clanMatch =
    path.match(
      /^\/api\/clans\/(\d+)$/
    );


  if (
    request.method === "GET" &&
    clanMatch
  ) {

    const clanId =
      Number(
        clanMatch[1]
      );


    const clan =
      await env.DB.prepare(`
        SELECT
          c.id,
          c.name,
          c.captain_id,
          c.league,
          c.clan_code,
          c.logo_url,
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
        LEFT JOIN scores s
          ON s.clan_id=c.id
        AND s.league=c.league
        WHERE c.id=?
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


  /* =========================
     USUARIOS
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/users"
  ) {

    const url =
      new URL(
        request.url
      );


    const q =
      String(
        url.searchParams.get(
          "q"
        ) || ""
      ).trim();


    const users =
      await env.DB.prepare(`
        SELECT
          id,
          username,
          psn_id,
          avatar_url
        FROM users
        WHERE
          LOWER(username)
          LIKE LOWER(?)
        ORDER BY
          username ASC
        LIMIT 20
      `)
      .bind(
        `%${q}%`
      )
      .all();


    return json(
      users.results,
      200,
      headers
    );

  }


  /* =========================
     VER PERFIL
  ========================= */

  const userMatch =
    path.match(
      /^\/api\/users\/(\d+)$/
    );


  if (
    request.method === "GET" &&
    userMatch
  ) {

    const userId =
      Number(
        userMatch[1]
      );


    const user =
      await env.DB.prepare(`
        SELECT
          id,
          username,
          psn_id,
          psn_changed_at,
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
            "Usuario no encontrado."
        },
        404,
        headers
      );

    }


    return json(
      {
        user
      },
      200,
      headers
    );

  }


  /* =========================
     ACTUALIZAR PERFIL
  ========================= */

  if (
    request.method === "PUT" &&
    path === "/api/profile"
  ) {

    const data =
      await body(request);


    const psn =
      String(
        data.psn_id || ""
      ).trim();


    const avatar =
      String(
        data.avatar_url || ""
      ).trim();


    const now =
      Date.now();


    const user =
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
        user.psn_id || ""
      )
    ) {

      if (
        user.psn_changed_at &&
        now -
          Number(
            user.psn_changed_at
          ) <
          24 * 60 * 60 * 1000
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
        now,
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
    /* =========================
     MI CLAN
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/my-clan"
  ) {

    const clan =
      await getUserClan(
        env,
        me.id
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
          u.username ASC
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


  /* =========================
     CREAR CLAN
  ========================= */

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


    const clanCode =
      String(
        data.clan_code || ""
      )
      .trim()
      .toUpperCase();


    const logoUrl =
      String(
        data.logo_url || ""
      ).trim();


    const league =
      Number(
        data.league || 4
      );


    if (
      !name ||
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


    const existingClan =
      await getUserClan(
        env,
        me.id
      );


    if (existingClan) {

      return json(
        {
          error:
            "Ya perteneces a un clan."
        },
        400,
        headers
      );

    }


    const existingCode =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE
          clan_code=?
      `)
      .bind(
        clanCode
      )
      .first();


    if (existingCode) {

      return json(
        {
          error:
            "Esa insignia ya está utilizada."
        },
        400,
        headers
      );

    }


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
      VALUES (?,?,0,0,0,0)
    `)
    .bind(
      clanId,
      league
    )
    .run();


    return json(
      {
        ok:true,
        clan_id:clanId
      },
      201,
      headers
    );

  }


  /* =========================
     MODIFICAR CLAN
  ========================= */

  const editClanMatch =
    path.match(
      /^\/api\/clans\/(\d+)$/
    );


  if (
    request.method === "PUT" &&
    editClanMatch
  ) {

    const clanId =
      Number(
        editClanMatch[1]
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
            "Solo el capitán puede modificar el clan."
        },
        403,
        headers
      );

    }


    const data =
      await body(request);


    const name =
      String(
        data.name || ""
      ).trim();


    const clanCode =
      String(
        data.clan_code || ""
      )
      .trim()
      .toUpperCase();


    const logoUrl =
      String(
        data.logo_url || ""
      ).trim();


    if (
      !name ||
      name.length < 2 ||
      name.length > 24
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


    const duplicated =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE
          clan_code=?
          AND id!=?
      `)
      .bind(
        clanCode,
        clanId
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
        ok:true
      },
      200,
      headers
    );

  }


  /* =========================
     INVITAR JUGADOR
  ========================= */

  if (
    request.method === "POST" &&
    path === "/api/invites"
  ) {

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


    const target =
      await env.DB.prepare(`
        SELECT
          id,
          username
        FROM users
        WHERE id=?
      `)
      .bind(
        userId
      )
      .first();


    if (!target) {

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
      await env.DB.prepare(`
        SELECT
          1
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


    if (already) {

      return json(
        {
          error:
            "Ese jugador ya pertenece al clan."
        },
        400,
        headers
      );

    }


    const pending =
      await env.DB.prepare(`
        SELECT
          id
        FROM invites
        WHERE
          clan_id=?
          AND invitee_id=?
          AND status='pending'
      `)
      .bind(
        clanId,
        userId
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
      VALUES (?,?,?,'clan_invite')
    `)
    .bind(
      userId,
      "Invitación de clan",
      `Has recibido una invitación para unirte a ${clan.name}.`
    )
    .run();


    return json(
      {
        ok:true
      },
      201,
      headers
    );

  }


  /* =========================
     ACEPTAR INVITACIÓN
  ========================= */

  const inviteAcceptMatch =
    path.match(
      /^\/api\/invites\/(\d+)\/accept$/
    );


  if (
    request.method === "POST" &&
    inviteAcceptMatch
  ) {

    const inviteId =
      Number(
        inviteAcceptMatch[1]
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


    const currentClan =
      await getUserClan(
        env,
        me.id
      );


    if (currentClan) {

      return json(
        {
          error:
            "Ya perteneces a un clan."
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
      VALUES (?,?, 'member')
    `)
    .bind(
      invite.clan_id,
      me.id
    )
    .run();


    await env.DB.prepare(`
      UPDATE invites
      SET status='accepted'
      WHERE id=?
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


  /* =========================
     RECHAZAR INVITACIÓN
  ========================= */

  const inviteRejectMatch =
    path.match(
      /^\/api\/invites\/(\d+)\/reject$/
    );


  if (
    request.method === "POST" &&
    inviteRejectMatch
  ) {

    const inviteId =
      Number(
        inviteRejectMatch[1]
      );


    const result =
      await env.DB.prepare(`
        UPDATE invites
        SET status='rejected'
        WHERE
          id=?
          AND invitee_id=?
          AND status='pending'
      `)
      .bind(
        inviteId,
        me.id
      )
      .run();


    if (
      !result.meta.changes
    ) {

      return json(
        {
          error:
            "Invitación no encontrada."
        },
        404,
        headers
      );

    }


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  /* =========================
     VER INVITACIONES
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/invites"
  ) {

    const invites =
      await env.DB.prepare(`
        SELECT
          i.id,
          i.clan_id,
          i.inviter_id,
          i.invitee_id,
          i.status,
          i.created_at,
          c.name AS clan_name,
          c.clan_code,
          c.logo_url,
          u.username AS inviter_name
        FROM invites i
        JOIN clans c
          ON c.id=i.clan_id
        JOIN users u
          ON u.id=i.inviter_id
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
      invites.results,
      200,
      headers
    );

  }


  /* =========================
     EXPULSAR MIEMBRO
  ========================= */

  const removeMemberMatch =
    path.match(
      /^\/api\/clans\/(\d+)\/members\/(\d+)$/
    );


  if (
    request.method === "DELETE" &&
    removeMemberMatch
  ) {

    const clanId =
      Number(
        removeMemberMatch[1]
      );


    const userId =
      Number(
        removeMemberMatch[2]
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
            "Solo el capitán puede expulsar jugadores."
        },
        403,
        headers
      );

    }


    if (
      Number(
        userId
      ) ===
      Number(
        me.id
      )
    ) {

      return json(
        {
          error:
            "El capitán no puede expulsarse a sí mismo."
        },
        400,
        headers
      );

    }


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
      clanId,
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
      VALUES (?,?,?,'clan_removed')
    `)
    .bind(
      userId,
      "Clan",
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


  /* =========================
     CAMBIAR CAPITÁN
  ========================= */

  const captainMatch =
    path.match(
      /^\/api\/clans\/(\d+)\/captain\/(\d+)$/
    );


  if (
    request.method === "POST" &&
    captainMatch
  ) {

    const clanId =
      Number(
        captainMatch[1]
      );


    const newCaptainId =
      Number(
        captainMatch[2]
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
            "Solo el capitán actual puede cambiar el capitán."
        },
        403,
        headers
      );

    }


    const newCaptain =
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
        newCaptainId
      )
      .first();


    if (!newCaptain) {

      return json(
        {
          error:
            "El nuevo capitán debe pertenecer al clan."
        },
        400,
        headers
      );

    }


    await env.DB.prepare(`
      UPDATE clans
      SET captain_id=?
      WHERE id=?
    `)
    .bind(
      newCaptainId,
      clanId
    )
    .run();


    await env.DB.prepare(`
      UPDATE members
      SET role='member'
      WHERE
        clan_id=?
    `)
    .bind(
      clanId
    )
    .run();


    await env.DB.prepare(`
      UPDATE members
      SET role='captain'
      WHERE
        clan_id=?
        AND user_id=?
    `)
    .bind(
      clanId,
      newCaptainId
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


  /* =========================
     RETOS
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/challenges"
  ) {

    const url =
      new URL(
        request.url
      );


    const league =
      Number(
        url.searchParams.get(
          "league"
        ) || 4
      );


    const rows =
      await env.DB.prepare(`
        SELECT
          ch.id,
          ch.creator_clan_id,
          ch.accepter_clan_id,
          ch.status,
          ch.map1,
          ch.map2,
          ch.map3,
          ch.team_size,
          ch.created_at,
          ch.expires_at
        FROM challenges ch
        JOIN clans creator
          ON creator.id=
             ch.creator_clan_id
        WHERE
          creator.league=?
        ORDER BY
          ch.id DESC
      `)
      .bind(
        league
      )
      .all();


    return json(
      rows.results,
      200,
      headers
    );

  }


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
        data.team_size ||
        league
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
            "Debes pertenecer a un clan de esta liga."
        },
        400,
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
            "Solo el capitán puede publicar retos."
        },
        403,
        headers
      );

    }


    const maps =
      randomMaps();


    const createdAt =
      new Date();


    const expires =
      new Date(
        createdAt.getTime() +
        30 * 60 * 1000
      );


    const result =
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
          created_at,
          expires_at
        )
        VALUES
        (?,?,?,?,?,?,?,?,?)
      `)
      .bind(
        clan.id,
        "open",
        maps[0],
        maps[1],
        maps[2],
        teamSize,
        JSON.stringify(
          data.game_modes ||
          ["snd"]
        ),
        createdAt.toISOString(),
        expires.toISOString()
      )
      .run();


    return json(
      {
        ok:true,
        challenge_id:
          result.meta.last_row_id
      },
      201,
      headers
    );

  }


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


    const data =
      await body(request);


    const reason =
      String(
        data.reason ||
        "Reto cancelado por el capitán."
      ).trim();


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
            "Este reto ya no está disponible."
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
            "Solo el capitán que publicó el reto puede cancelarlo."
        },
        403,
        headers
      );

    }


    await env.DB.prepare(`
      UPDATE challenges
      SET
        status='cancelled',
        cancel_reason=?,
        cancelled_at=?
      WHERE id=?
    `)
    .bind(
      reason,
      new Date().toISOString(),
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
    /* =========================
     ACEPTAR RETO
  ========================= */

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
            "Este reto ya no está disponible."
        },
        400,
        headers
      );

    }


    const creatorClan =
      await env.DB.prepare(`
        SELECT *
        FROM clans
        WHERE id=?
      `)
      .bind(
        challenge.creator_clan_id
      )
      .first();


    if (!creatorClan) {

      return json(
        {
          error:
            "Clan creador no encontrado."
        },
        404,
        headers
      );

    }


    const opponentClan =
      await getUserClan(
        env,
        me.id,
        creatorClan.league
      );


    if (!opponentClan) {

      return json(
        {
          error:
            "Debes pertenecer a un clan de esta liga."
        },
        400,
        headers
      );

    }


    if (
      Number(
        opponentClan.id
      ) ===
      Number(
        creatorClan.id
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


    if (
      Number(
        opponentClan.captain_id
      ) !==
      Number(
        me.id
      )
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
      opponentClan.id,
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


  /* =========================
     ADMIN
  ========================= */

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


    const users =
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
      users.results,
      200,
      headers
    );

  }


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


    const clans =
      await env.DB.prepare(`
        SELECT
          c.id,
          c.name,
          c.captain_id,
          c.league,
          c.clan_code,
          c.logo_url,
          u.username AS captain_name,
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
        AND s.league=c.league
        ORDER BY
          c.id DESC
      `)
      .all();


    return json(
      clans.results,
      200,
      headers
    );

  }


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


    const challenges =
      await env.DB.prepare(`
        SELECT
          ch.*,
          creator.name
            AS creator_clan_name,
          accepter.name
            AS accepter_clan_name
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
      challenges.results,
      200,
      headers
    );

  }


  /* =========================
     BLOQUEAR USUARIO
  ========================= */

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


    const until =
      permanent
      ?
      0
      :
      Date.now() +
        minutes *
        60 *
        1000;


    await env.DB.prepare(`
      UPDATE users
      SET
        is_blocked=1,
        blocked_until=?
      WHERE id=?
    `)
    .bind(
      until,
      userId
    )
    .run();


    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id=?
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


  /* =========================
     DESBLOQUEAR USUARIO
  ========================= */

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
      WHERE id=?
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


  /* =========================
     ADMIN CAMBIAR ID
  ========================= */

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
      ).trim();


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


  /* =========================
     ADMIN MODIFICAR RESULTADO
  ========================= */

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
      VALUES (?,?,?,?,?,?)
      ON CONFLICT(clan_id)
      DO UPDATE SET
        points=excluded.points,
        wins=excluded.wins,
        losses=excluded.losses,
        played=excluded.played
    `)
    .bind(
      clanId,
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


  /* =========================
     ADMIN ELIMINAR CLAN
  ========================= */

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


    await env.DB.prepare(`
      DELETE FROM members
      WHERE clan_id=?
    `)
    .bind(
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
        ok:true
      },
      200,
      headers
    );

  }


  /* =========================
     ADMIN CANCELAR RETO
  ========================= */

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


    const result =
      await env.DB.prepare(`
        UPDATE challenges
        SET
          status='cancelled',
          cancel_reason=
            'Cancelado por administración',
          cancelled_at=?
        WHERE id=?
      `)
      .bind(
        new Date().toISOString(),
        challengeId
      )
      .run();


    if (
      !result.meta.changes
    ) {

      return json(
        {
          error:
            "Reto no encontrado."
        },
        404,
        headers
      );

    }


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  /* =========================
     ADMIN REINICIAR LIGA
  ========================= */

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
      WHERE league=?
    `)
    .bind(
      league
    )
    .run();


    await env.DB.prepare(`
      UPDATE challenges
      SET
        status='cancelled',
        cancel_reason=
          'Liga reiniciada por administración',
        cancelled_at=?
      WHERE
        status IN
        ('open','accepted')
        AND creator_clan_id IN
        (
          SELECT id
          FROM clans
          WHERE league=?
        )
    `)
    .bind(
      new Date().toISOString(),
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


  /* =========================
     RUTA NO ENCONTRADA
  ========================= */

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


__name(
  api,
  "api"
);


/* =========================
   FETCH
========================= */

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


  return new Response(
    "Ruta no encontrada.",
    {
      status:404
    }
  );

}


export default {
  fetch
};
