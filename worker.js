var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", {
  value,
  configurable: true
});

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
          "content-type": "application/json;charset=UTF-8",
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
  const origin = request.headers.get("Origin");

  return {
    "Access-Control-Allow-Methods":
      "GET,POST,PUT,DELETE,OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type",

    "Access-Control-Allow-Credentials":
      "true",

    ...origin
      ? {
          "Access-Control-Allow-Origin":
            origin,

          "Vary":
            "Origin"
        }
      : {}
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
        iterations:
          1e5,
        hash:
          "SHA-256"
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

__name(hashPassword, "hashPassword");

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

__name(verifyPassword, "verifyPassword");

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
          ) + code;

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
      () =>
        Math.random() -
        0.5
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
    new Date()
      .toISOString();

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
        status: 204,
        headers
      }
    );

  }

  await initDatabase(env);

  await expireChallenges(env);

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
        .bind(username)
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
        created.meta
          .last_row_id;

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
          ok: true,

          user: {
            id: userId,
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
        .bind(username)
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
        ok: true,

        user: {
          id: user.id,
          username:
            user.username,
          psn_id:
            user.psn_id
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
        .bind(token)
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

      const remaining =
        24 * 60 * 60 * 1000 -
        (
          Date.now() -
          Number(
            me.psn_changed_at
          )
        );

      return json(
        {
          error:
            "Solo puedes cambiar tu ID una vez cada 24 horas.",
          retry_after_ms:
            remaining
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
        WHERE username LIKE ?
        ORDER BY username
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

  if (
    request.method === "GET" &&
    /^\/api\/users\/\d+$/
      .test(path)
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
        .bind(id)
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
          c.league
        FROM clans c
        JOIN members m
          ON m.clan_id=c.id
        WHERE m.user_id=?
        ORDER BY c.league
      `)
        .bind(id)
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

      WHERE c.name LIKE ?
    `;

    const values = [
      "%" +
      query +
      "%"
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

  if (
    request.method === "GET" &&
    /^\/api\/clans\/\d+$/
      .test(path)
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

        WHERE c.id=?
      `)
        .bind(id)
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
        .bind(id)
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
      )
        .trim()
        .slice(0, 500);

    const league =
      Number(
        data.league
      );

    if (
      name.length < 2 ||
      name.length > 24 ||
      !/^[A-Z]{4}$/
        .test(clanCode) ||
      ![2,3,4].includes(
        league
      )
    ) {

      return json(
        {
          error:
            "Nombre 2-24 caracteres, insignia de exactamente 4 letras y liga 2v2, 3v3 o 4v4."
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

    const existingCode =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE clan_code=?
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
        created.meta
          .last_row_id;

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
          league
        )
        VALUES (?,?)
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

  if (
    request.method === "GET" &&
    path === "/api/leaderboard"
  ) {

    const league =
      Number(
        new URL(
          request.url
        ).searchParams
          .get("league") || 4
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

        WHERE c.league=?

        ORDER BY
          points DESC,
          wins DESC,
          name
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
   INVITACIONES
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/clans\/\d+\/invite$/.test(path)
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
    ).trim();


  const clan =
    await env.DB.prepare(`
      SELECT *
      FROM clans
      WHERE id=?
    `)
      .bind(clanId)
      .first();


  if(!clan){

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(
      clan.captain_id
    ) !==
    Number(me.id)
  ){

    return json(
      {
        error:
          "Solo el capitán puede invitar jugadores."
      },
      403,
      headers
    );

  }


  let user;


  if(targetUserId){

    user =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE id=?
      `)
        .bind(
          targetUserId
        )
        .first();

  }else{

    user =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE username=?
      `)
        .bind(
          targetUsername
        )
        .first();

  }


  if(!user){

    return json(
      {
        error:
          "Jugador no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(user.id) ===
    Number(me.id)
  ){

    return json(
      {
        error:
          "No puedes invitarte a ti mismo."
      },
      400,
      headers
    );

  }


  const already =
    await env.DB.prepare(`
      SELECT 1
      FROM members m
      JOIN clans c
        ON c.id=m.clan_id
      WHERE
        m.user_id=?
        AND c.league=?
    `)
      .bind(
        user.id,
        clan.league
      )
      .first();


  if(already){

    return json(
      {
        error:
          "Ese jugador ya pertenece a un clan de esta liga."
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
    `)
      .bind(
        clanId,
        user.id
      )
      .first();


  if(pending){

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
        user.id
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
    VALUES (?,?,?,?)
  `)
    .bind(
      user.id,
      "🛡️ Invitación a clan",
      `${me.username} te ha invitado al clan ${clan.name}.`,
      "clan_invite"
    )
    .run();


  return json(
    {
      ok:true,
      inviteId:
        created.meta.last_row_id
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

  const result =
    await env.DB.prepare(`
      SELECT
        c.id,
        c.name,
        c.clan_code,
        c.logo_url,
        c.league,
        c.captain_id,

        CASE
          WHEN c.captain_id=?
          THEN 'captain'
          ELSE 'member'
        END AS my_role,

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

      JOIN members m
        ON m.clan_id=c.id

      LEFT JOIN scores s
        ON s.clan_id=c.id

      WHERE
        m.user_id=?

      ORDER BY
        c.league
    `)
      .bind(
        me.id,
        me.id
      )
      .all();


  const clans =
    result.results;


  for(
    const clan
    of clans
  ){

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


    clan.members =
      members.results;

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
   INVITACIONES / NOTIFICACIONES
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/notifications"
) {

  const result =
    await env.DB.prepare(`
      SELECT
        n.*,

        i.id AS invite_id,
        i.clan_id,
        i.status AS invite_status,

        c.name AS clan_name,
        c.clan_code,
        c.league

      FROM notifications n

      LEFT JOIN invites i
        ON i.id=n.id

      LEFT JOIN clans c
        ON c.id=i.clan_id

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
        i.status,
        i.created_at,

        c.name AS clan_name,
        c.clan_code,
        c.league,

        u.username AS inviter_username

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
        result.results,

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
        c.name AS clan_name,
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


  if(!invite){

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


  if(existing){

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
    SET status='accepted'
    WHERE id=?
  `)
    .bind(
      inviteId
    )
    .run();


  await env.DB.prepare(`
    UPDATE notifications
    SET is_read=1
    WHERE
      user_id=?
      AND type='clan_invite'
  `)
    .bind(
      me.id
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
    VALUES (?,?,?,?)
  `)
    .bind(
      invite.captain_id,
      "👤 Nuevo jugador",
      `${me.username} ha aceptado la invitación al clan ${invite.clan_name}.`,
      "clan_member"
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


  if(!invite){

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
    SET status='rejected'
    WHERE id=?
  `)
    .bind(
      inviteId
    )
    .run();


  await env.DB.prepare(`
    UPDATE notifications
    SET is_read=1
    WHERE
      user_id=?
      AND type='clan_invite'
  `)
    .bind(
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


/* =====================================================
   MARCAR NOTIFICACIÓN LEÍDA
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/notifications\/\d+\/read$/
    .test(path)
) {

  const id =
    Number(
      path.split("/")[3]
    );


  await env.DB.prepare(`
    UPDATE notifications
    SET is_read=1
    WHERE
      id=?
      AND user_id=?
  `)
    .bind(
      id,
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


/* =====================================================
   ABANDONAR CLAN
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/clans\/\d+\/leave$/
    .test(path)
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
      .bind(
        clanId
      )
      .first();


  if(!clan){

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(clan.captain_id) ===
    Number(me.id)
  ){

    return json(
      {
        error:
          "El capitán no puede abandonar el clan. Debe eliminarlo o pasar el cargo."
      },
      400,
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


  if(!membership){

    return json(
      {
        error:
          "No perteneces a este clan."
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
      ok:true
    },
    200,
    headers
  );

}


/* =====================================================
   ELIMINAR CLAN — CAPITÁN
===================================================== */

if (
  request.method === "DELETE" &&
  /^\/api\/clans\/\d+$/
    .test(path)
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


  if(!clan){

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(clan.captain_id) !==
    Number(me.id) &&
    !isAdmin(me)
  ){

    return json(
      {
        error:
          "Solo el capitán puede eliminar el clan."
      },
      403,
      headers
    );

  }


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
      ok:true
    },
    200,
    headers
  );

}


/* =====================================================
   EXPULSAR JUGADOR DEL CLAN
===================================================== */

if (
  request.method === "DELETE" &&
  /^\/api\/clans\/\d+\/members\/\d+$/
    .test(path)
) {

  const parts =
    path.split("/");

  const clanId =
    Number(
      parts[3]
    );

  const userId =
    Number(
      parts[5]
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


  if(!clan){

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(clan.captain_id) !==
    Number(me.id) &&
    !isAdmin(me)
  ){

    return json(
      {
        error:
          "Solo el capitán puede expulsar jugadores."
      },
      403,
      headers
    );

  }


  if(
    Number(clan.captain_id) ===
    Number(userId)
  ){

    return json(
      {
        error:
          "No puedes expulsar al capitán."
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


  await env.DB.prepare(`
    INSERT INTO notifications
    (
      user_id,
      title,
      message,
      type
    )
    VALUES (?,?,?,?)
  `)
    .bind(
      userId,
      "🚫 Expulsado del clan",
      `Has sido expulsado del clan ${clan.name}.`,
      "clan_removed"
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


/* =====================================================
   EDITAR CLAN
===================================================== */

if (
  request.method === "PUT" &&
  /^\/api\/clans\/\d+$/
    .test(path)
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


  if(!clan){

    return json(
      {
        error:
          "Clan no encontrado."
      },
      404,
      headers
    );

  }


  if(
    Number(clan.captain_id) !==
    Number(me.id) &&
    !isAdmin(me)
  ){

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
      data.name ??
      clan.name
    )
      .trim();


  const code =
    String(
      data.clan_code ??
      clan.clan_code
    )
      .trim()
      .toUpperCase();


  const logo =
    String(
      data.logo_url ??
      clan.logo_url ??
      ""
    )
      .trim()
      .slice(0,500);


  if(
    name.length < 2 ||
    name.length > 24
  ){

    return json(
      {
        error:
          "Nombre de clan no válido."
      },
      400,
      headers
    );

  }


  if(
    !/^[A-Z]{4}$/.test(code)
  ){

    return json(
      {
        error:
          "La insignia debe tener exactamente 4 letras."
      },
      400,
      headers
    );

  }


  const duplicate =
    await env.DB.prepare(`
      SELECT id
      FROM clans
      WHERE
        clan_code=?
        AND id!=?
    `)
      .bind(
        code,
        clanId
      )
      .first();


  if(duplicate){

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
      code,
      logo,
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


/* =====================================================
   RETOS — CREAR
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


  if(
    ![2,3,4].includes(
      league
    )
  ){

    return json(
      {
        error:
          "La liga 1v1 todavía necesita su configuración específica."
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


  if(!clan){

    return json(
      {
        error:
          "Necesitas tener un clan en esta liga."
      },
      400,
      headers
    );

  }


  const memberCount =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM members
      WHERE clan_id=?
    `)
      .bind(
        clan.id
      )
      .first();


  const minimumPlayers =
    league;


  if(
    Number(
      memberCount.total
    ) <
    minimumPlayers
  ){

    return json(
      {
        error:
          `Tu clan necesita al menos ${minimumPlayers} jugadores inscritos para poder lanzar un reto.`
      },
      400,
      headers
    );

  }


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


  if(active){

    return json(
      {
        error:
          "Tu clan ya tiene un reto abierto."
      },
      400,
      headers
    );

  }


  const maps =
    randomMaps();


  const now =
    new Date();


  const expires =
    new Date(
      now.getTime() +
      30 * 60 * 1000
    );


  const mode =
    String(
      data.mode ||
      "snd"
    );


  const modes =
    JSON.stringify([
      mode
    ]);


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
        created_at,
        expires_at
      )
      VALUES
      (?,'open',?,?,?,?,?,?,?)
    `)
      .bind(
        clan.id,
        maps[0],
        maps[1],
        maps[2],
        league,
        modes,
        now.toISOString(),
        expires.toISOString()
      )
      .run();


  return json(
    {
      ok:true,
      challengeId:
        created.meta.last_row_id,
      expires_at:
        expires.toISOString()
    },
    200,
    headers
  );

}


/* =====================================================
   FIN PARTE 2
===================================================== */
/* =====================================================
   ACEPTAR RETO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/accept$/.test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );

  const challenge =
    await env.DB.prepare(`
      SELECT
        ch.*,
        c.name AS creator_clan_name,
        c.clan_code AS creator_clan_code,
        c.league
      FROM challenges ch
      JOIN clans c
        ON c.id=ch.creator_clan_id
      WHERE ch.id=?
    `)
      .bind(challengeId)
      .first();


  if(!challenge){

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  if(
    challenge.status !==
    "open"
  ){

    return json(
      {
        error:
          "Este reto ya no está disponible."
      },
      400,
      headers
    );

  }


  if(
    challenge.expires_at &&
    challenge.expires_at <=
    new Date().toISOString()
  ){

    await env.DB.prepare(`
      UPDATE challenges
      SET
        status='expired',
        cancel_reason='No aceptado en 30 minutos',
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


  if(!myClan){

    return json(
      {
        error:
          "Necesitas pertenecer a un clan de esta liga."
      },
      400,
      headers
    );

  }


  if(
    Number(myClan.id) ===
    Number(
      challenge.creator_clan_id
    )
  ){

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
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM members
      WHERE clan_id=?
    `)
      .bind(
        myClan.id
      )
      .first();


  if(
    Number(memberCount.total) <
    Number(challenge.team_size)
  ){

    return json(
      {
        error:
          `Tu clan necesita al menos ${challenge.team_size} jugadores inscritos para aceptar este reto.`
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
      myClan.id,
      challengeId
    )
    .run();


  const creatorMembers =
    await env.DB.prepare(`
      SELECT user_id
      FROM members
      WHERE clan_id=?
    `)
      .bind(
        challenge.creator_clan_id
      )
      .all();


  for(
    const member
    of creatorMembers.results
  ){

    await env.DB.prepare(`
      INSERT INTO notifications
      (
        user_id,
        title,
        message,
        type
      )
      VALUES (?,?,?,?)
    `)
      .bind(
        member.user_id,
        "⚔️ Reto aceptado",
        `${myClan.name} ha aceptado el reto. Ya puedes ver el enfrentamiento.`,
        "challenge_accepted"
      )
      .run();

  }


  const accepterMembers =
    await env.DB.prepare(`
      SELECT user_id
      FROM members
      WHERE clan_id=?
    `)
      .bind(
        myClan.id
      )
      .all();


  for(
    const member
    of accepterMembers.results
  ){

    await env.DB.prepare(`
      INSERT INTO notifications
      (
        user_id,
        title,
        message,
        type
      )
      VALUES (?,?,?,?)
    `)
      .bind(
        member.user_id,
        "⚔️ Reto aceptado",
        `Has aceptado el reto contra ${challenge.creator_clan_name}.`,
        "challenge_accepted"
      )
      .run();

  }


  return json(
    {
      ok:true,

      challenge:{
        id:challengeId,

        creator_clan_id:
          challenge.creator_clan_id,

        creator_clan_name:
          challenge.creator_clan_name,

        accepter_clan_id:
          myClan.id,

        accepter_clan_name:
          myClan.name,

        map1:
          challenge.map1,

        map2:
          challenge.map2,

        map3:
          challenge.map3,

        team_size:
          challenge.team_size,

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
   CANCELAR RETO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/cancel$/.test(path)
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


  if(!challenge){

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
      challenge.team_size
    );


  if(
    !myClan ||
    (
      Number(
        myClan.id
      ) !==
      Number(
        challenge.creator_clan_id
      ) &&
      Number(
        myClan.id
      ) !==
      Number(
        challenge.accepter_clan_id
      )
    )
  ){

    return json(
      {
        error:
          "No tienes permiso para cancelar este reto."
      },
      403,
      headers
    );

  }


  if(
    challenge.status !==
    "open"
  ){

    return json(
      {
        error:
          "Solo se pueden cancelar retos que todavía no han sido aceptados."
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
      cancel_reason='Cancelado por el clan',
      cancelled_at=?
    WHERE id=?
  `)
    .bind(
      now,
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


/* =====================================================
   RETOS ACTIVOS
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
      params.get("league") || 4
    );


  let result;


  if(
    [2,3,4].includes(
      league
    )
  ){

    result =
      await env.DB.prepare(`
        SELECT
          ch.id,

          ch.status,

          ch.map1,
          ch.map2,
          ch.map3,

          ch.team_size,
          ch.game_modes,

          ch.created_at,
          ch.expires_at,

          ch.creator_clan_id,

          c.name AS creator_clan_name,
          c.clan_code AS creator_clan_code

        FROM challenges ch

        JOIN clans c
          ON c.id=ch.creator_clan_id

        WHERE
          ch.status IN
          ('open','accepted')

          AND c.league=?

        ORDER BY
          ch.created_at DESC

        LIMIT 100
      `)
        .bind(
          league
        )
        .all();

  }else{

    result =
      {
        results:[]
      };

  }


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
   RETO INDIVIDUAL
===================================================== */

if (
  request.method === "GET" &&
  /^\/api\/challenges\/\d+$/.test(path)
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

        accepter.name
          AS accepter_clan_name,

        accepter.clan_code
          AS accepter_clan_code

      FROM challenges ch

      JOIN clans creator
        ON creator.id=
           ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id=
           ch.accepter_clan_id

      WHERE ch.id=?
    `)
      .bind(
        challengeId
      )
      .first();


  if(!challenge){

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

      ...challenge,

      game_modes:
        JSON.parse(
          challenge.game_modes ||
          "[]"
        )

    },
    200,
    headers
  );

}


/* =====================================================
   REPORTAR RESULTADO
===================================================== */

if (
  request.method === "POST" &&
  /^\/api\/challenges\/\d+\/result$/.test(path)
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


  if(!challenge){

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  if(
    challenge.status !==
    "accepted"
  ){

    return json(
      {
        error:
          "El reto no está activo."
      },
      400,
      headers
    );

  }


  if(
    winnerClanId !==
    Number(
      challenge.creator_clan_id
    ) &&
    winnerClanId !==
    Number(
      challenge.accepter_clan_id
    )
  ){

    return json(
      {
        error:
          "Ganador no válido."
      },
      400,
      headers
    );

  }


  const myClan =
    await getUserClan(
      env,
      me.id,
      challenge.team_size
    );


  if(!myClan){

    return json(
      {
        error:
          "No perteneces a un clan de este reto."
      },
      400,
      headers
    );

  }


  if(
    Number(myClan.id) !==
    Number(
      challenge.creator_clan_id
    ) &&
    Number(myClan.id) !==
    Number(
      challenge.accepter_clan_id
    )
  ){

    return json(
      {
        error:
          "Tu clan no participa en este reto."
      },
      403,
      headers
    );

  }


  const existing =
    await env.DB.prepare(`
      SELECT *
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


  if(existing){

    return json(
      {
        error:
          "Ya has enviado tu resultado."
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


  const reports =
    await env.DB.prepare(`
      SELECT
        winner_clan_id
      FROM reports
      WHERE challenge_id=?
    `)
      .bind(
        challengeId
      )
      .all();


  const reportRows =
    reports.results;


  if(
    reportRows.length >= 2
  ){

    const first =
      Number(
        reportRows[0]
          .winner_clan_id
      );

    const second =
      Number(
        reportRows[1]
          .winner_clan_id
      );


    if(
      first === second
    ){

      const loserClanId =
        first ===
        Number(
          challenge.creator_clan_id
        )
          ?
            Number(
              challenge.accepter_clan_id
            )
          :
            Number(
              challenge.creator_clan_id
            );


      await env.DB.prepare(`
        UPDATE challenges

        SET
          status='completed',
          winner_clan_id=?,
          completed_at=?

        WHERE id=?
      `)
        .bind(
          first,
          new Date().toISOString(),
          challengeId
        )
        .run();


      await updateScore(
        env,
        first,
        true,
        challenge.team_size
      );


      await updateScore(
        env,
        loserClanId,
        false,
        challenge.team_size
      );


      const players =
        await env.DB.prepare(`
          SELECT user_id
          FROM members
          WHERE
            clan_id=?
            OR clan_id=?
        `)
          .bind(
            first,
            loserClanId
          )
          .all();


      for(
        const player
        of players.results
      ){

        await env.DB.prepare(`
          INSERT INTO notifications
          (
            user_id,
            title,
            message,
            type
          )
          VALUES (?,?,?,?)
        `)
          .bind(
            player.user_id,
            "🏆 Resultado confirmado",
            `El reto #${challengeId} ha terminado.`,
            "result"
          )
          .run();

      }


      return json(
        {
          ok:true,

          completed:true,

          winner_clan_id:
            first

        },
        200,
        headers
      );

    }

  }


  return json(
    {
      ok:true,

      completed:false,

      message:
        "Resultado guardado. Falta la confirmación del rival."

    },
    200,
    headers
  );

}


/* =====================================================
   FUNCIÓN DE PUNTOS
===================================================== */

async function updateScore(
  env,
  clanId,
  won,
  league
){

  const points =
    won
      ? 3
      : 0;


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


  if(won){

    await env.DB.prepare(`
      UPDATE scores

      SET
        points=points+3,
        wins=wins+1,
        played=played+1

      WHERE clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }else{

    await env.DB.prepare(`
      UPDATE scores

      SET
        losses=losses+1,
        played=played+1

      WHERE clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }

}

__name(
  updateScore,
  "updateScore"
);


/* =====================================================
   HISTORIAL
===================================================== */

if (
  request.method === "GET" &&
  path === "/api/history"
) {

  const result =
    await env.DB.prepare(`
      SELECT

        ch.id,

        ch.created_at,
        ch.completed_at,

        ch.winner_clan_id,

        ch.team_size,

        mine.id
          AS my_clan_id,

        mine.name
          AS my_clan_name,

        CASE

          WHEN
            mine.id=
            ch.creator_clan_id

          THEN
            accepter.id

          ELSE
            creator.id

        END
          AS opponent_clan_id,

        CASE

          WHEN
            mine.id=
            ch.creator_clan_id

          THEN
            accepter.name

          ELSE
            creator.name

        END
          AS opponent_clan_name

      FROM challenges ch

      JOIN clans creator
        ON creator.id=
           ch.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id=
           ch.accepter_clan_id

      JOIN members mm
        ON
          (
            mm.clan_id=
            ch.creator_clan_id

            OR

            mm.clan_id=
            ch.accepter_clan_id
          )

        AND mm.user_id=?

      JOIN clans mine
        ON mine.id=mm.clan_id

      WHERE
        ch.status='completed'

      ORDER BY
        ch.completed_at DESC

      LIMIT 100
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
  /^\/api\/challenges\/\d+\/chat$/.test(path)
) {

  const challengeId =
    Number(
      path.split("/")[3]
    );


  const messages =
    await env.DB.prepare(`
      SELECT

        cm.id,
        cm.message,
        cm.created_at,

        u.username

      FROM chat_messages cm

      JOIN users u
        ON u.id=cm.user_id

      WHERE
        cm.challenge_id=?

      ORDER BY
        cm.created_at ASC

      LIMIT 200
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
  /^\/api\/challenges\/\d+\/chat$/.test(path)
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
      .slice(0, 500);


  if(!message){

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


  if(!challenge){

    return json(
      {
        error:
          "Reto no encontrado."
      },
      404,
      headers
    );

  }


  const clan =
    await getUserClan(
      env,
      me.id,
      challenge.team_size
    );


  if(
    !clan ||
    (
      Number(clan.id) !==
      Number(
        challenge.creator_clan_id
      ) &&
      Number(clan.id) !==
      Number(
        challenge.accepter_clan_id
      )
    )
  ){

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
      ok:true
    },
    200,
    headers
  );

}


/* =====================================================
   ADMIN
===================================================== */

if (
  path.startsWith(
    "/api/admin/"
  )
) {

  if(
    !isAdmin(me)
  ){

    return json(
      {
        error:
          "Acceso de administrador requerido."
      },
      403,
      headers
    );

  }


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


  if (
    request.method === "POST" &&
    /^\/api\/admin\/users\/\d+\/block$/.test(path)
  ) {

    const id =
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
        id
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id=?
    `)
      .bind(
        id
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


  if (
    request.method === "POST" &&
    /^\/api\/admin\/users\/\d+\/unblock$/.test(path)
  ) {

    const id =
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
        id
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


  if (
    request.method === "PUT" &&
    /^\/api\/admin\/users\/\d+\/psn$/.test(path)
  ) {

    const id =
      Number(
        path.split("/")[4]
      );


    const data =
      await body(request);


    const psn =
      String(
        data.psn_id || ""
      )
        .trim()
        .slice(0, 32);


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
        id
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


  if (
    request.method === "POST" &&
    /^\/api\/admin\/challenges\/\d+\/result$/.test(path)
  ) {

    const id =
      Number(
        path.split("/")[4]
      );


    const data =
      await body(request);


    const winner =
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
          id
        )
        .first();


    if(!challenge){

      return json(
        {
          error:
            "Reto no encontrado."
        },
        404,
        headers
      );

    }


    const creator =
      Number(
        challenge.creator_clan_id
      );


    const accepter =
      Number(
        challenge.accepter_clan_id
      );


    if(
      winner !== creator &&
      winner !== accepter
    ){

      return json(
        {
          error:
            "Ganador no válido."
        },
        400,
        headers
      );

    }


    if(
      challenge.status !==
      "completed"
    ){

      const loser =
        winner === creator
          ? accepter
          : creator;


      await updateScore(
        env,
        winner,
        true,
        challenge.team_size
      );


      if(loser){

        await updateScore(
          env,
          loser,
          false,
          challenge.team_size
        );

      }

    }


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
        id
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


  if (
    request.method === "DELETE" &&
    /^\/api\/admin\/clans\/\d+$/.test(path)
  ) {

    const id =
      Number(
        path.split("/")[4]
      );


    await env.DB.prepare(`
      DELETE FROM invites
      WHERE clan_id=?
    `)
      .bind(
        id
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM members
      WHERE clan_id=?
    `)
      .bind(
        id
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM scores
      WHERE clan_id=?
    `)
      .bind(
        id
      )
      .run();


    await env.DB.prepare(`
      DELETE FROM clans
      WHERE id=?
    `)
      .bind(
        id
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


  if (
    request.method === "POST" &&
    /^\/api\/admin\/leagues\/\d+\/reset$/.test(path)
  ) {

    const league =
      Number(
        path.split("/")[4]
      );


    if(
      ![2,3,4].includes(
        league
      )
    ){

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
        clan_id IN (
          SELECT id
          FROM clans
          WHERE league=?
        )
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
   EXPORT DEFAULT
===================================================== */

export default {

  async fetch(
    request,
    env
  ){

    try{

      const url =
        new URL(
          request.url
        );


      const response =
        await api(
          request,
          env,
          url.pathname
        );


      return response;

    }catch(error){

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
