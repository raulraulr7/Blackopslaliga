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


/* =====================================================
   RESPUESTAS
===================================================== */

const json = (
  data,
  status = 200,
  headers = {}
) =>
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


const body = async (
  request
) => {

  try {
    return await request.json();
  } catch {
    return {};
  }

};


/* =====================================================
   CORS
===================================================== */

function cors(request) {

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


/* =====================================================
   COOKIES
===================================================== */

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
    )
    .replaceAll(
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
        row.name ===
        column
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
      "challenges",
      "one_vs_one_mode",
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
    ]
    of columns
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
        "MIGRATION",
        table,
        column,
        error.message
      );

    }

  }


  /* Códigos para clanes antiguos */

  try {

    const old =
      await env.DB.prepare(`
        SELECT id
        FROM clans
        WHERE
          clan_code IS NULL
          OR clan_code=''
      `).all();


    for (
      const clan
      of old.results
    ) {

      let n =
        Number(
          clan.id
        );

      let code = "";

      for (
        let i = 0;
        i < 4;
        i++
      ) {

        code =
          String.fromCharCode(
            65 + (
              n % 26
            )
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

  } catch(error) {

    console.log(
      "CLAN CODE MIGRATION",
      error.message
    );

  }

}


/* =====================================================
   USUARIO
===================================================== */

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
      SELECT u.*

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
    ).toLowerCase() ===
    "admin";

}


/* =====================================================
   CLAN DEL USUARIO
===================================================== */

async function getUserClan(
  env,
  userId,
  league = null
) {

  if (
    league !== null &&
    league !== undefined
  ) {

    return await env.DB.prepare(`
      SELECT c.*

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
    SELECT c.*

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

        (
          SELECT COUNT(*)
          FROM members mm
          WHERE mm.clan_id=c.id
        ) AS member_count

      FROM clans c

      JOIN members m
        ON m.clan_id=c.id

      WHERE
        m.user_id=?

      ORDER BY
        c.league
    `)
      .bind(
        userId
      )
      .all();

  return result.results;

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
   NOTIFICACIONES
===================================================== */

async function notify(
  env,
  userId,
  title,
  message,
  type = "general"
) {

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
      title,
      message,
      type
    )
    .run();

}


async function notifyClan(
  env,
  clanId,
  title,
  message,
  type = "general"
) {

  const members =
    await env.DB.prepare(`
      SELECT user_id
      FROM members
      WHERE clan_id=?
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
      type
    );

  }

}


/* =====================================================
   CADUCAR RETOS
===================================================== */

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


/* =====================================================
   API
===================================================== */

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


  await initDatabase(
    env
  );

  await expireChallenges(
    env
  );


  /* ===================================================
     ME
  =================================================== */

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
          isAdmin(user),

        clans:
          user
            ? await getUserClans(
                env,
                user.id
              )
            : []
      },
      200,
      headers
    );

  }


  /* ===================================================
     REGISTRO
  =================================================== */

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
      )
        .trim();

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
        },

        clans:[]
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


  /* ===================================================
     LOGIN
  =================================================== */

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


    return json(
      {
        ok:true,

        user:{
          id:user.id,
          username:user.username,
          psn_id:user.psn_id,
          avatar_url:user.avatar_url
        },

        admin:
          isAdmin(user),

        clans:
          await getUserClans(
            env,
            user.id
          )
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


  /* ===================================================
     LOGOUT
  =================================================== */

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


  const me =
    await getCurrentUser(
      request,
      env
    );


  const publicRoute =
    request.method === "GET" &&
    (
      path ===
        "/api/clans" ||

      path ===
        "/api/leaderboard" ||

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


  /* ===================================================
     PERFIL
  =================================================== */

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

        psn !==
          String(
            me.psn_id || ""
          )
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
        ok:true
      },
      200,
      headers
    );

  }


  /* ===================================================
     MIS CLANES
  =================================================== */

  if (
    request.method === "GET" &&
    (
      path ===
        "/api/my-clans" ||

      path ===
        "/api/me/clans"
    )
  ) {

    return json(
      await getUserClans(
        env,
        me.id
      ),
      200,
      headers
    );

  }


  /* ===================================================
     CREAR CLAN
     
     IMPORTANTE:
     1v1 también permitido.
  =================================================== */

  if (
    request.method === "POST" &&
    path === "/api/clans"
  ) {

    const data =
      await body(
        request
      );


    const name =
      String(
        data.name || ""
      )
        .trim();


    const code =
      String(
        data.clan_code || ""
      )
        .trim()
        .toUpperCase();


    const logo =
      String(
        data.logo_url || ""
      )
        .trim()
        .slice(
          0,
          500
        );


    const league =
      Number(
        data.league
      );


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


    if (
      !/^[A-Z]{4}$/.test(
        code
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
      ![
        1,
        2,
        3,
        4
      ].includes(
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


    const existing =
      await getUserClan(
        env,
        me.id,
        league
      );


    if (existing) {

      return json(
        {
          error:
            "Ya perteneces a un clan en esta liga."
        },
        400,
        headers
      );

    }


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


    if (existingName) {

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
        WHERE
          UPPER(clan_code)=?
      `)
        .bind(
          code
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
            code,
            logo
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

        VALUES (?, ?, 0, 0, 0, 0)
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

          clanCode:
            code,

          clan:{
            id:
              clanId,

            name,

            clan_code:
              code,

            league,

            captain_id:
              me.id
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


  /* ===================================================
     LISTAR CLANES
  =================================================== */

  if (
    request.method === "GET" &&
    path === "/api/clans"
  ) {

    const params =
      new URL(
        request.url
      ).searchParams;


    const search =
      String(
        params.get(
          "search"
        ) ||
        params.get(
          "q"
        ) ||
        ""
      )
        .trim();


    const league =
      Number(
        params.get(
          "league"
        ) || 0
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
          WHERE m.clan_id=c.id
        ) AS member_count

      FROM clans c

      LEFT JOIN scores s
        ON s.clan_id=c.id

      WHERE
        c.name LIKE ?
    `;


    const values = [
      "%" +
      search +
      "%"
    ];


    if (
      [
        1,
        2,
        3,
        4
      ].includes(
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


  /* ===================================================
     FIN PARTE 1
  =================================================== */
  /* ===================================================
     VER CLAN
  =================================================== */

  if (
    request.method === "GET" &&
    /^\/api\/clans\/\d+$/.test(path)
  ) {

    const clanId =
      Number(
        path.split("/")[3]
      );

    const clan =
      await env.DB.prepare(`
        SELECT

          c.*,

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

          u.username
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


  /* ===================================================
     INVITAR JUGADOR
  =================================================== */

  if (
    request.method === "POST" &&
    /^\/api\/clans\/\d+\/invite$/
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
          me.id
        )
        .first();


    if (
      !member ||
      (
        member.role !==
          "captain" &&
        !isAdmin(me)
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


    const data =
      await body(
        request
      );


    const username =
      String(
        data.username || ""
      )
        .trim();


    if (!username) {

      return json(
        {
          error:
            "Falta el usuario."
        },
        400,
        headers
      );

    }


    const user =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE
          LOWER(username)=LOWER(?)
      `)
        .bind(
          username
        )
        .first();


    if (!user) {

      return json(
        {
          error:
            "No existe ese usuario."
        },
        404,
        headers
      );

    }


    if (
      user.id ===
      me.id
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


    const already =
      await env.DB.prepare(`
        SELECT *
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


    if (already) {

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
        user.id
      )
      .run();


    await notify(
      env,
      user.id,
      "Invitación a clan",
      `${clan.name} te ha invitado a unirte a su clan.`,
      "clan_invite"
    );


    return json(
      {
        ok:true,

        message:
          "Invitación enviada."
      },
      200,
      headers
    );

  }


  /* ===================================================
     LISTAR INVITACIONES
  =================================================== */

  if (
    request.method === "GET" &&
    path === "/api/invites"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT

          i.id,

          i.status,

          i.created_at,

          c.id AS clan_id,

          c.name AS clan_name,

          c.clan_code,

          c.logo_url,

          c.league,

          u.username AS inviter_username

        FROM invites i

        JOIN clans c
          ON c.id=i.clan_id

        JOIN users u
          ON u.id=i.inviter_id

        WHERE
          i.invitee_id=?

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


  /* ===================================================
     ACEPTAR INVITACIÓN
  =================================================== */

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


    if (existing) {

      return json(
        {
          error:
            "Ya perteneces a un clan en esta liga."
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


    await notify(
      env,
      invite.captain_id,
      "Nuevo miembro",
      `${me.username} se ha unido a ${invite.clan_name}.`,
      "clan_join"
    );


    return json(
      {
        ok:true,

        message:
          "Te has unido al clan."
      },
      200,
      headers
    );

  }


  /* ===================================================
     RECHAZAR INVITACIÓN
  =================================================== */

  if (
    request.method === "POST" &&
    /^\/api\/invites\/\d+\/reject$/
      .test(path)
  ) {

    const inviteId =
      Number(
        path.split("/")[3]
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


  /* ===================================================
     ABANDONAR CLAN
  =================================================== */

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
          me.id
        )
        .first();


    if (!member) {

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
      Number(
        clan.captain_id
      ) ===
      Number(
        me.id
      )
    ) {

      return json(
        {
          error:
            "El capitán no puede abandonar el clan. Transfiere el puesto primero."
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


  /* ===================================================
     EXPULSAR JUGADOR
  =================================================== */

  if (
    request.method === "POST" &&
    /^\/api\/clans\/\d+\/kick$/
      .test(path)
  ) {

    const clanId =
      Number(
        path.split("/")[3]
      );


    const data =
      await body(
        request
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
      ) &&
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "Solo el capitán puede expulsar."
        },
        403,
        headers
      );

    }


    if (
      userId ===
      Number(
        clan.captain_id
      )
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
      "Has sido expulsado",
      `Has sido expulsado de ${clan.name}.`,
      "clan_kick"
    );


    return json(
      {
        ok:true
      },
      200,
      headers
    );

  }


  /* ===================================================
     LEADERBOARD
  =================================================== */

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
        params.get(
          "league"
        ) || 4
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
            s.played,
            0
          ) AS played,

          COALESCE(
            s.wins,
            0
          ) AS wins,

          COALESCE(
            s.losses,
            0
          ) AS losses,

          COALESCE(
            s.points,
            0
          ) AS points

        FROM clans c

        LEFT JOIN scores s
          ON s.clan_id=c.id

        WHERE
          c.league=?

        ORDER BY

          points DESC,

          wins DESC,

          played ASC,

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


  /* ===================================================
     CREAR RETO
  =================================================== */

  if (
    request.method === "POST" &&
    path === "/api/challenges"
  ) {

    const data =
      await body(
        request
      );


    const league =
      Number(
        data.league || 4
      );


    if (
      ![
        1,
        2,
        3,
        4
      ].includes(
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
            "Necesitas pertenecer a un clan de esa liga."
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
      ) &&
      !isAdmin(me)
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


    const mode =
      String(
        data.mode ||
        "snd"
      )
        .trim()
        .toLowerCase();


    /* ===============================
       1v1
    =============================== */

    if (
      league === 1
    ) {

      const allowedModes = [
        "sniper",
        "pistols",
        "shotguns",
        "smg"
      ];


      if (
        !allowedModes.includes(
          mode
        )
      ) {

        return json(
          {
            error:
              "Modo 1v1 no válido."
          },
          400,
          headers
        );

      }


      const existing =
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


      if (existing) {

        return json(
          {
            error:
              "Ya tienes un reto abierto."
          },
          400,
          headers
        );

      }


      const expires =
        new Date(
          Date.now() +
          30 * 60 * 1000
        ).toISOString();


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

          one_vs_one_mode,

          expires_at
        )

        VALUES (
          ?,
          'open',
          ?,
          ?,
          ?,
          1,
          ?,
          ?,
          ?
        )
      `)
        .bind(

          clan.id,

          ONE_VS_ONE_MAP,

          ONE_VS_ONE_MAP,

          ONE_VS_ONE_MAP,

          JSON.stringify([
            mode
          ]),

          mode,

          expires

        )
        .run();


      return json(
        {
          ok:true,

          message:
            "Reto 1v1 publicado."
        },
        200,
        headers
      );

    }


    /* ===============================
       2v2 / 3v3 / 4v4
    =============================== */

    const teamSize =
      Number(
        data.team_size ||
        league
      );


    if (
      teamSize !==
      league
    ) {

      return json(
        {
          error:
            "El tamaño del equipo no coincide con la liga."
        },
        400,
        headers
      );

    }


    const maps =
      randomMaps();


    const expires =
      new Date(
        Date.now() +
        30 * 60 * 1000
      ).toISOString();


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

        expires_at
      )

      VALUES (
        ?,
        'open',
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

        maps[0],

        maps[1],

        maps[2],

        teamSize,

        JSON.stringify([
          mode
        ]),

        expires

      )
      .run();


    return json(
      {
        ok:true,

        message:
          "Reto publicado.",

        maps
      },
      200,
      headers
    );

  }


  /* ===================================================
     LISTAR RETOS
  =================================================== */

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
        params.get(
          "league"
        ) || 4
      );


    const result =
      await env.DB.prepare(`
        SELECT

          ch.*,

          c1.name
            AS creator_clan_name,

          c1.clan_code
            AS creator_clan_code,

          c1.logo_url
            AS creator_logo,

          c1.league
            AS creator_league,

          c2.name
            AS accepter_clan_name,

          c2.clan_code
            AS accepter_clan_code,

          c2.logo_url
            AS accepter_logo

        FROM challenges ch

        JOIN clans c1
          ON c1.id=
             ch.creator_clan_id

        LEFT JOIN clans c2
          ON c2.id=
             ch.accepter_clan_id

        WHERE
          c1.league=?

          AND ch.status
          IN (
            'open',
            'accepted',
            'pending_result'
          )

        ORDER BY
          ch.id DESC

        LIMIT 100
      `)
        .bind(
          league
        )
        .all();


    const rows =
      result.results.map(
        row => {

          let maps = [
            row.map1,
            row.map2,
            row.map3
          ];


          if (
            row.league === 1
          ) {

            maps = [
              ONE_VS_ONE_MAP
            ];

          }


          let modes = [];

          try {

            modes =
              JSON.parse(
                row.game_modes ||
                "[]"
              );

          } catch {

            modes = [];

          }


          return {

            ...row,

            id:
              Number(
                row.id
              ),

            league:
              Number(
                row.team_size ||
                row.creator_league ||
                4
              ),

            team_size:
              Number(
                row.team_size ||
                4
              ),

            mode:
              row.one_vs_one_mode ||
              modes[0] ||
              "snd",

            maps,

            creator_name:
              row.creator_clan_name,

            creator_code:
              row.creator_clan_code,

            creator_logo:
              row.creator_logo,

            accepter_name:
              row.accepter_clan_name,

            accepter_code:
              row.accepter_clan_code,

            accepter_logo:
              row.accepter_logo

          };

        }
      );


    return json(
      rows,
      200,
      headers
    );

  }


  /* ===================================================
     VER RETO
  =================================================== */

  if (
    request.method === "GET" &&
    /^\/api\/challenges\/\d+$/
      .test(path)
  ) {

    const id =
      Number(
        path.split("/")[3]
      );


    const challenge =
      await env.DB.prepare(`
        SELECT

          ch.*,

          c1.name
            AS creator_clan_name,

          c1.clan_code
            AS creator_clan_code,

          c1.logo_url
            AS creator_logo,

          c1.league
            AS creator_league,

          c2.name
            AS accepter_clan_name,

          c2.clan_code
            AS accepter_clan_code,

          c2.logo_url
            AS accepter_logo

        FROM challenges ch

        JOIN clans c1
          ON c1.id=
             ch.creator_clan_id

        LEFT JOIN clans c2
          ON c2.id=
             ch.accepter_clan_id

        WHERE ch.id=?
      `)
        .bind(
          id
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


    let modes = [];

    try {

      modes =
        JSON.parse(
          challenge.game_modes ||
          "[]"
        );

    } catch {

      modes = [];

    }


    const maps =
      challenge.team_size === 1
        ? [
            ONE_VS_ONE_MAP
          ]
        : [
            challenge.map1,
            challenge.map2,
            challenge.map3
          ];


    const reports =
      await env.DB.prepare(`
        SELECT

          r.*,

          c.name AS clan_name,

          c.clan_code

        FROM reports r

        JOIN clans c
          ON c.id=r.clan_id

        WHERE
          r.challenge_id=?
      `)
        .bind(
          id
        )
        .all();


    const messages =
      await env.DB.prepare(`
        SELECT

          cm.*,

          u.username

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
          id
        )
        .all();


    return json(
      {
        ...challenge,

        league:
          Number(
            challenge.team_size ||
            challenge.creator_league ||
            4
          ),

        team_size:
          Number(
            challenge.team_size ||
            4
          ),

        mode:
          challenge.one_vs_one_mode ||
          modes[0] ||
          "snd",

        maps,

        reports:
          reports.results,

        messages:
          messages.results,

        creator_name:
          challenge.creator_clan_name,

        creator_code:
          challenge.creator_clan_code,

        accepter_name:
          challenge.accepter_clan_name,

        accepter_code:
          challenge.accepter_clan_code
      },
      200,
      headers
    );

  }


  /* ===================================================
     ACEPTAR RETO
  =================================================== */

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

          c.name AS creator_name,

          c.league

        FROM challenges ch

        JOIN clans c
          ON c.id=
             ch.creator_clan_id

        WHERE
          ch.id=?

          AND ch.status='open'
      `)
        .bind(
          challengeId
        )
        .first();


    if (!challenge) {

      return json(
        {
          error:
            "Reto no disponible."
        },
        404,
        headers
      );

    }


    const clan =
      await getUserClan(
        env,
        me.id,
        challenge.league
      );


    if (!clan) {

      return json(
        {
          error:
            "Necesitas pertenecer a un clan de esta liga."
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
      Number(
        clan.captain_id
      ) !==
      Number(
        me.id
      ) &&
      !isAdmin(me)
    ) {

      return json(
        {
          error:
            "Solo el capitán puede aceptar retos."
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
        clan.id,
        challengeId
      )
      .run();


    await notifyClan(
      env,
      challenge.creator_clan_id,
      "Reto aceptado",
      `${clan.name} ha aceptado vuestro reto.`,
      "challenge"
    );


    return json(
      {
        ok:true,

        message:
          "Reto aceptado."
      },
      200,
      headers
    );

  }


  /* ===================================================
     REPORTAR RESULTADO
  =================================================== */

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
      await body(
        request
      );


    const result =
      String(
        data.result || ""
      )
        .toLowerCase();


    if (
      ![
        "win",
        "loss"
      ].includes(
        result
      )
    ) {

      return json(
        {
          error:
            "Resultado no válido."
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
      `)
        .bind(
          challengeId
        )
        .first();


    if (!challenge) {

      return json(
        {
          error:
            "El reto no está preparado para resultado."
        },
        400,
        headers
      );

    }


    const clan =
      await getUserClan(
        env,
        me.id,
        Number(
          challenge.team_size
        )
      );


    if (!clan) {

      return json(
        {
          error:
            "No perteneces a un clan de esta liga."
        },
        400,
        headers
      );

    }


    const isCreator =
      clan.id ===
      challenge.creator_clan_id;


    const isAccepter =
      clan.id ===
      challenge.accepter_clan_id;


    if (
      !isCreator &&
      !isAccepter
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


    const winnerClan =
      result === "win"
        ? clan.id
        : (
            isCreator
              ? challenge.accepter_clan_id
              : challenge.creator_clan_id
          );


    const already =
      await env.DB.prepare(`
        SELECT id

        FROM reports

        WHERE
          challenge_id=?

          AND clan_id=?
      `)
        .bind(
          challengeId,
          clan.id
        )
        .first();


    if (already) {

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

        clan.id,

        winnerClan
      )
      .run();


    const reports =
      await env.DB.prepare(`
        SELECT *

        FROM reports

        WHERE
          challenge_id=?
      `)
        .bind(
          challengeId
        )
        .all();


    if (
      reports.results.length <
      2
    ) {

      await env.DB.prepare(`
        UPDATE challenges

        SET
          status='pending_result'

        WHERE
          id=?
      `)
        .bind(
          challengeId
        )
        .run();


      const otherClan =
        isCreator
          ? challenge.accepter_clan_id
          : challenge.creator_clan_id;


      await notifyClan(
        env,
        otherClan,
        "Resultado pendiente",
        `${clan.name} ha enviado el resultado del reto. Confirma el resultado.`,
        "challenge_result"
      );


      return json(
        {
          ok:true,

          completed:false,

          message:
            "Resultado enviado. Falta la confirmación del otro capitán."
        },
        200,
        headers
      );

    }


    const first =
      reports.results[0];

    const second =
      reports.results[1];


    if (
      Number(
        first.winner_clan_id
      ) !==
      Number(
        second.winner_clan_id
      )
    ) {

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
          status='accepted'

        WHERE
          id=?
      `)
        .bind(
          challengeId
        )
        .run();


      await notifyClan(
        env,
        challenge.creator_clan_id,
        "Resultado no coincidente",
        "Los capitanes han enviado resultados diferentes. Volved a reportar el resultado.",
        "challenge_result"
      );


      await notifyClan(
        env,
        challenge.accepter_clan_id,
        "Resultado no coincidente",
        "Los capitanes han enviado resultados diferentes. Volved a reportar el resultado.",
        "challenge_result"
      );


      return json(
        {
          ok:false,

          completed:false,

          conflict:true,

          message:
            "Los resultados no coinciden."
        },
        409,
        headers
      );

    }


    const winner =
      Number(
        first.winner_clan_id
      );


    const loser =
      winner ===
      Number(
        challenge.creator_clan_id
      )
        ? challenge.accepter_clan_id
        : challenge.creator_clan_id;


    await env.DB.prepare(`
      UPDATE challenges

      SET

        status='completed',

        winner_clan_id=?,

        completed_at=?

      WHERE
        id=?
    `)
      .bind(
        winner,

        new Date().toISOString(),

        challengeId
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
        winner,
        challenge.team_size
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
        loser,
        challenge.team_size
      )
      .run();


    await env.DB.prepare(`
      UPDATE scores

      SET

        points=points+3,

        wins=wins+1,

        played=played+1

      WHERE
        clan_id=?
    `)
      .bind(
        winner
      )
      .run();


    await env.DB.prepare(`
      UPDATE scores

      SET

        losses=losses+1,

        played=played+1

      WHERE
        clan_id=?
    `)
      .bind(
        loser
      )
      .run();


    await notifyClan(
      env,
      winner,
      "🏆 Victoria confirmada",
      "El resultado del reto ha sido confirmado.",
      "challenge_complete"
    );


    await notifyClan(
      env,
      loser,
      "Resultado confirmado",
      "El resultado del reto ha sido confirmado.",
      "challenge_complete"
    );


    return json(
      {
        ok:true,

        completed:true,

        winner_clan_id:
          winner,

        message:
          "Resultado confirmado por ambos capitanes."
      },
      200,
      headers
    );

  }


  /* ===================================================
     CHAT DEL RETO
  =================================================== */

  if (
    request.method === "GET" &&
    /^\/api\/challenges\/\d+\/chat$/
      .test(path)
  ) {

    const challengeId =
      Number(
        path.split("/")[3]
      );


    const result =
      await env.DB.prepare(`
        SELECT

          cm.id,

          cm.challenge_id,

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


  /* ===================================================
     ENVIAR MENSAJE CHAT
  =================================================== */

  if (
    request.method === "POST" &&
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


    const clan =
      await getUserClan(
        env,
        me.id,
        Number(
          challenge.team_size
        )
      );


    if (!clan) {

      return json(
        {
          error:
            "No perteneces a la liga del reto."
        },
        403,
        headers
      );

    }


    if (
      clan.id !==
      challenge.creator_clan_id &&
      clan.id !==
      challenge.accepter_clan_id
    ) {

      return json(
        {
          error:
            "No puedes escribir en este reto."
        },
        403,
        headers
      );

    }


    const data =
      await body(
        request
      );


    const message =
      String(
        data.message || ""
      )
        .trim()
        .slice(
          0,
          500
        );


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


  /* ===================================================
     NOTIFICACIONES
  =================================================== */

  if (
    request.method === "GET" &&
    path === "/api/notifications"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT

          *

        FROM notifications

        WHERE
          user_id=?

        ORDER BY
          id DESC

        LIMIT 100
      `)
        .bind(
          me.id
        )
        .all();


    return json(
      result.results.map(
        notification => ({
          ...notification,

          read:
            Boolean(
              notification.is_read
            )
        })
      ),
      200,
      headers
    );

  }


  /* ===================================================
     MARCAR NOTIFICACIÓN LEÍDA
  =================================================== */

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

      SET
        is_read=1

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


  /* ===================================================
     HISTORIAL
  =================================================== */

  if (
    request.method === "GET" &&
    path === "/api/history"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT

          ch.*,

          c1.name
            AS creator_clan_name,

          c2.name
            AS accepter_clan_name

        FROM challenges ch

        JOIN clans c1
          ON c1.id=
             ch.creator_clan_id

        LEFT JOIN clans c2
          ON c2.id=
             ch.accepter_clan_id

        WHERE

          ch.status='completed'

          AND (
            ch.creator_clan_id IN (
              SELECT clan_id
              FROM members
              WHERE user_id=?
            )

            OR

            ch.accepter_clan_id IN (
              SELECT clan_id
              FROM members
              WHERE user_id=?
            )
          )

        ORDER BY
          ch.completed_at DESC

        LIMIT 100
      `)
        .bind(
          me.id,
          me.id
        )
        .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  /* ===================================================
     BUSCAR USUARIOS
  =================================================== */

  if (
    request.method === "GET" &&
    path === "/api/users"
  ) {

    const params =
      new URL(
        request.url
      ).searchParams;


    const search =
      String(
        params.get(
          "search"
        ) ||
        params.get(
          "q"
        ) ||
        ""
      )
        .trim();


    const result =
      await env.DB.prepare(`
        SELECT

          id,

          username,

          psn_id,

          avatar_url

        FROM users

        WHERE
          username LIKE ?

        ORDER BY
          username ASC

        LIMIT 50
      `)
        .bind(
          "%" +
          search +
          "%"
        )
        .all();


    return json(
      result.results,
      200,
      headers
    );

  }


  /* ===================================================
     VER USUARIO
  =================================================== */

  if (
    request.method === "GET" &&
    /^\/api\/users\/\d+$/
      .test(path)
  ) {

    const id =
      Number(
        path.split("/")[3]
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
            "Usuario no encontrado."
        },
        404,
        headers
      );

    }


    return json(
      user,
      200,
      headers
    );

  }


  /* ===================================================
     RUTA NO ENCONTRADA
  =================================================== */

  return json(
    {
      error:
        "Ruta no encontrada.",
      path,
      method:
        request.method
    },
    404,
    headers
  );

}


/* =====================================================
   EXPORT
===================================================== */

export default {

  async fetch(
    request,
    env
  ) {

    const url =
      new URL(
        request.url
      );


    try {

      return await api(
        request,
        env,
        url.pathname
      );

    } catch(error) {

      console.error(
        "WORKER ERROR",
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
  /* ===================================================
     ADMIN
  =================================================== */

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


    /* ================================================
       USUARIOS
    ================================================ */

    if (
      request.method === "GET" &&
      path === "/api/admin/users"
    ) {

      const result =
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
            id DESC

          LIMIT 500
        `)
          .all();


      return json(
        result.results,
        200,
        headers
      );

    }


    /* ================================================
       BLOQUEAR USUARIO
    ================================================ */

    if (
      request.method === "POST" &&
      /^\/api\/admin\/users\/\d+\/block$/
        .test(path)
    ) {

      const userId =
        Number(
          path.split("/")[4]
        );


      if (
        userId ===
        Number(me.id)
      ) {

        return json(
          {
            error:
              "No puedes bloquear tu propia cuenta."
          },
          400,
          headers
        );

      }


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
          ok:true
        },
        200,
        headers
      );

    }


    /* ================================================
       DESBLOQUEAR USUARIO
    ================================================ */

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
          ok:true
        },
        200,
        headers
      );

    }


    /* ================================================
       BORRAR USUARIO
    ================================================ */

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
        userId ===
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


      const captainClans =
        await env.DB.prepare(`
          SELECT id

          FROM clans

          WHERE
            captain_id=?
        `)
          .bind(
            userId
          )
          .all();


      for (
        const clan
        of captainClans.results
      ) {

        await deleteClan(
          env,
          clan.id
        );

      }


      await env.DB.prepare(`
        DELETE FROM members

        WHERE
          user_id=?
      `)
        .bind(
          userId
        )
        .run();


      await env.DB.prepare(`
        DELETE FROM invites

        WHERE

          inviter_id=?

          OR

          invitee_id=?
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


    /* ================================================
       CLANES ADMIN
    ================================================ */

    if (
      request.method === "GET" &&
      path === "/api/admin/clans"
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

            u.username
              AS captain_username,

            (
              SELECT COUNT(*)

              FROM members m

              WHERE
                m.clan_id=c.id

            ) AS member_count

          FROM clans c

          LEFT JOIN users u
            ON u.id=c.captain_id

          ORDER BY

            c.league ASC,

            c.name ASC

          LIMIT 500
        `)
          .all();


      return json(
        result.results,
        200,
        headers
      );

    }


    /* ================================================
       BORRAR CLAN ADMIN
    ================================================ */

    if (
      request.method === "DELETE" &&
      /^\/api\/admin\/clans\/\d+$/
        .test(path)
    ) {

      const clanId =
        Number(
          path.split("/").pop()
        );


      await deleteClan(
        env,
        clanId
      );


      return json(
        {
          ok:true
        },
        200,
        headers
      );

    }


    /* ================================================
       RETOS ADMIN
    ================================================ */

    if (
      request.method === "GET" &&
      path === "/api/admin/challenges"
    ) {

      const result =
        await env.DB.prepare(`
          SELECT

            ch.id,

            ch.status,

            ch.team_size,

            ch.map1,

            ch.map2,

            ch.map3,

            ch.one_vs_one_mode,

            ch.created_at,

            ch.completed_at,

            ch.winner_clan_id,

            c1.name
              AS creator_clan_name,

            c2.name
              AS accepter_clan_name

          FROM challenges ch

          JOIN clans c1
            ON c1.id=
               ch.creator_clan_id

          LEFT JOIN clans c2
            ON c2.id=
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


    /* ================================================
       BORRAR RETO ADMIN
    ================================================ */

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
          ok:true
        },
        200,
        headers
      );

    }


    /* ================================================
       ADMIN CAMBIAR RESULTADO
    ================================================ */

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
        await body(
          request
        );


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
              "Clan ganador no válido."
          },
          400,
          headers
        );

      }


      /* Si había resultado anterior,
         lo quitamos antes de poner el nuevo. */

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


        await removeWin(
          env,
          oldWinner
        );


        if (
          oldLoser
        ) {

          await removeLoss(
            env,
            oldLoser
          );

        }

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

        WHERE
          id=?
      `)
        .bind(
          winnerId,

          new Date()
            .toISOString(),

          challengeId
        )
        .run();


      await addWin(
        env,
        winnerId,
        challenge.team_size
      );


      const loserId =
        winnerId === creatorId
          ? accepterId
          : creatorId;


      if (
        loserId
      ) {

        await addLoss(
          env,
          loserId,
          challenge.team_size
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


    /* ================================================
       DESHACER RESULTADO ADMIN
    ================================================ */

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
              "Este reto no tiene resultado."
          },
          400,
          headers
        );

      }


      const winner =
        Number(
          challenge.winner_clan_id
        );


      const creator =
        Number(
          challenge.creator_clan_id
        );


      const accepter =
        Number(
          challenge.accepter_clan_id
        );


      const loser =
        winner === creator
          ? accepter
          : creator;


      await removeWin(
        env,
        winner
      );


      if (
        loser
      ) {

        await removeLoss(
          env,
          loser
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
          ok:true
        },
        200,
        headers
      );

    }


    /* ================================================
       RESET DE LIGA
    ================================================ */

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
        ![
          1,
          2,
          3,
          4
        ].includes(
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


    return json(
      {
        error:
          "Ruta de administración no encontrada."
      },
      404,
      headers
    );

  }


  /* ===================================================
     FUNCIONES AUXILIARES
  =================================================== */

  async function addWin(
    env,
    clanId,
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

      VALUES (
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


    await env.DB.prepare(`
      UPDATE scores

      SET

        points=points+3,

        wins=wins+1,

        played=played+1

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }


  async function addLoss(
    env,
    clanId,
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

      VALUES (
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


    await env.DB.prepare(`
      UPDATE scores

      SET

        losses=losses+1,

        played=played+1

      WHERE
        clan_id=?
    `)
      .bind(
        clanId
      )
      .run();

  }


  async function removeWin(
    env,
    clanId
  ) {

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

  }


  async function removeLoss(
    env,
    clanId
  ) {

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


  async function deleteClan(
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


  /* ===================================================
     FIN
  =================================================== */

  return json(
    {
      error:
        "Ruta no encontrada.",
      path,
      method:
        request.method
    },
    404,
    headers
  );


}
