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

const body = async request => {
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
          "Vary": "Origin"
        }
      : {})
  };
}

function sessionCookie(token) {

  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${
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


/* =========================
   PASSWORDS
========================= */

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


/* =========================
   DATABASE MIGRATION
========================= */

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


  /*
    NUEVOS CAMPOS
  */

  const columns = [

    [
      "users",
      "psn_id",
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
      "TEXT DEFAULT '[\"snd\"]'"
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


  /*
    Códigos de clan
  */

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

      await env.DB.prepare(`
        UPDATE clans
        SET clan_code=?
        WHERE id=?
      `)
        .bind(
          "BOL-" +
          String(clan.id)
            .padStart(5, "0"),
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


/* =========================
   CURRENT USER
========================= */

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

function isAdmin(user) {

  return (
    !!user &&
    user.username
      .toLowerCase() ===
      "admin"
  );
}


/* =========================
   CLAN OF USER
========================= */

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
    .bind(userId)
    .first();
}


/* =========================
   MAPS
========================= */

function randomMaps() {

  return [
    ...MAPS
  ]
    .sort(
      () => Math.random() - 0.5
    )
    .slice(0,3);
}


/* =========================
   EXPIRE CHALLENGES
========================= */

async function expireChallenges(env) {

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


/* =========================
   API
========================= */

async function api(
  request,
  env,
  path
) {

  const headers =
    cors(request);

  if(
    request.method ===
    "OPTIONS"
  ){

    return new Response(
      null,
      {
        status:204,
        headers
      }
    );
  }

  await initDatabase(env);

  await expireChallenges(env);


  /* ===== ME ===== */

  if(
    request.method ===
    "GET" &&
    path === "/api/me"
  ){

    const user =
      await getCurrentUser(
        request,
        env
      );

    return json(
      {
        user,
        admin:isAdmin(user)
      },
      200,
      headers
    );
  }


  /* ===== REGISTER ===== */

  if(
    request.method ===
    "POST" &&
    path === "/api/register"
  ){

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

    if(
      username.length < 3 ||
      username.length > 20 ||
      password.length < 6
    ){

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

    if(exists){

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
            sessionCookie(token)
        }
      );

    } catch(error){

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


  /* ===== LOGIN ===== */

  if(
    request.method ===
    "POST" &&
    path === "/api/login"
  ){

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

    if(
      !user ||
      !(await verifyPassword(
        password,
        user.password_hash
      ))
    ){

      return json(
        {
          error:
            "Usuario o contraseña incorrectos."
        },
        401,
        headers
      );
    }

    if(
      user.is_blocked &&
      (
        user.blocked_until === 0 ||
        user.blocked_until >
          Date.now()
      )
    ){

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
          psn_id:user.psn_id
        }
      },
      200,
      {
        ...headers,
        "Set-Cookie":
          sessionCookie(token)
      }
    );
  }


  /* ===== LOGOUT ===== */

  if(
    request.method ===
    "POST" &&
    path === "/api/logout"
  ){

    const token =
      getCookie(request);

    if(token){

      await env.DB.prepare(`
        DELETE FROM sessions
        WHERE token=?
      `)
        .bind(token)
        .run();
    }

    return json(
      {ok:true},
      200,
      {
        ...headers,
        "Set-Cookie":
          deleteSessionCookie()
      }
    );
  }


  /* =========================
     AUTH REQUIRED
  ========================= */

  const me =
    await getCurrentUser(
      request,
      env
    );

  if(!me){

    return json(
      {
        error:
          "Debes iniciar sesión."
      },
      401,
      headers
    );
  }

  if(
    me.is_blocked &&
    (
      me.blocked_until === 0 ||
      me.blocked_until >
        Date.now()
    )
  ){

    return json(
      {
        error:
          "Usuario bloqueado."
      },
      403,
      headers
    );
  }


  /* ===== PROFILE ===== */

  if(
    request.method ===
    "PUT" &&
    path === "/api/profile"
  ){

    const data =
      await body(request);

    const psn =
      String(
        data.psn_id || ""
      )
        .trim()
        .slice(0,32);

    await env.DB.prepare(`
      UPDATE users
      SET psn_id=?
      WHERE id=?
    `)
      .bind(
        psn,
        me.id
      )
      .run();

    return json(
      {ok:true},
      200,
      headers
    );
  }


  /* ===== USERS ===== */

  if(
    request.method ===
    "GET" &&
    path === "/api/users"
  ){

    const params =
      new URL(request.url)
        .searchParams;

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


  /* ===== PUBLIC USER ===== */

  if(
    request.method ===
    "GET" &&
    /^\/api\/users\/\d+$/.test(path)
  ){

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
          created_at
        FROM users
        WHERE id=?
      `)
        .bind(id)
        .first();

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


  /* ===== CLANS LIST ===== */

  if(
    request.method ===
    "GET" &&
    path === "/api/clans"
  ){

    const params =
      new URL(request.url)
        .searchParams;

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

    const values=[
      "%" +
      query +
      "%"
    ];

    if(
      [2,3,4].includes(
        league
      )
    ){

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
      await env.DB
        .prepare(sql)
        .bind(...values)
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }


  /* ===== PUBLIC CLAN ===== */

  if(
    request.method ===
    "GET" &&
    /^\/api\/clans\/\d+$/.test(path)
  ){

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
    /* =========================
     CREATE CLAN
  ========================= */

  if(
    request.method ===
    "POST" &&
    path === "/api/clans"
  ){

    const data =
      await body(request);

    const name =
      String(
        data.name || ""
      ).trim();

    const league =
      Number(data.league);

    if(
      name.length < 2 ||
      name.length > 24 ||
      ![2,3,4].includes(league)
    ){

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

    if(existingMembership){

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
        WHERE name=?
        AND league=?
      `)
        .bind(
          name,
          league
        )
        .first();

    if(existingClan){

      return json(
        {
          error:
            "Ese nombre ya existe en esa liga."
        },
        400,
        headers
      );
    }

    try{

      const created =
        await env.DB.prepare(`
          INSERT INTO clans
          (
            name,
            captain_id,
            league,
            clan_code
          )
          VALUES (?,?,?,'TEMP')
        `)
          .bind(
            name,
            me.id,
            league
          )
          .run();

      const clanId =
        created.meta.last_row_id;

      const clanCode =
        "BOL-" +
        String(clanId)
          .padStart(5,"0");

      await env.DB.prepare(`
        UPDATE clans
        SET clan_code=?
        WHERE id=?
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
          ok:true,
          clanId,
          clanCode
        },
        200,
        headers
      );

    }catch(error){

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


  /* =========================
     LEADERBOARD
  ========================= */

  if(
    request.method ===
    "GET" &&
    path === "/api/leaderboard"
  ){

    const league =
      Number(
        new URL(request.url)
          .searchParams
          .get("league") || 4
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

    const result =
      await env.DB.prepare(`
        SELECT
          c.id,
          c.name,
          c.clan_code,
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
        .bind(league)
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }


  /* =========================
     CREATE CHALLENGE
  ========================= */

  if(
    request.method ===
    "POST" &&
    path === "/api/challenges"
  ){

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

    if(
      ![2,3,4].includes(
        league
      ) ||
      teamSize !== league
    ){

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

    if(!clan){

      return json(
        {
          error:
            "No perteneces a ningún clan en esta liga."
        },
        400,
        headers
      );
    }

    if(
      clan.captain_id !==
      me.id
    ){

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
          OR accepter_clan_id=?
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

    if(active){

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
      ?
      data.game_modes
      :
      ["snd"];

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

        VALUES(
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
          JSON.stringify(modes),
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


  /* =========================
     CHALLENGES BOARD
  ========================= */

  if(
    request.method ===
    "GET" &&
    path === "/api/challenges"
  ){

    await expireChallenges(
      env
    );

    const params =
      new URL(request.url)
        .searchParams;

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
      ?
      clan.id
      :
      -1;

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

    return json(
      result.results,
      200,
      headers
    );
  }


  /* =========================
     ACCEPT CHALLENGE
  ========================= */

  const acceptMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/accept$/
    );

  if(
    request.method ===
    "POST" &&
    acceptMatch
  ){

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

    if(!challenge){

      return json(
        {
          error:
            "El reto ya no está disponible."
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
          cancel_reason=
            'No aceptado en 30 minutos',
          cancelled_at=CURRENT_TIMESTAMP

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

    if(!clan){

      return json(
        {
          error:
            "No perteneces a un clan en esta liga."
        },
        400,
        headers
      );
    }

    if(
      clan.id ===
      challenge.creator_clan_id
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

    if(
      clan.captain_id !==
      me.id
    ){

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
          OR accepter_clan_id=?
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

    if(active){

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


  /* =========================
     REPORT RESULT
  ========================= */

  const reportMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/report$/
    );

  if(
    request.method ===
    "POST" &&
    reportMatch
  ){

    const challengeId =
      Number(
        reportMatch[1]
      );

    const data =
      await body(request);

    const result =
      String(
        data.result || ""
      );

    if(
      result !== "win" &&
      result !== "loss"
    ){

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

    if(!challenge){

      return json(
        {
          error:
            "El reto no está disponible."
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

    if(!clan){

      return json(
        {
          error:
            "No perteneces a un clan de esta liga."
        },
        403,
        headers
      );
    }

    if(
      ![
        challenge.creator_clan_id,
        challenge.accepter_clan_id
      ].includes(clan.id)
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

    if(
      clan.captain_id !==
      me.id
    ){

      return json(
        {
          error:
            "Solo el capitán puede confirmar el resultado."
        },
        403,
        headers
      );
    }

    const winner =
      result === "win"
      ?
      clan.id
      :
      (
        clan.id ===
        challenge.creator_clan_id
        ?
        challenge.accepter_clan_id
        :
        challenge.creator_clan_id
      );

    await env.DB.prepare(`
      INSERT OR REPLACE INTO reports
      (
        challenge_id,
        clan_id,
        winner_clan_id
      )
      VALUES(?,?,?)
    `)
      .bind(
        challengeId,
        clan.id,
        winner
      )
      .run();

    const reports =
      await env.DB.prepare(`
        SELECT *
        FROM reports
        WHERE challenge_id=?
      `)
        .bind(
          challengeId
        )
        .all();

    if(
      reports.results.length <
      2
    ){

      return json(
        {
          ok:true,
          completed:false,
          message:
            "Resultado enviado. Falta el otro capitán."
        },
        200,
        headers
      );
    }

    const firstWinner =
      reports.results[0]
        .winner_clan_id;

    const secondWinner =
      reports.results[1]
        .winner_clan_id;

    if(
      firstWinner !==
      secondWinner
    ){

      return json(
        {
          ok:true,
          completed:false,
          conflict:true,
          message:
            "Los resultados no coinciden. Administración debe revisarlo."
        },
        200,
        headers
      );
    }

    const winnerClan =
      firstWinner;

    const loserClan =
      winnerClan ===
      challenge.creator_clan_id
      ?
      challenge.accepter_clan_id
      :
      challenge.creator_clan_id;

    await env.DB.batch([

      env.DB.prepare(`
        UPDATE challenges

        SET
          status='completed',
          winner_clan_id=?,
          completed_at=CURRENT_TIMESTAMP

        WHERE id=?
      `)
        .bind(
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
      `)
        .bind(
          winnerClan
        ),

      env.DB.prepare(`
        UPDATE scores

        SET
          played=played+1,
          losses=losses+1

        WHERE clan_id=?
      `)
        .bind(
          loserClan
        )

    ]);

    return json(
      {
        ok:true,
        completed:true
      },
      200,
      headers
    );
  }


  /* =========================
     HISTORY
  ========================= */

  if(
    request.method ===
    "GET" &&
    path === "/api/history"
  ){

    const clan =
      await getUserClan(
        env,
        me.id
      );

    const clanId =
      clan
      ?
      clan.id
      :
      -1;

    const result =
      await env.DB.prepare(`
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
      `)
        .bind(
          clanId,
          clanId
        )
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }
    /* =========================
     ADMIN
  ========================= */

  if(isAdmin(me)){

    /* ===== ADMIN USERS ===== */

    if(
      request.method ===
      "GET" &&
      path === "/api/admin/users"
    ){

      const result =
        await env.DB.prepare(`
          SELECT
            id,
            username,
            psn_id,
            is_blocked,
            blocked_until,
            created_at
          FROM users
          ORDER BY id DESC
          LIMIT 500
        `)
          .all();

      return json(
        result.results,
        200,
        headers
      );
    }


    /* ===== BLOCK USER ===== */

    if(
      request.method ===
      "POST" &&
      path === "/api/admin/block"
    ){

      const data =
        await body(request);

      const userId =
        Number(
          data.user_id
        );

      let blockedUntil;

      if(data.permanent){

        /*
          0 = bloqueo indefinido
        */

        blockedUntil=0;

      }else{

        const minutes =
          Number(
            data.minutes || 60
          );

        blockedUntil =
          Date.now() +
          minutes * 60000;
      }

      await env.DB.prepare(`
        UPDATE users

        SET
          is_blocked=1,
          blocked_until=?

        WHERE id=?
      `)
        .bind(
          blockedUntil,
          userId
        )
        .run();

      /*
        Cerramos sus sesiones
      */

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


    /* ===== UNBLOCK USER ===== */

    if(
      request.method ===
      "POST" &&
      path === "/api/admin/unblock"
    ){

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
       RESET RANKING
    ========================= */

    if(
      request.method ===
      "POST" &&
      path === "/api/admin/reset-ranking"
    ){

      const data =
        await body(request);

      const league =
        Number(
          data.league || 4
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

        WHERE league=?
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


    /* =========================
       ADMIN CANCEL CHALLENGE
    ========================= */

    if(
      request.method ===
      "POST" &&
      path === "/api/admin/delete-challenge"
    ){

      const data =
        await body(request);

      const challengeId =
        Number(
          data.challenge_id
        );

      await env.DB.prepare(`
        UPDATE challenges

        SET
          status='cancelled',
          cancel_reason='ADMIN',
          cancelled_at=CURRENT_TIMESTAMP

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

  }


  /* =========================
     UNKNOWN ROUTE
  ========================= */

  return json(
    {
      error:
        "Ruta no encontrada."
    },
    404,
    headers
  );
}


/* =========================
   REQUEST HANDLER
========================= */

async function handleRequest(
  request,
  env
){

  const url =
    new URL(
      request.url
    );

  /*
    Todas las rutas /api/*
    pasan por nuestro backend.
  */

  if(
    url.pathname.startsWith(
      "/api/"
    )
  ){

    return api(
      request,
      env,
      url.pathname
    );
  }


  /*
    Todo lo demás lo sirve
    Cloudflare Pages/Assets.
  */

  if(env.ASSETS){

    return env.ASSETS.fetch(
      request
    );
  }

  return new Response(
    "BlackOpsLALIGA",
    {
      status:200
    }
  );
}


/* =========================
   CLOUDFLARE WORKER
========================= */

export default {

  async fetch(
    request,
    env
  ){

    try{

      return await handleRequest(
        request,
        env
      );

    }catch(error){

      console.error(
        "WORKER ERROR:",
        error
      );

      return json(
        {
          error:
            "Error interno del servidor",
          detail:
            error.message
        },
        500,
        cors(request)
      );
    }
  }

};
