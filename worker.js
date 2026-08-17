var __defProp = Object.defineProperty;
var __name = (target, value) =>
  __defProp(target, "name", {
    value,
    configurable: true
  });

/* ==========================================
   CONFIGURACIÓN
========================================== */

var MAPS = [
  "Raid",
  "Standoff",
  "Slums",
  "Yemen",
  "Meltdown",
  "Express"
];

var COOKIE = "bol_session";
var SESSION_DAYS = 7;


/* ==========================================
   RESPUESTAS
========================================== */

function json(
  data,
  status = 200,
  extraHeaders = {}
) {

  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "content-type":
          "application/json; charset=UTF-8",

        ...extraHeaders
      }
    }
  );
}

__name(json, "json");


/* ==========================================
   CORS
========================================== */

function corsHeaders(request) {

  const origin =
    request.headers.get("Origin");

  const headers = {

    "Access-Control-Allow-Methods":
      "GET,POST,PUT,DELETE,OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type",

    "Access-Control-Allow-Credentials":
      "true"

  };

  if(origin){

    headers[
      "Access-Control-Allow-Origin"
    ] = origin;

    headers["Vary"] = "Origin";
  }

  return headers;
}

__name(corsHeaders, "corsHeaders");


/* ==========================================
   BODY JSON
========================================== */

async function body(request){

  try{

    return await request.json();

  }catch{

    return {};

  }
}

__name(body, "body");


/* ==========================================
   COOKIES
========================================== */

function getCookie(
  request,
  name
){

  const cookies =
    request.headers.get("Cookie") || "";

  const match =
    cookies.match(
      new RegExp(
        "(^|;\\s*)" +
        name +
        "=([^;]+)"
      )
    );

  return match
    ? decodeURIComponent(match[2])
    : null;
}

__name(getCookie, "getCookie");


function sessionCookie(token){

  return [

    `${COOKIE}=${encodeURIComponent(token)}`,

    "Path=/",

    `Max-Age=${SESSION_DAYS * 86400}`,

    "HttpOnly",

    "SameSite=Lax",

    "Secure"

  ].join("; ");
}

__name(sessionCookie, "sessionCookie");


function deleteSessionCookie(){

  return [

    `${COOKIE}=`,

    "Path=/",

    "Max-Age=0",

    "HttpOnly",

    "SameSite=Lax",

    "Secure"

  ].join("; ");
}

__name(
  deleteSessionCookie,
  "deleteSessionCookie"
);


/* ==========================================
   CONTRASEÑAS
========================================== */

async function passwordKey(
  password,
  salt
){

  const encoder =
    new TextEncoder();

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name:"PBKDF2",

        salt:
          encoder.encode(salt),

        iterations:100000,

        hash:"SHA-256"
      },

      key,

      256
    );

  return btoa(
    String.fromCharCode(
      ...new Uint8Array(bits)
    )
  ).replaceAll("=","");
}

__name(
  passwordKey,
  "passwordKey"
);


async function hashPassword(
  password
){

  const salt =
    crypto.randomUUID();

  return (
    salt +
    "." +
    await passwordKey(
      password,
      salt
    )
  );
}

__name(
  hashPassword,
  "hashPassword"
);


async function verifyPassword(
  password,
  stored
){

  if(
    !stored ||
    !stored.includes(".")
  ){

    return false;
  }

  const parts =
    stored.split(".");

  if(parts.length !== 2){

    return false;
  }

  const salt =
    parts[0];

  const hash =
    parts[1];

  const calculated =
    await passwordKey(
      password,
      salt
    );

  return calculated === hash;
}

__name(
  verifyPassword,
  "verifyPassword"
);


/* ==========================================
   BASE DE DATOS
========================================== */

async function initDatabase(env){

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires INTEGER NOT NULL
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS clans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      captain_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clan_id INTEGER NOT NULL,
      user_id INTEGER UNIQUE NOT NULL,
      role TEXT DEFAULT 'member',
      joined_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS scores (
      clan_id INTEGER PRIMARY KEY,
      points INTEGER DEFAULT 0,
      wins INTEGER DEFAULT 0,
      losses INTEGER DEFAULT 0,
      played INTEGER DEFAULT 0
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clan_id INTEGER NOT NULL,
      inviter_id INTEGER NOT NULL,
      invitee_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS notifications (
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
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      creator_clan_id INTEGER NOT NULL,
      accepter_clan_id INTEGER,
      map1 TEXT,
      map2 TEXT,
      map3 TEXT,
      status TEXT DEFAULT 'open',
      winner_clan_id INTEGER,
      completed_at TEXT
    )
  `).run();


  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS reports (
      challenge_id INTEGER NOT NULL,
      clan_id INTEGER NOT NULL,
      winner_clan_id INTEGER NOT NULL,
      PRIMARY KEY (challenge_id, clan_id)
    )
  `).run();


  await addColumn(
    env,
    "challenges",
    "team_size",
    "INTEGER DEFAULT 4"
  );


  await addColumn(
    env,
    "challenges",
    "game_modes",
    `TEXT DEFAULT '["snd"]'`
  );


  await addColumn(
    env,
    "challenges",
    "scheduled_at",
    "TEXT"
  );


  await addColumn(
    env,
    "challenges",
    "cancel_reason",
    "TEXT"
  );


  await addColumn(
    env,
    "challenges",
    "cancelled_at",
    "TEXT"
  );
}

__name(
  initDatabase,
  "initDatabase"
);


/* ==========================================
   AÑADIR COLUMNAS ANTIGUAS
========================================== */

async function addColumn(
  env,
  table,
  column,
  definition
){

  try{

    const columns =
      await env.DB.prepare(
        `PRAGMA table_info(${table})`
      ).all();

    const exists =
      columns.results.some(
        c =>
          c.name === column
      );

    if(!exists){

      await env.DB.prepare(
        `ALTER TABLE ${table}
         ADD COLUMN ${column}
         ${definition}`
      ).run();
    }

  }catch(error){

    console.log(
      "COLUMN ERROR",
      table,
      column,
      error
    );
  }
}

__name(
  addColumn,
  "addColumn"
);


/* ==========================================
   USUARIO ACTUAL
========================================== */

async function getUser(
  request,
  env
){

  const token =
    getCookie(
      request,
      COOKIE
    );

  if(!token){

    return null;
  }

  const result =
    await env.DB.prepare(`
      SELECT
        u.id,
        u.username
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE
        s.token = ?
        AND s.expires > ?
    `)
    .bind(
      token,
      Date.now()
    )
    .first();

  return result || null;
}

__name(
  getUser,
  "getUser"
);


/* ==========================================
   EQUIPO DEL USUARIO
========================================== */

async function getClan(
  env,
  userId
){

  return await env.DB.prepare(`
    SELECT
      c.*
    FROM clans c
    JOIN members m
      ON m.clan_id = c.id
    WHERE
      m.user_id = ?
    LIMIT 1
  `)
  .bind(userId)
  .first();
}

__name(
  getClan,
  "getClan"
);


/* ==========================================
   MAPAS ALEATORIOS
========================================== */

function randomMaps(){

  return [
    ...MAPS
  ]
  .sort(
    () =>
      Math.random() - 0.5
  )
  .slice(0,3);
}

__name(
  randomMaps,
  "randomMaps"
);


/* ==========================================
   NOTIFICACIONES
========================================== */

async function notify(
  env,
  userId,
  title,
  message,
  type = "general"
){

  await env.DB.prepare(`
    INSERT INTO notifications
    (
      user_id,
      title,
      message,
      type
    )
    VALUES (?, ?, ?, ?)
  `)
  .bind(
    userId,
    title,
    message,
    type
  )
  .run();
}

__name(
  notify,
  "notify"
);


/* ==========================================
   API
========================================== */

async function api(
  request,
  env,
  path
){

  const headers =
    corsHeaders(request);


  /* OPTIONS */

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


  /* USUARIO */

  const currentUser =
    await getUser(
      request,
      env
    );


  /* ========================================
     ME
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/me"
  ){

    return json(
      {
        user:
          currentUser,

        clan:
          currentUser
            ? await getClan(
                env,
                currentUser.id
              )
            : null
      },

      200,

      headers
    );
  }


  /* ========================================
     REGISTER
  ======================================== */

  if(
    request.method === "POST" &&
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
      username.length > 20
    ){

      return json(
        {
          error:
            "El usuario debe tener entre 3 y 20 caracteres."
        },

        400,

        headers
      );
    }


    if(
      password.length < 6
    ){

      return json(
        {
          error:
            "La contraseña debe tener al menos 6 caracteres."
        },

        400,

        headers
      );
    }


    const existing =
      await env.DB.prepare(
        "SELECT id FROM users WHERE username = ?"
      )
      .bind(username)
      .first();


    if(existing){

      return json(
        {
          error:
            "Ese usuario ya existe."
        },

        400,

        headers
      );
    }


    try{

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
          VALUES (?, ?)
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
        VALUES (?, ?, ?)
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

    }catch(error){

      console.error(
        "REGISTER ERROR:",
        error
      );

      return json(
        {
          error:
            "No se pudo crear la cuenta.",

          detail:
            error?.message ||
            String(error)
        },

        500,

        headers
      );
    }
  }


  /* ========================================
     LOGIN
  ======================================== */

  if(
    request.method === "POST" &&
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
      await env.DB.prepare(
        "SELECT * FROM users WHERE username = ?"
      )
      .bind(username)
      .first();


    if(
      !user ||
      !await verifyPassword(
        password,
        user.password_hash
      )
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


    const token =
      crypto.randomUUID();


    await env.DB.prepare(`
      INSERT INTO sessions
      (
        token,
        user_id,
        expires
      )
      VALUES (?, ?, ?)
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
          username:user.username
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


  /* ========================================
     LOGOUT
  ======================================== */

  if(
    request.method === "POST" &&
    path === "/api/logout"
  ){

    const token =
      getCookie(
        request,
        COOKIE
      );


    if(token){

      await env.DB.prepare(
        "DELETE FROM sessions WHERE token = ?"
      )
      .bind(token)
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


  /* ========================================
     PROTECCIÓN
  ======================================== */

  if(!currentUser){

    return json(
      {
        error:
          "Debes iniciar sesión."
      },

      401,

      headers
    );
  }


  /* ========================================
     NOTIFICACIONES
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/notifications"
  ){

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          title,
          message,
          type,
          is_read,
          created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
      `)
      .bind(
        currentUser.id
      )
      .all();


    return json(
      result.results,
      200,
      headers
    );
  }


  if(
    request.method === "POST" &&
    path === "/api/notifications/read"
  ){

    await env.DB.prepare(`
      UPDATE notifications
      SET is_read = 1
      WHERE user_id = ?
    `)
    .bind(
      currentUser.id
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


  /* ========================================
     INVITAR JUGADOR
  ======================================== */

  if(
    request.method === "POST" &&
    path === "/api/clan/invite"
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "No perteneces a ningún equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id !==
      currentUser.id
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


    const count =
      await env.DB.prepare(`
        SELECT
          COUNT(*) AS total
        FROM members
        WHERE clan_id = ?
      `)
      .bind(
        clan.id
      )
      .first();


    if(
      Number(
        count?.total || 0
      ) >= 6
    ){

      return json(
        {
          error:
            "El equipo ya tiene 6 jugadores."
        },

        400,

        headers
      );
    }


    const data =
      await body(request);

    const username =
      String(
        data.username || ""
      ).trim();


    if(!username){

      return json(
        {
          error:
            "Escribe el nombre del jugador."
        },

        400,

        headers
      );
    }


    const invited =
      await env.DB.prepare(`
        SELECT
          id,
          username
        FROM users
        WHERE username = ?
      `)
      .bind(username)
      .first();


    if(!invited){

      return json(
        {
          error:
            "No existe ningún jugador con ese nombre."
        },

        404,

        headers
      );
    }


    if(
      invited.id ===
      currentUser.id
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


    const invitedClan =
      await getClan(
        env,
        invited.id
      );


    if(invitedClan){

      return json(
        {
          error:
            "Ese jugador ya pertenece a un equipo."
        },

        400,

        headers
      );
    }


    const existing =
      await env.DB.prepare(`
        SELECT id
        FROM invites
        WHERE
          clan_id = ?
          AND invitee_id = ?
          AND status = 'pending'
      `)
      .bind(
        clan.id,
        invited.id
      )
      .first();


    if(existing){

      return json(
        {
          error:
            "Ya existe una invitación pendiente."
        },

        400,

        headers
      );
    }


    const invite =
      await env.DB.prepare(`
        INSERT INTO invites
        (
          clan_id,
          inviter_id,
          invitee_id,
          status
        )
        VALUES (?, ?, ?, 'pending')
      `)
      .bind(
        clan.id,
        currentUser.id,
        invited.id
      )
      .run();


    await notify(
      env,
      invited.id,
      "Nueva invitación",
      `${clan.name} te ha invitado a su equipo.`,
      "clan_invite"
    );


    return json(
      {
        ok:true,

        id:
          invite.meta.last_row_id
      },

      200,

      headers
    );
  }


  /* ========================================
     INVITACIONES
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/invites"
  ){

    const result =
      await env.DB.prepare(`
        SELECT
          i.id,
          i.clan_id,
          c.name AS clan,
          u.username AS inviter,
          i.created_at
        FROM invites i
        JOIN clans c
          ON c.id = i.clan_id
        JOIN users u
          ON u.id = i.inviter_id
        WHERE
          i.invitee_id = ?
          AND i.status = 'pending'
        ORDER BY i.id DESC
      `)
      .bind(
        currentUser.id
      )
      .all();


    return json(
      result.results,
      200,
      headers
    );
  }


  /* ========================================
     ACEPTAR INVITACIÓN
  ======================================== */

  const acceptInvite =
    path.match(
      /^\/api\/invites\/(\d+)\/accept$/
    );


  if(
    request.method === "POST" &&
    acceptInvite
  ){

    const inviteId =
      Number(
        acceptInvite[1]
      );


    const invite =
      await env.DB.prepare(`
        SELECT *
        FROM invites
        WHERE
          id = ?
          AND invitee_id = ?
          AND status = 'pending'
      `)
      .bind(
        inviteId,
        currentUser.id
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


    const already =
      await getClan(
        env,
        currentUser.id
      );


    if(already){

      return json(
        {
          error:
            "Ya perteneces a un equipo."
        },

        400,

        headers
      );
    }


    const count =
      await env.DB.prepare(`
        SELECT
          COUNT(*) AS total
        FROM members
        WHERE clan_id = ?
      `)
      .bind(
        invite.clan_id
      )
      .first();


    if(
      Number(
        count?.total || 0
      ) >= 6
    ){

      return json(
        {
          error:
            "El equipo ya tiene 6 jugadores."
        },

        400,

        headers
      );
    }


    await env.DB.batch([

      env.DB.prepare(`
        INSERT INTO members
        (
          clan_id,
          user_id,
          role,
          joined_at
        )
        VALUES (
          ?,
          ?,
          'member',
          CURRENT_TIMESTAMP
        )
      `)
      .bind(
        invite.clan_id,
        currentUser.id
      ),

      env.DB.prepare(`
        UPDATE invites
        SET status = 'accepted'
        WHERE id = ?
      `)
      .bind(
        inviteId
      )

    ]);


    const clan =
      await env.DB.prepare(
        "SELECT * FROM clans WHERE id = ?"
      )
      .bind(
        invite.clan_id
      )
      .first();


    if(clan){

      await notify(
        env,
        clan.captain_id,
        "Invitación aceptada",
        `${currentUser.username} se ha unido a ${clan.name}.`,
        "clan_join"
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


  /* ========================================
     RECHAZAR INVITACIÓN
  ======================================== */

  const rejectInvite =
    path.match(
      /^\/api\/invites\/(\d+)\/reject$/
    );


  if(
    request.method === "POST" &&
    rejectInvite
  ){

    const inviteId =
      Number(
        rejectInvite[1]
      );


    const invite =
      await env.DB.prepare(`
        SELECT *
        FROM invites
        WHERE
          id = ?
          AND invitee_id = ?
          AND status = 'pending'
      `)
      .bind(
        inviteId,
        currentUser.id
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
      SET status = 'rejected'
      WHERE id = ?
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


  /* ========================================
     CREAR EQUIPO
  ======================================== */

  if(
    request.method === "POST" &&
    path === "/api/clans"
  ){

    const existingClan =
      await getClan(
        env,
        currentUser.id
      );


    if(existingClan){

      return json(
        {
          error:
            "Ya perteneces a un equipo."
        },

        400,

        headers
      );
    }


    const data =
      await body(request);

    const name =
      String(
        data.name || ""
      ).trim();


    if(
      name.length < 2 ||
      name.length > 24
    ){

      return json(
        {
          error:
            "Nombre de equipo: 2-24 caracteres."
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
            captain_id
          )
          VALUES (?, ?)
        `)
        .bind(
          name,
          currentUser.id
        )
        .run();


      const clanId =
        created.meta.last_row_id;


      await env.DB.batch([

        env.DB.prepare(`
          INSERT INTO members
          (
            clan_id,
            user_id,
            role,
            joined_at
          )
          VALUES (
            ?,
            ?,
            'captain',
            CURRENT_TIMESTAMP
          )
        `)
        .bind(
          clanId,
          currentUser.id
        ),

        env.DB.prepare(`
          INSERT INTO scores
          (
            clan_id,
            points,
            wins,
            losses,
            played
          )
          VALUES (?, 0, 0, 0, 0)
        `)
        .bind(
          clanId
        )

      ]);


      return json(
        {
          ok:true,
          clanId
        },

        200,

        headers
      );

    }catch(error){

      return json(
        {
          error:
            "No se pudo crear el equipo.",

          detail:
            error?.message ||
            String(error)
        },

        500,

        headers
      );
    }
  }


  /* ========================================
     MI EQUIPO
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/clan"
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          clan:null,
          members:[],
          score:null
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
          m.role,
          m.joined_at
        FROM members m
        JOIN users u
          ON u.id = m.user_id
        WHERE
          m.clan_id = ?
        ORDER BY
          CASE
            WHEN m.role = 'captain'
            THEN 0
            ELSE 1
          END,
          m.id ASC
      `)
      .bind(
        clan.id
      )
      .all();


    const score =
      await env.DB.prepare(`
        SELECT *
        FROM scores
        WHERE clan_id = ?
      `)
      .bind(
        clan.id
      )
      .first();


    return json(
      {
        clan,
        members:
          members.results,
        score
      },

      200,

      headers
    );
  }


  /* ========================================
     ABANDONAR EQUIPO
  ======================================== */

  if(
    request.method === "POST" &&
    path === "/api/clan/leave"
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "No perteneces a ningún equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id ===
      currentUser.id
    ){

      return json(
        {
          error:
            "El capitán no puede abandonar el equipo. Primero debe gestionar el equipo."
        },

        400,

        headers
      );
    }


    await env.DB.prepare(`
      DELETE FROM members
      WHERE
        clan_id = ?
        AND user_id = ?
    `)
    .bind(
      clan.id,
      currentUser.id
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


  /* ========================================
     RANKING
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/leaderboard"
  ){

    const result =
      await env.DB.prepare(`
        SELECT
          c.id,
          c.name,

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
          ON s.clan_id = c.id

        ORDER BY
          points DESC,
          wins DESC,
          c.name ASC
      `)
      .all();


    return json(
      result.results,
      200,
      headers
    );
  }


  /* ========================================
     CREAR RETO
  ======================================== */

  if(
    request.method === "POST" &&
    path === "/api/challenges"
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "Necesitas pertenecer a un equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id !==
      currentUser.id
    ){

      return json(
        {
          error:
            "Solo el capitán puede crear retos."
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
            creator_clan_id = ?
            OR accepter_clan_id = ?
          )
          AND status IN
          ('open', 'accepted')
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
            "Tu equipo ya tiene un reto activo."
        },

        400,

        headers
      );
    }


    const data =
      await body(request);


    const teamSize =
      Number(
        data.team_size || 4
      );


    if(
      ![
        2,
        3,
        4
      ].includes(
        teamSize
      )
    ){

      return json(
        {
          error:
            "El formato debe ser 2v2, 3v3 o 4v4."
        },

        400,

        headers
      );
    }


    let gameModes =
      Array.isArray(
        data.game_modes
      )
        ? data.game_modes
        : ["snd"];


    const allowedModes = [
      "snd",
      "hardpoint",
      "ctf"
    ];


    gameModes =
      gameModes.filter(
        mode =>
          allowedModes.includes(
            mode
          )
      );


    if(
      !gameModes.length
    ){

      return json(
        {
          error:
            "Debes seleccionar al menos un modo."
        },

        400,

        headers
      );
    }


    /*
     * 🕐 HORA AUTOMÁTICA
     *
     * No confiamos en la hora enviada
     * por el navegador.
     *
     * El Worker genera la hora aquí.
     */

    const scheduledAt =
      new Date().toISOString();


    const selectedMaps =
      randomMaps();


    try{

      const created =
        await env.DB.prepare(`
          INSERT INTO challenges
          (
            creator_clan_id,
            accepter_clan_id,
            map1,
            map2,
            map3,
            status,
            team_size,
            game_modes,
            scheduled_at
          )
          VALUES
          (
            ?,
            NULL,
            ?,
            ?,
            ?,
            'open',
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
            gameModes
          ),

          scheduledAt
        )
        .run();


      return json(
        {
          ok:true,

          id:
            created.meta.last_row_id,

          scheduled_at:
            scheduledAt,

          maps:
            selectedMaps,

          team_size:
            teamSize,

          game_modes:
            gameModes
        },

        200,

        headers
      );

    }catch(error){

      return json(
        {
          error:
            "No se pudo publicar el reto.",

          detail:
            error?.message ||
            String(error)
        },

        500,

        headers
      );
    }
  }


  /* ========================================
     LISTAR RETOS
  ======================================== */

  if(
    request.method === "GET" &&
    path === "/api/challenges"
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    const clanId =
      clan?.id || -1;


    const result =
      await env.DB.prepare(`
        SELECT
          ch.*,

          a.name AS creator_name,

          b.name AS accepter_name

        FROM challenges ch

        JOIN clans a
          ON a.id =
            ch.creator_clan_id

        LEFT JOIN clans b
          ON b.id =
            ch.accepter_clan_id

        WHERE
          ch.status = 'open'
          OR ch.creator_clan_id = ?
          OR ch.accepter_clan_id = ?

        ORDER BY
          ch.id DESC
      `)
      .bind(
        clanId,
        clanId
      )
      .all();


    const challenges =
      result.results.map(
        challenge => {

          let modes = [];

          try{

            modes =
              JSON.parse(
                challenge.game_modes ||
                '["snd"]'
              );

          }catch{

            modes =
              ["snd"];
          }


          return {

            ...challenge,

            game_modes:
              modes,

            maps:[
              challenge.map1,
              challenge.map2,
              challenge.map3
            ],

            mine:
              challenge.creator_clan_id ===
                clanId ||

              challenge.accepter_clan_id ===
                clanId

          };
        }
      );


    return json(
      challenges,
      200,
      headers
    );
  }


  /* ========================================
     ACEPTAR RETO
  ======================================== */

  const acceptMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/accept$/
    );


  if(
    request.method === "POST" &&
    acceptMatch
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "Necesitas pertenecer a un equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id !==
      currentUser.id
    ){

      return json(
        {
          error:
            "Solo el capitán puede aceptar."
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
            creator_clan_id = ?
            OR accepter_clan_id = ?
          )
          AND status IN
          ('open', 'accepted')
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
            "Tu equipo ya tiene otro reto activo."
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
          id = ?
          AND status = 'open'
      `)
      .bind(
        acceptMatch[1]
      )
      .first();


    if(
      !challenge ||
      challenge.creator_clan_id ===
        clan.id
    ){

      return json(
        {
          error:
            "Reto no disponible."
        },

        400,

        headers
      );
    }


    await env.DB.prepare(`
      UPDATE challenges
      SET
        accepter_clan_id = ?,
        status = 'accepted'
      WHERE
        id = ?
        AND status = 'open'
    `)
    .bind(
      clan.id,
      challenge.id
    )
    .run();


    const creator =
      await env.DB.prepare(`
        SELECT
          captain_id
        FROM clans
        WHERE id = ?
      `)
      .bind(
        challenge.creator_clan_id
      )
      .first();


    if(creator){

      await notify(
        env,
        creator.captain_id,
        "Reto aceptado",
        `${clan.name} ha aceptado tu reto #${challenge.id}.`,
        "challenge"
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


  /* ========================================
     CANCELAR RETO
  ======================================== */

  const cancelMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/cancel$/
    );


  if(
    request.method === "POST" &&
    cancelMatch
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "No perteneces a ningún equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id !==
      currentUser.id
    ){

      return json(
        {
          error:
            "Solo el capitán puede cancelar."
        },

        403,

        headers
      );
    }


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE
          id = ?
          AND status IN
          ('open', 'accepted')
      `)
      .bind(
        cancelMatch[1]
      )
      .first();


    if(!challenge){

      return json(
        {
          error:
            "Reto no encontrado o ya terminado."
        },

        404,

        headers
      );
    }


    if(
      challenge.creator_clan_id !==
        clan.id &&

      challenge.accepter_clan_id !==
        clan.id
    ){

      return json(
        {
          error:
            "No puedes cancelar este reto."
        },

        403,

        headers
      );
    }


    const data =
      await body(request);


    const reason =
      String(
        data.reason ||
        "Reto cancelado."
      ).slice(
        0,
        500
      );


    await env.DB.prepare(`
      UPDATE challenges
      SET
        status = 'cancelled',
        cancel_reason = ?,
        cancelled_at =
          CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(
      reason,
      challenge.id
    )
    .run();


    const otherClanId =
      challenge.creator_clan_id ===
        clan.id

        ? challenge.accepter_clan_id

        : challenge.creator_clan_id;


    if(otherClanId){

      const otherClan =
        await env.DB.prepare(`
          SELECT
            captain_id
          FROM clans
          WHERE id = ?
        `)
        .bind(
          otherClanId
        )
        .first();


      if(otherClan){

        await notify(
          env,
          otherClan.captain_id,
          "Reto cancelado",
          `${clan.name} ha cancelado el reto #${challenge.id}.`,
          "challenge"
        );
      }
    }


    return json(
      {
        ok:true
      },

      200,

      headers
    );
  }


  /* ========================================
     CHAT - GET
  ======================================== */

  const chatGet =
    path.match(
      /^\/api\/challenges\/(\d+)\/chat$/
    );


  if(
    request.method === "GET" &&
    chatGet
  ){

    const challengeId =
      Number(
        chatGet[1]
      );


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE id = ?
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
      await getClan(
        env,
        currentUser.id
      );


    if(
      !clan ||

      (
        clan.id !==
          challenge.creator_clan_id &&

        clan.id !==
          challenge.accepter_clan_id
      )
    ){

      return json(
        {
          error:
            "No tienes acceso a este chat."
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
          u.username
        FROM chat_messages cm
        JOIN users u
          ON u.id = cm.user_id
        WHERE
          cm.challenge_id = ?
        ORDER BY
          cm.id ASC
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


  /* ========================================
     CHAT - POST
  ======================================== */

  const chatPost =
    path.match(
      /^\/api\/challenges\/(\d+)\/chat$/
    );


  if(
    request.method === "POST" &&
    chatPost
  ){

    const challengeId =
      Number(
        chatPost[1]
      );


    const challenge =
      await env.DB.prepare(`
        SELECT *
        FROM challenges
        WHERE id = ?
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
      await getClan(
        env,
        currentUser.id
      );


    if(
      !clan ||

      (
        clan.id !==
          challenge.creator_clan_id &&

        clan.id !==
          challenge.accepter_clan_id
      )
    ){

      return json(
        {
          error:
            "No tienes acceso a este chat."
        },

        403,

        headers
      );
    }


    const data =
      await body(request);


    const message =
      String(
        data.message || ""
      ).trim();


    if(!message){

      return json(
        {
          error:
            "El mensaje está vacío."
        },

        400,

        headers
      );
    }


    if(
      message.length > 1000
    ){

      return json(
        {
          error:
            "El mensaje es demasiado largo."
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
      VALUES (?, ?, ?)
    `)
    .bind(
      challengeId,
      currentUser.id,
      message
    )
    .run();


    const otherClanId =
      clan.id ===
        challenge.creator_clan_id

        ? challenge.accepter_clan_id

        : challenge.creator_clan_id;


    if(otherClanId){

      const otherClan =
        await env.DB.prepare(`
          SELECT
            captain_id
          FROM clans
          WHERE id = ?
        `)
        .bind(
          otherClanId
        )
        .first();


      if(otherClan){

        await notify(
          env,
          otherClan.captain_id,
          "Nuevo mensaje",
          `${currentUser.username} ha escrito en el chat del reto #${challengeId}.`,
          "chat"
        );
      }
    }


    return json(
      {
        ok:true
      },

      200,

      headers
    );
  }


  /* ========================================
     RESULTADO DEL RETO
     
     win  = mi equipo ganó
     loss = mi equipo perdió
  ======================================== */

  const reportMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/report$/
    );


  if(
    request.method === "POST" &&
    reportMatch
  ){

    const clan =
      await getClan(
        env,
        currentUser.id
      );


    if(!clan){

      return json(
        {
          error:
            "Necesitas pertenecer a un equipo."
        },

        400,

        headers
      );
    }


    if(
      clan.captain_id !==
      currentUser.id
    ){

      return json(
        {
          error:
            "Solo el capitán puede reportar el resultado."
        },

        403,

        headers
      );
    }


    const challengeId =
      Number(
        reportMatch[1]
      );


    const data =
      await body(request);


    const result =
      String(
        data.result || ""
      ).toLowerCase();


    /*
     * Solo permitimos:
     *
     * win
     * loss
     */

    if(
      result !== "win" &&
      result !== "loss"
    ){

      return json(
        {
          error:
            "El resultado debe ser win o loss."
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
          id = ?
          AND status = 'accepted'
      `)
      .bind(
        challengeId
      )
      .first();


    if(!challenge){

      return json(
        {
          error:
            "Reto no encontrado o ya terminado."
        },

        404,

        headers
      );
    }


    /*
     * Comprobamos que el capitán
     * pertenece a uno de los dos equipos.
     */

    if(
      clan.id !==
        challenge.creator_clan_id &&

      clan.id !==
        challenge.accepter_clan_id
    ){

      return json(
        {
          error:
            "No puedes reportar este reto."
        },

        403,

        headers
      );
    }


    /*
     * Convertimos:
     *
     * win  -> mi equipo es ganador
     *
     * loss -> el otro equipo es ganador
     */

    const winnerClanId =
      result === "win"

        ? clan.id

        : (
            clan.id ===
              challenge.creator_clan_id

              ? challenge.accepter_clan_id

              : challenge.creator_clan_id
          );


    /*
     * Guardamos el resultado
     * de este capitán.
     *
     * INSERT OR REPLACE permite
     * corregir su resultado antes
     * de que se confirme el reto.
     */

    await env.DB.prepare(`
      INSERT OR REPLACE INTO reports
      (
        challenge_id,
        clan_id,
        winner_clan_id
      )
      VALUES (?, ?, ?)
    `)
    .bind(
      challengeId,
      clan.id,
      winnerClanId
    )
    .run();


    /*
     * Comprobamos los dos resultados.
     */

    const reports =
      await env.DB.prepare(`
        SELECT
          challenge_id,
          clan_id,
          winner_clan_id
        FROM reports
        WHERE
          challenge_id = ?
      `)
      .bind(
        challengeId
      )
      .all();


    const results =
      reports.results || [];


    /*
     * Solo ha respondido un capitán.
     */

    if(
      results.length < 2
    ){

      return json(
        {
          ok:true,

          completed:false,

          conflict:false,

          message:
            "Resultado enviado. Falta la confirmación del otro capitán."
        },

        200,

        headers
      );
    }


    /*
     * Tenemos los dos resultados.
     */

    const firstWinner =
      Number(
        results[0].winner_clan_id
      );


    const secondWinner =
      Number(
        results[1].winner_clan_id
      );


    /*
     * ================================
     * RESULTADOS COINCIDEN
     * ================================
     *
     * Ejemplo:
     *
     * Equipo A -> Victoria
     * Equipo B -> Derrota
     *
     * Los dos están diciendo
     * que ganó Equipo A.
     */

    if(
      firstWinner ===
      secondWinner
    ){

      const winner =
        firstWinner;


      const loser =
        winner ===
          Number(
            challenge.creator_clan_id
          )

          ? Number(
              challenge.accepter_clan_id
            )

          : Number(
              challenge.creator_clan_id
            );


      /*
       * Cerramos el reto y actualizamos
       * las estadísticas.
       */

      await env.DB.batch([

        env.DB.prepare(`
          UPDATE challenges
          SET
            status = 'completed',
            winner_clan_id = ?,
            completed_at =
              CURRENT_TIMESTAMP
          WHERE
            id = ?
            AND status = 'accepted'
        `)
        .bind(
          winner,
          challengeId
        ),


        /*
         * GANADOR
         *
         * +10 puntos
         * +1 victoria
         * +1 partido
         */

        env.DB.prepare(`
          UPDATE scores
          SET
            points =
              MAX(
                0,
                points + 10
              ),

            wins =
              wins + 1,

            played =
              played + 1

          WHERE
            clan_id = ?
        `)
        .bind(
          winner
        ),


        /*
         * PERDEDOR
         *
         * -5 puntos
         * +1 derrota
         * +1 partido
         */

        env.DB.prepare(`
          UPDATE scores
          SET
            points =
              MAX(
                0,
                points - 5
              ),

            losses =
              losses + 1,

            played =
              played + 1

          WHERE
            clan_id = ?
        `)
        .bind(
          loser
        )

      ]);


      /*
       * Capitán del creador.
       */

      const creator =
        await env.DB.prepare(`
          SELECT
            captain_id
          FROM clans
          WHERE id = ?
        `)
        .bind(
          challenge.creator_clan_id
        )
        .first();


      /*
       * Capitán del rival.
       */

      const accepter =
        await env.DB.prepare(`
          SELECT
            captain_id
          FROM clans
          WHERE id = ?
        `)
        .bind(
          challenge.accepter_clan_id
        )
        .first();


      /*
       * Notificación creador.
       */

      if(creator){

        await notify(
          env,
          creator.captain_id,
          "🏆 Resultado confirmado",
          `El reto #${challengeId} ha terminado. El resultado ha sido confirmado.`,
          "result"
        );
      }


      /*
       * Notificación rival.
       */

      if(
        accepter &&

        accepter.captain_id !==
          creator?.captain_id
      ){

        await notify(
          env,
          accepter.captain_id,
          "🏆 Resultado confirmado",
          `El reto #${challengeId} ha terminado. El resultado ha sido confirmado.`,
          "result"
        );
      }


      /*
       * Al pasar a COMPLETED,
       * deja de ser un reto activo.
       *
       * Por tanto los dos equipos
       * pueden jugar otro.
       */

      return json(
        {
          ok:true,

          completed:true,

          conflict:false,

          winner_clan_id:
            winner,

          loser_clan_id:
            loser,

          message:
            "Resultado confirmado. El reto ha terminado."
        },

        200,

        headers
      );
    }


    /*
     * ================================
     * RESULTADOS NO COINCIDEN
     * ================================
     *
     * Ejemplo:
     *
     * Equipo A -> Victoria
     * Equipo B -> Victoria
     *
     * Cada uno dice que ha ganado.
     *
     * No damos puntos.
     * No cerramos el reto.
     */

    return json(
      {
        ok:true,

        completed:false,

        conflict:true,

        message:
          "Los resultados no coinciden. El reto queda pendiente de revisión."
      },

      200,

      headers
    );
  }


  /* ========================================
     NO ENCONTRADO
  ======================================== */

  return json(
    {
      error:
        "No encontrado."
    },

    404,

    headers
  );
}

__name(
  api,
  "api"
);


/* ==========================================
   WORKER PRINCIPAL
========================================== */

var worker_default = {

  async fetch(
    request,
    env
  ){

    try{

      /*
       * Creamos/verificamos las tablas
       * necesarias.
       */

      await initDatabase(
        env
      );


      const url =
        new URL(
          request.url
        );


      /*
       * Todas las rutas /api/
       * pasan por nuestro backend.
       */

      if(
        url.pathname.startsWith(
          "/api/"
        )
      ){

        return await api(
          request,
          env,
          url.pathname
        );
      }


      /*
       * El resto lo sirve Cloudflare
       * desde ASSETS.
       */

      if(env.ASSETS){

        return await env.ASSETS.fetch(
          request
        );
      }


      return new Response(
        "ASSETS no está configurado.",

        {
          status:500,

          headers:{
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );

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
            error?.message ||
            String(error)
        },

        500,

        corsHeaders(
          request
        )
      );
    }
  }
};


export {
  worker_default as default
};
