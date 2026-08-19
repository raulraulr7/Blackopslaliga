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

const LEAGUES = [1, 2, 3, 4];

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
        "content-type": "application/json; charset=utf-8",
        ...headers
      }
    }
  );


const text = (
  value,
  status = 200,
  headers = {}
) =>
  new Response(
    value,
    {
      status,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        ...headers
      }
    }
  );


const errorResponse = (
  message,
  status = 400
) =>
  json(
    {
      error: message
    },
    status
  );


function normalizeLeague(value){

  const n =
    Number(value);

  if(
    !LEAGUES.includes(n)
  ){
    return null;
  }

  return n;
}


function normalizeTeamSize(value){

  const n =
    Number(value);

  return normalizeLeague(n);
}


function leagueName(value){

  const n =
    Number(value);

  return (
    {
      1: "1v1",
      2: "2v2",
      3: "3v3",
      4: "4v4"
    }[n]
    ||
    null
  );
}


function normalizeMode(
  mode,
  league
){

  const value =
    String(
      mode || ""
    )
      .trim()
      .toLowerCase();

  if(
    Number(league) === 1
  ){

    if(
      value === "franco" ||
      value === "sniper" ||
      value === "francotirador"
    ){

      return "franco";

    }

    if(
      value === "arma" ||
      value === "weapon"
    ){

      return "arma";

    }

    return null;

  }


  if(
    value === "snd" ||
    value === "search" ||
    value === "buscar y destruir" ||
    value === "buscar_y_destruir"
  ){

    return "snd";

  }


  if(
    value === "ctf" ||
    value === "tomar bandera" ||
    value === "tomar_bandera"
  ){

    return "ctf";

  }


  if(
    value === "hardpoint" ||
    value === "punto caliente" ||
    value === "punto_caliente"
  ){

    return "hardpoint";

  }


  return null;

}


function allowedModes(
  league
){

  return Number(league) === 1
    ? [
        "franco",
        "arma"
      ]
    : [
        "snd",
        "ctf",
        "hardpoint"
      ];

}


function cleanUsername(
  value
){

  return String(
    value || ""
  )
    .trim()
    .slice(0, 30);

}


function cleanClanName(
  value
){

  return String(
    value || ""
  )
    .trim()
    .slice(0, 40);

}


function cleanClanCode(
  value
){

  return String(
    value || ""
  )
    .trim()
    .slice(0, 12);

}


function cleanPsn(
  value
){

  return String(
    value || ""
  )
    .trim()
    .slice(0, 32);

}


function getCookie(
  request,
  name
){

  const header =
    request.headers.get(
      "Cookie"
    );

  if(!header)
    return null;


  const parts =
    header.split(";");


  for(
    const part of parts
  ){

    const index =
      part.indexOf("=");

    if(index === -1)
      continue;


    const key =
      part
        .slice(0,index)
        .trim();


    if(key !== name)
      continue;


    return decodeURIComponent(
      part
        .slice(index + 1)
        .trim()
    );

  }


  return null;

}


function sessionCookie(
  token
){

  return [
    `${COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Secure",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");

}


function clearSessionCookie(){

  return [
    `${COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Secure",
    "Max-Age=0"
  ].join("; ");

}


async function bodyJson(
  request
){

  try{

    return await request.json();

  }catch(error){

    return {};

  }

}


async function getSessionUser(
  request,
  env
){

  const token =
    getCookie(
      request,
      COOKIE
    );


  if(!token)
    return null;


  const row =
    await env.DB.prepare(`
      SELECT
        s.token,
        s.user_id,
        u.id,
        u.username,
        u.psn_id,
        u.is_admin
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND (
          s.expires_at IS NULL
          OR s.expires_at > CURRENT_TIMESTAMP
        )
      LIMIT 1
    `)
    .bind(token)
    .first();


  if(!row)
    return null;


  return row;

}


async function requireUser(
  request,
  env
){

  const user =
    await getSessionUser(
      request,
      env
    );


  if(!user){

    throw new Error(
      "Debes iniciar sesión."
    );

  }


  return user;

}


async function requireAdmin(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  if(
    Number(user.is_admin || 0) !== 1
  ){

    throw new Error(
      "No tienes permisos de administrador."
    );

  }


  return user;

}


function makeToken(){

  const bytes =
    new Uint8Array(32);

  crypto.getRandomValues(
    bytes
  );


  return Array.from(
    bytes
  )
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2,"0")
    )
    .join("");

}


async function hashPassword(
  password
){

  const data =
    new TextEncoder()
      .encode(
        String(password || "")
      );


  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );


  return Array.from(
    new Uint8Array(hash)
  )
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2,"0")
    )
    .join("");

}


async function createNotification(
  env,
  {
    userId,
    type,
    title,
    message = "",
    challengeId = null,
    clanId = null,
    relatedId = null,
    targetType = null,
    targetId = null
  }
){

  if(!userId)
    return null;


  const result =
    await env.DB.prepare(`
      INSERT INTO notifications (
        user_id,
        type,
        title,
        message,
        challenge_id,
        clan_id,
        is_read,
        created_at,
        related_id,
        target_type,
        target_id
      )
      VALUES (
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        0,
        CURRENT_TIMESTAMP,
        ?,
        ?,
        ?
      )
    `)
    .bind(
      Number(userId),
      String(type || "info"),
      String(title || ""),
      String(message || ""),
      challengeId == null
        ? null
        : Number(challengeId),
      clanId == null
        ? null
        : Number(clanId),
      relatedId == null
        ? null
        : Number(relatedId),
      targetType,
      targetId == null
        ? null
        : Number(targetId)
    )
    .run();


  return result;

}


async function getUserClan(
  env,
  userId,
  league
){

  const sector =
    normalizeLeague(
      league
    );


  if(!sector)
    return null;


  return await env.DB.prepare(`
    SELECT
      c.*,
      m.user_id AS member_user_id
    FROM clans c
    JOIN members m
      ON m.clan_id = c.id
    WHERE m.user_id = ?
      AND c.league = ?
    ORDER BY c.id ASC
    LIMIT 1
  `)
  .bind(
    Number(userId),
    sector
  )
  .first();

}


async function getClan(
  env,
  clanId
){

  return await env.DB.prepare(`
    SELECT *
    FROM clans
    WHERE id = ?
    LIMIT 1
  `)
  .bind(
    Number(clanId)
  )
  .first();

}


async function isClanMember(
  env,
  clanId,
  userId
){

  const row =
    await env.DB.prepare(`
      SELECT 1
      FROM members
      WHERE clan_id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      Number(clanId),
      Number(userId)
    )
    .first();


  return Boolean(row);

}


async function isClanCaptain(
  env,
  clanId,
  userId
){

  const clan =
    await getClan(
      env,
      clanId
    );


  if(!clan)
    return false;


  return (
    Number(
      clan.captain_id ||
      clan.owner_id ||
      0
    ) ===
    Number(userId)
  );

}


async function clanMemberCount(
  env,
  clanId
){

  const row =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM members
      WHERE clan_id = ?
    `)
    .bind(
      Number(clanId)
    )
    .first();


  return Number(
    row?.count || 0
  );

}


async function getClanMembers(
  env,
  clanId
){

  const result =
    await env.DB.prepare(`
      SELECT
        m.id,
        m.user_id,
        m.clan_id,
        u.username,
        u.psn_id,
        u.is_admin
      FROM members m
      JOIN users u
        ON u.id = m.user_id
      WHERE m.clan_id = ?
      ORDER BY
        m.id ASC
    `)
    .bind(
      Number(clanId)
    )
    .all();


  return result.results || [];

}


async function getClansForUser(
  env,
  userId
){

  const result =
    await env.DB.prepare(`
      SELECT
        c.*,
        (
          SELECT COUNT(*)
          FROM members m2
          WHERE m2.clan_id = c.id
        ) AS member_count
      FROM clans c
      JOIN members m
        ON m.clan_id = c.id
      WHERE m.user_id = ?
      ORDER BY c.league ASC, c.id ASC
    `)
    .bind(
      Number(userId)
    )
    .all();


  return result.results || [];

}


function routePath(
  request
){

  return new URL(
    request.url
  ).pathname;

}


function method(
  request
){

  return request.method
    .toUpperCase();

}


async function handleRegister(
  request,
  env
){

  const body =
    await bodyJson(
      request
    );


  const username =
    cleanUsername(
      body.username
    );


  const password =
    String(
      body.password || ""
    );


  const psnId =
    cleanPsn(
      body.psn_id ||
      body.psn ||
      ""
    );


  if(
    username.length < 3
  ){

    return errorResponse(
      "El usuario debe tener al menos 3 caracteres."
    );

  }


  if(
    password.length < 4
  ){

    return errorResponse(
      "La contraseña debe tener al menos 4 caracteres."
    );

  }


  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER(?)
      LIMIT 1
    `)
    .bind(
      username
    )
    .first();


  if(existing){

    return errorResponse(
      "Ese usuario ya existe.",
      409
    );

  }


  const passwordHash =
    await hashPassword(
      password
    );


  const result =
    await env.DB.prepare(`
      INSERT INTO users (
        username,
        password_hash,
        psn_id,
        is_admin
      )
      VALUES (
        ?,
        ?,
        ?,
        0
      )
    `)
    .bind(
      username,
      passwordHash,
      psnId || null
    )
    .run();


  const userId =
    result.meta?.last_row_id;


  if(!userId){

    return errorResponse(
      "No se ha podido crear la cuenta.",
      500
    );

  }


  const token =
    makeToken();


  await env.DB.prepare(`
    INSERT INTO sessions (
      token,
      user_id,
      expires_at
    )
    VALUES (
      ?,
      ?,
      datetime(
        'now',
        '+${SESSION_DAYS} days'
      )
    )
  `)
  .bind(
    token,
    Number(userId)
  )
  .run();


  return json(
    {
      ok:true,

      user:{
        id:Number(userId),
        username,
        psn_id:
          psnId || null,
        is_admin:0
      }
    },
    201,
    {
      "Set-Cookie":
        sessionCookie(
          token
        )
    }
  );

}


async function handleLogin(
  request,
  env
){

  const body =
    await bodyJson(
      request
    );


  const username =
    cleanUsername(
      body.username
    );


  const password =
    String(
      body.password || ""
    );


  if(
    !username ||
    !password
  ){

    return errorResponse(
      "Usuario y contraseña son obligatorios."
    );

  }


  const passwordHash =
    await hashPassword(
      password
    );


  const user =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        psn_id,
        is_admin
      FROM users
      WHERE LOWER(username) = LOWER(?)
        AND password_hash = ?
      LIMIT 1
    `)
    .bind(
      username,
      passwordHash
    )
    .first();


  if(!user){

    return errorResponse(
      "Usuario o contraseña incorrectos.",
      401
    );

  }


  const token =
    makeToken();


  await env.DB.prepare(`
    INSERT INTO sessions (
      token,
      user_id,
      expires_at
    )
    VALUES (
      ?,
      ?,
      datetime(
        'now',
        '+${SESSION_DAYS} days'
      )
    )
  `)
  .bind(
    token,
    Number(user.id)
  )
  .run();


  return json(
    {
      ok:true,

      user:{
        id:Number(user.id),
        username:user.username,
        psn_id:
          user.psn_id || null,
        is_admin:
          Number(
            user.is_admin || 0
          )
      },

      admin:
        Number(
          user.is_admin || 0
        ) === 1
    },
    200,
    {
      "Set-Cookie":
        sessionCookie(
          token
        )
    }
  );

}


async function handleLogout(
  request,
  env
){

  const token =
    getCookie(
      request,
      COOKIE
    );


  if(token){

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
    .bind(token)
    .run();

  }


  return json(
    {
      ok:true
    },
    200,
    {
      "Set-Cookie":
        clearSessionCookie()
    }
  );

}


async function handleMe(
  request,
  env
){

  const user =
    await getSessionUser(
      request,
      env
    );


  if(!user){

    return json(
      {
        user:null,
        admin:false
      }
    );

  }


  return json(
    {
      user:{
        id:Number(user.id),
        username:user.username,
        psn_id:
          user.psn_id || null,
        is_admin:
          Number(
            user.is_admin || 0
          )
      },

      admin:
        Number(
          user.is_admin || 0
        ) === 1
    }
  );

}


async function handleUpdateMe(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const body =
    await bodyJson(
      request
    );


  const psnId =
    cleanPsn(
      body.psn_id ||
      body.psn ||
      ""
    );


  await env.DB.prepare(`
    UPDATE users
    SET psn_id = ?
    WHERE id = ?
  `)
  .bind(
    psnId || null,
    Number(user.id)
  )
  .run();


  return json({
    ok:true,

    user:{
      id:Number(user.id),
      username:user.username,
      psn_id:
        psnId || null,
      is_admin:
        Number(
          user.is_admin || 0
        )
    }
  });

}


/* =====================================================
   FIN WORKER PARTE 1/4
===================================================== */
async function handleStats(
  request,
  env
){

  const users =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM users
    `)
    .first();


  const clans =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM clans
    `)
    .first();


  const challenges =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM challenges
    `)
    .first();


  return json({

    users:
      Number(
        users?.count || 0
      ),

    clans:
      Number(
        clans?.count || 0
      ),

    challenges:
      Number(
        challenges?.count || 0
      )

  });

}


/* =====================================================
   CLANES
===================================================== */

async function handleCreateClan(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const body =
    await bodyJson(
      request
    );


  const name =
    cleanClanName(
      body.name ||
      body.clan_name
    );


  const clanCode =
    cleanClanCode(
      body.clan_code ||
      body.code ||
      body.insignia
    );


  const league =
    normalizeLeague(
      body.league ||
      body.team_size
    );


  if(!name){

    return errorResponse(
      "El nombre del clan es obligatorio."
    );

  }


  if(
    name.length < 2
  ){

    return errorResponse(
      "El nombre del clan es demasiado corto."
    );

  }


  if(!clanCode){

    return errorResponse(
      "La insignia del clan es obligatoria."
    );

  }


  if(!league){

    return errorResponse(
      "El sector debe ser 1v1, 2v2, 3v3 o 4v4."
    );

  }


  /*
    Cada usuario puede tener un clan
    por sector.
  */

  const existingMembership =
    await getUserClan(
      env,
      user.id,
      league
    );


  if(existingMembership){

    return errorResponse(
      `Ya perteneces a un clan de ${leagueName(league)}.`
    );

  }


  /*
    Evitamos duplicados de nombre.
  */

  const existingName =
    await env.DB.prepare(`
      SELECT id
      FROM clans
      WHERE LOWER(name) = LOWER(?)
      LIMIT 1
    `)
    .bind(
      name
    )
    .first();


  if(existingName){

    return errorResponse(
      "Ya existe un clan con ese nombre."
    );

  }


  /*
    La insignia puede repetirse en
    distintos sectores.
  */

  const result =
    await env.DB.prepare(`
      INSERT INTO clans (
        name,
        clan_code,
        captain_id,
        league,
        created_at
      )
      VALUES (
        ?,
        ?,
        ?,
        ?,
        CURRENT_TIMESTAMP
      )
    `)
    .bind(
      name,
      clanCode,
      Number(user.id),
      league
    )
    .run();


  const clanId =
    Number(
      result.meta?.last_row_id || 0
    );


  if(!clanId){

    return errorResponse(
      "No se ha podido crear el clan.",
      500
    );

  }


  /*
    El creador entra automáticamente
    como miembro.
  */

  await env.DB.prepare(`
    INSERT INTO members (
      clan_id,
      user_id
    )
    VALUES (
      ?,
      ?
    )
  `)
  .bind(
    clanId,
    Number(user.id)
  )
  .run();


  const clan =
    await getClan(
      env,
      clanId
    );


  return json(
    {
      ok:true,

      message:
        "Clan creado correctamente.",

      clan:{
        ...clan,
        league,
        team_size:league,
        member_count:1
      }
    },
    201
  );

}


async function handleClans(
  request,
  env
){

  const url =
    new URL(
      request.url
    );


  const search =
    String(
      url.searchParams.get(
        "search"
      ) ||
      ""
    )
    .trim();


  const leagueParam =
    url.searchParams.get(
      "league"
    );


  let league =
    null;


  if(
    leagueParam &&
    leagueParam !== "0"
  ){

    league =
      normalizeLeague(
        leagueParam
      );


    if(!league){

      return errorResponse(
        "Sector no válido."
      );

    }

  }


  let query = `
    SELECT
      c.*,
      (
        SELECT COUNT(*)
        FROM members m
        WHERE m.clan_id = c.id
      ) AS member_count
    FROM clans c
    WHERE 1 = 1
  `;


  const params = [];


  if(search){

    query += `
      AND LOWER(c.name)
      LIKE LOWER(?)
    `;

    params.push(
      `%${search}%`
    );

  }


  if(league){

    query += `
      AND c.league = ?
    `;

    params.push(
      league
    );

  }


  query += `
    ORDER BY
      c.league ASC,
      c.name COLLATE NOCASE ASC
  `;


  const result =
    await env.DB.prepare(
      query
    )
    .bind(
      ...params
    )
    .all();


  return json(
    {
      clans:
        result.results || []
    }
  );

}


async function handleMyClans(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const clans =
    await getClansForUser(
      env,
      user.id
    );


  return json(
    {
      clans
    }
  );

}


async function handleClan(
  request,
  env,
  clanId
){

  const clan =
    await getClan(
      env,
      clanId
    );


  if(!clan){

    return errorResponse(
      "Clan no encontrado.",
      404
    );

  }


  const members =
    await getClanMembers(
      env,
      clanId
    );


  return json({

    ...clan,

    league:
      Number(
        clan.league ||
        clan.team_size ||
        4
      ),

    team_size:
      Number(
        clan.league ||
        clan.team_size ||
        4
      ),

    member_count:
      members.length,

    members

  });

}


/* =====================================================
   INVITACIONES
===================================================== */

async function handleCreateInvite(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const body =
    await bodyJson(
      request
    );


  const clanId =
    Number(
      body.clan_id ||
      body.clanId ||
      0
    );


  const targetUserId =
    Number(
      body.user_id ||
      body.userId ||
      0
    );


  if(!clanId){

    return errorResponse(
      "Falta el clan."
    );

  }


  if(!targetUserId){

    return errorResponse(
      "Falta el ID del usuario."
    );

  }


  const clan =
    await getClan(
      env,
      clanId
    );


  if(!clan){

    return errorResponse(
      "El clan no existe.",
      404
    );

  }


  const isCaptain =
    await isClanCaptain(
      env,
      clanId,
      user.id
    );


  if(
    !isCaptain &&
    !Number(user.is_admin || 0)
  ){

    return errorResponse(
      "Solo el capitán puede invitar jugadores.",
      403
    );

  }


  if(
    Number(targetUserId) ===
    Number(user.id)
  ){

    return errorResponse(
      "No puedes invitarte a ti mismo."
    );

  }


  const targetUser =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        psn_id
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(
      targetUserId
    )
    .first();


  if(!targetUser){

    return errorResponse(
      "El usuario no existe.",
      404
    );

  }


  const alreadyMember =
    await isClanMember(
      env,
      clanId,
      targetUserId
    );


  if(alreadyMember){

    return errorResponse(
      "Ese usuario ya pertenece al clan."
    );

  }


  /*
    Comprobamos si ya pertenece a otro
    clan del mismo sector.
  */

  const currentClan =
    await getUserClan(
      env,
      targetUserId,
      clan.league
    );


  if(currentClan){

    return errorResponse(
      `Ese usuario ya pertenece a otro clan de ${leagueName(clan.league)}.`
    );

  }


  /*
    Comprobamos invitación pendiente.
  */

  const pendingInvite =
    await env.DB.prepare(`
      SELECT id
      FROM invites
      WHERE clan_id = ?
        AND user_id = ?
        AND (
          status IS NULL
          OR status = 'pending'
          OR status = 'open'
        )
      ORDER BY id DESC
      LIMIT 1
    `)
    .bind(
      clanId,
      targetUserId
    )
    .first();


  if(pendingInvite){

    return errorResponse(
      "Ese usuario ya tiene una invitación pendiente."
    );

  }


  /*
    La estructura de invites puede variar
    según la versión de D1. Primero usamos
    las columnas básicas.
  */

  const inviteResult =
    await env.DB.prepare(`
      INSERT INTO invites (
        clan_id,
        user_id,
        status,
        created_at
      )
      VALUES (
        ?,
        ?,
        'pending',
        CURRENT_TIMESTAMP
      )
    `)
    .bind(
      clanId,
      targetUserId
    )
    .run();


  const inviteId =
    Number(
      inviteResult.meta?.last_row_id ||
      0
    );


  await createNotification(
    env,
    {
      userId:
        targetUserId,

      type:
        "clan_invite",

      title:
        "Invitación a clan",

      message:
        `${clan.name} te ha invitado a unirte a su clan.`,

      clanId:
        clanId,

      relatedId:
        inviteId,

      targetType:
        "clan_invite",

      targetId:
        inviteId
    }
  );


  return json(
    {
      ok:true,

      message:
        "Invitación enviada.",

      invite_id:
        inviteId
    },
    201
  );

}


async function handleInvites(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const result =
    await env.DB.prepare(`
      SELECT
        i.*,
        c.name AS clan_name,
        c.clan_code,
        c.league,
        u.username AS inviter_username
      FROM invites i
      JOIN clans c
        ON c.id = i.clan_id
      LEFT JOIN users u
        ON u.id = c.captain_id
      WHERE i.user_id = ?
      ORDER BY i.id DESC
    `)
    .bind(
      Number(user.id)
    )
    .all();


  return json(
    {
      invites:
        result.results || []
    }
  );

}


async function handleMyInvites(
  request,
  env
){

  return handleInvites(
    request,
    env
  );

}


async function handleAcceptInvite(
  request,
  env,
  inviteId
){

  const user =
    await requireUser(
      request,
      env
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
        ON c.id = i.clan_id
      WHERE i.id = ?
        AND i.user_id = ?
      LIMIT 1
    `)
    .bind(
      Number(inviteId),
      Number(user.id)
    )
    .first();


  if(!invite){

    return errorResponse(
      "Invitación no encontrada.",
      404
    );

  }


  if(
    invite.status &&
    ![
      "pending",
      "open"
    ].includes(
      String(
        invite.status
      )
    )
  ){

    return errorResponse(
      "Esta invitación ya no está pendiente."
    );

  }


  const existingClan =
    await getUserClan(
      env,
      user.id,
      invite.league
    );


  if(existingClan){

    return errorResponse(
      `Ya perteneces a un clan de ${leagueName(invite.league)}.`
    );

  }


  const memberCount =
    await clanMemberCount(
      env,
      invite.clan_id
    );


  const maxMembers =
    Number(
      invite.league
    );


  if(
    memberCount >= maxMembers
  ){

    return errorResponse(
      "El clan ya está completo."
    );

  }


  await env.DB.prepare(`
    INSERT INTO members (
      clan_id,
      user_id
    )
    VALUES (
      ?,
      ?
    )
  `)
  .bind(
    Number(invite.clan_id),
    Number(user.id)
  )
  .run();


  await env.DB.prepare(`
    UPDATE invites
    SET status = 'accepted'
    WHERE id = ?
  `)
  .bind(
    Number(inviteId)
  )
  .run();


  /*
    Avisamos al capitán.
  */

  await createNotification(
    env,
    {
      userId:
        invite.captain_id,

      type:
        "clan_invite_accepted",

      title:
        "Invitación aceptada",

      message:
        `${user.username} ha aceptado la invitación a ${invite.clan_name}.`,

      clanId:
        invite.clan_id,

      relatedId:
        Number(inviteId),

      targetType:
        "clan",

      targetId:
        invite.clan_id
    }
  );


  return json({
    ok:true,

    message:
      "Te has unido al clan."
  });

}


async function handleRejectInvite(
  request,
  env,
  inviteId
){

  const user =
    await requireUser(
      request,
      env
    );


  const invite =
    await env.DB.prepare(`
      SELECT
        i.*,
        c.name AS clan_name,
        c.captain_id
      FROM invites i
      JOIN clans c
        ON c.id = i.clan_id
      WHERE i.id = ?
        AND i.user_id = ?
      LIMIT 1
    `)
    .bind(
      Number(inviteId),
      Number(user.id)
    )
    .first();


  if(!invite){

    return errorResponse(
      "Invitación no encontrada.",
      404
    );

  }


  await env.DB.prepare(`
    UPDATE invites
    SET status = 'rejected'
    WHERE id = ?
  `)
  .bind(
    Number(inviteId)
  )
  .run();


  await createNotification(
    env,
    {
      userId:
        invite.captain_id,

      type:
        "clan_invite_rejected",

      title:
        "Invitación rechazada",

      message:
        `${user.username} ha rechazado la invitación a ${invite.clan_name}.`,

      clanId:
        invite.clan_id,

      relatedId:
        Number(inviteId),

      targetType:
        "clan",

      targetId:
        invite.clan_id
    }
  );


  return json({
    ok:true,

    message:
      "Invitación rechazada."
  });

}


/* =====================================================
   FIN WORKER PARTE 2/4
===================================================== */
/* =====================================================
   NOTIFICACIONES
===================================================== */

async function handleNotifications(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const result =
    await env.DB.prepare(`
      SELECT
        id,
        user_id,
        type,
        title,
        message,
        challenge_id,
        clan_id,
        is_read,
        created_at,
        related_id,
        target_type,
        target_id
      FROM notifications
      WHERE user_id = ?
      ORDER BY
        id DESC
      LIMIT 100
    `)
    .bind(
      Number(user.id)
    )
    .all();


  return json(
    {
      notifications:
        result.results || []
    }
  );

}


async function handleMarkNotificationRead(
  request,
  env,
  notificationId
){

  const user =
    await requireUser(
      request,
      env
    );


  await env.DB.prepare(`
    UPDATE notifications
    SET is_read = 1
    WHERE id = ?
      AND user_id = ?
  `)
  .bind(
    Number(notificationId),
    Number(user.id)
  )
  .run();


  return json({
    ok:true
  });

}


async function handleMarkAllNotificationsRead(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  await env.DB.prepare(`
    UPDATE notifications
    SET is_read = 1
    WHERE user_id = ?
  `)
  .bind(
    Number(user.id)
  )
  .run();


  return json({
    ok:true
  });

}


async function handleDeleteNotification(
  request,
  env,
  notificationId
){

  const user =
    await requireUser(
      request,
      env
    );


  await env.DB.prepare(`
    DELETE FROM notifications
    WHERE id = ?
      AND user_id = ?
  `)
  .bind(
    Number(notificationId),
    Number(user.id)
  )
  .run();


  return json({
    ok:true
  });

}


async function handleDeleteAllNotifications(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  await env.DB.prepare(`
    DELETE FROM notifications
    WHERE user_id = ?
  `)
  .bind(
    Number(user.id)
  )
  .run();


  return json({
    ok:true
  });

}


/* =====================================================
   RETOS
===================================================== */

async function handleChallenges(
  request,
  env
){

  const url =
    new URL(
      request.url
    );


  const leagueParam =
    url.searchParams.get(
      "league"
    );


  const league =
    normalizeLeague(
      leagueParam ||
      4
    );


  if(!league){

    return errorResponse(
      "Sector no válido."
    );

  }


  const result =
    await env.DB.prepare(`
      SELECT
        c.*,

        creator.name
          AS creator_clan_name,

        accepter.name
          AS accepter_clan_name

      FROM challenges c

      LEFT JOIN clans creator
        ON creator.id =
           c.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id =
           c.accepter_clan_id

      WHERE
        COALESCE(
          c.league,
          c.team_size,
          4
        ) = ?

      ORDER BY
        c.id DESC
    `)
    .bind(
      league
    )
    .all();


  return json(
    {
      challenges:
        result.results || []
    }
  );

}


async function handleCreateChallenge(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const body =
    await bodyJson(
      request
    );


  const league =
    normalizeLeague(
      body.league ||
      body.team_size
    );


  if(!league){

    return errorResponse(
      "Sector no válido."
    );

  }


  const mode =
    normalizeMode(
      body.mode ||
      body.game_mode ||
      body.one_vs_one_mode,
      league
    );


  if(!mode){

    return errorResponse(
      league === 1
        ? "Selecciona Francotirador o Arma."
        : "Selecciona ByD, Tomar Bandera o Punto Caliente."
    );

  }


  const clan =
    await getUserClan(
      env,
      user.id,
      league
    );


  if(!clan){

    return errorResponse(
      `No perteneces a ningún clan de ${leagueName(league)}.`
    );

  }


  const maps =
    Array.isArray(
      body.maps
    )
      ? body.maps
      : [];


  const map1 =
    String(
      body.map1 ||
      maps[0] ||
      MAPS[0]
    );


  const map2 =
    String(
      body.map2 ||
      maps[1] ||
      MAPS[1]
    );


  const map3 =
    String(
      body.map3 ||
      maps[2] ||
      MAPS[2]
    );


  const result =
    await env.DB.prepare(`
      INSERT INTO challenges (
        creator_clan_id,
        status,
        map1,
        map2,
        map3,
        created_at,
        team_size,
        game_modes,
        league,
        one_vs_one_mode
      )
      VALUES (
        ?,
        'open',
        ?,
        ?,
        ?,
        CURRENT_TIMESTAMP,
        ?,
        ?,
        ?,
        ?
      )
    `)
    .bind(
      Number(clan.id),
      map1,
      map2,
      map3,
      league,
      mode,
      league,
      league === 1
        ? mode
        : null
    )
    .run();


  const challengeId =
    Number(
      result.meta?.last_row_id ||
      0
    );


  if(!challengeId){

    return errorResponse(
      "No se ha podido publicar el reto.",
      500
    );

  }


  /*
    Avisamos al resto de capitanes
    del mismo sector.
  */

  const captains =
    await env.DB.prepare(`
      SELECT DISTINCT
        c.captain_id AS user_id
      FROM clans c
      WHERE c.league = ?
        AND c.id != ?
        AND c.captain_id IS NOT NULL
    `)
    .bind(
      league,
      Number(clan.id)
    )
    .all();


  for(
    const captain of
    (
      captains.results || []
    )
  ){

    await createNotification(
      env,
      {
        userId:
          captain.user_id,

        type:
          "new_challenge",

        title:
          "Nuevo reto publicado",

        message:
          `${clan.name} ha publicado un reto ${leagueName(league)}.`,

        challengeId:
          challengeId,

        clanId:
          clan.id,

        relatedId:
          challengeId,

        targetType:
          "challenge",

        targetId:
          challengeId
      }
    );

  }


  return json(
    {
      ok:true,

      message:
        "Reto publicado.",

      challenge_id:
        challengeId
    },
    201
  );

}


async function handleAcceptChallenge(
  request,
  env,
  challengeId
){

  const user =
    await requireUser(
      request,
      env
    );


  const challenge =
    await env.DB.prepare(`
      SELECT
        c.*,

        creator.name
          AS creator_clan_name,

        creator.league
          AS creator_league

      FROM challenges c

      JOIN clans creator
        ON creator.id =
           c.creator_clan_id

      WHERE c.id = ?

      LIMIT 1
    `)
    .bind(
      Number(challengeId)
    )
    .first();


  if(!challenge){

    return errorResponse(
      "Reto no encontrado.",
      404
    );

  }


  if(
    challenge.status !==
    "open"
  ){

    return errorResponse(
      "Este reto ya no está disponible."
    );

  }


  const league =
    normalizeLeague(
      challenge.league ||
      challenge.team_size
    );


  const clan =
    await getUserClan(
      env,
      user.id,
      league
    );


  if(!clan){

    return errorResponse(
      `No perteneces a ningún clan de ${leagueName(league)}.`
    );

  }


  if(
    Number(clan.id) ===
    Number(
      challenge.creator_clan_id
    )
  ){

    return errorResponse(
      "No puedes aceptar tu propio reto."
    );

  }


  await env.DB.prepare(`
    UPDATE challenges
    SET
      accepter_clan_id = ?,
      status = 'accepted'
    WHERE id = ?
      AND status = 'open'
  `)
  .bind(
    Number(clan.id),
    Number(challengeId)
  )
  .run();


  /*
    Avisamos al creador del reto.
  */

  const creatorClan =
    await getClan(
      env,
      challenge.creator_clan_id
    );


  if(
    creatorClan &&
    creatorClan.captain_id
  ){

    await createNotification(
      env,
      {
        userId:
          creatorClan.captain_id,

        type:
          "challenge_accepted",

        title:
          "Reto aceptado",

        message:
          `${clan.name} ha aceptado tu reto.`,

        challengeId:
          Number(challengeId),

        clanId:
          clan.id,

        relatedId:
          Number(challengeId),

        targetType:
          "challenge",

        targetId:
          Number(challengeId)
      }
    );

  }


  return json({
    ok:true,

    message:
      "Reto aceptado."
  });

}


async function handleMyChallenges(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const result =
    await env.DB.prepare(`
      SELECT
        c.*,

        creator.name
          AS creator_clan_name,

        accepter.name
          AS accepter_clan_name

      FROM challenges c

      JOIN clans creator
        ON creator.id =
           c.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id =
           c.accepter_clan_id

      WHERE
        c.creator_clan_id IN (
          SELECT clan_id
          FROM members
          WHERE user_id = ?
        )

        OR

        c.accepter_clan_id IN (
          SELECT clan_id
          FROM members
          WHERE user_id = ?
        )

      ORDER BY
        c.id DESC
    `)
    .bind(
      Number(user.id),
      Number(user.id)
    )
    .all();


  return json(
    {
      challenges:
        result.results || []
    }
  );

}


async function handleChallenge(
  request,
  env,
  challengeId
){

  const user =
    await requireUser(
      request,
      env
    );


  const challenge =
    await env.DB.prepare(`
      SELECT
        c.*,

        creator.name
          AS creator_clan_name,

        accepter.name
          AS accepter_clan_name

      FROM challenges c

      JOIN clans creator
        ON creator.id =
           c.creator_clan_id

      LEFT JOIN clans accepter
        ON accepter.id =
           c.accepter_clan_id

      WHERE c.id = ?

      LIMIT 1
    `)
    .bind(
      Number(challengeId)
    )
    .first();


  if(!challenge){

    return errorResponse(
      "Reto no encontrado.",
      404
    );

  }


  const creatorMember =
    await isClanMember(
      env,
      challenge.creator_clan_id,
      user.id
    );


  const accepterMember =
    challenge.accepter_clan_id
      ? await isClanMember(
          env,
          challenge.accepter_clan_id,
          user.id
        )
      : false;


  if(
    !creatorMember &&
    !accepterMember &&
    !Number(user.is_admin || 0)
  ){

    return errorResponse(
      "No tienes acceso a este reto.",
      403
    );

  }


  return json(
    challenge
  );

}


/* =====================================================
   COMUNIDAD
===================================================== */

async function handleCommunityGet(
  request,
  env
){

  const result =
    await env.DB.prepare(`
      SELECT
        cm.*,
        u.username
      FROM community_messages cm
      LEFT JOIN users u
        ON u.id = cm.user_id
      ORDER BY
        cm.id DESC
      LIMIT 100
    `)
    .all();


  return json(
    {
      messages:
        result.results || []
    }
  );

}


async function handleCommunityPost(
  request,
  env
){

  const user =
    await requireUser(
      request,
      env
    );


  const body =
    await bodyJson(
      request
    );


  const message =
    String(
      body.message ||
      body.content ||
      ""
    )
      .trim()
      .slice(0,500);


  if(!message){

    return errorResponse(
      "El mensaje está vacío."
    );

  }


  await env.DB.prepare(`
    INSERT INTO community_messages (
      user_id,
      message,
      created_at
    )
    VALUES (
      ?,
      ?,
      CURRENT_TIMESTAMP
    )
  `)
  .bind(
    Number(user.id),
    message
  )
  .run();


  return json(
    {
      ok:true
    },
    201
  );

}


/* =====================================================
   FIN WORKER PARTE 3/4
===================================================== */
/* =====================================================
   RANKING
===================================================== */

async function handleRanking(
  request,
  env
){

  const url =
    new URL(
      request.url
    );


  const league =
    normalizeLeague(
      url.searchParams.get(
        "league"
      ) ||
      4
    );


  if(!league){

    return errorResponse(
      "Liga no válida."
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
          SUM(
            CASE
              WHEN s.winner_clan_id = c.id
              THEN 3
              ELSE 0
            END
          ),
          0
        ) AS points,

        COALESCE(
          SUM(
            CASE
              WHEN s.winner_clan_id = c.id
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS wins

      FROM clans c

      LEFT JOIN scores s
        ON (
          s.winner_clan_id = c.id
          OR
          s.loser_clan_id = c.id
        )

      WHERE c.league = ?

      GROUP BY
        c.id,
        c.name,
        c.clan_code,
        c.league

      ORDER BY
        points DESC,
        wins DESC,
        c.name COLLATE NOCASE ASC
    `)
    .bind(
      league
    )
    .all();


  return json(
    {
      ranking:
        result.results || []
    }
  );

}


/* =====================================================
   ADMIN
===================================================== */

async function handleAdminUsers(
  request,
  env
){

  await requireAdmin(
    request,
    env
  );


  const result =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        psn_id,
        is_admin
      FROM users
      ORDER BY
        id DESC
      LIMIT 500
    `)
    .all();


  return json(
    {
      users:
        result.results || []
    }
  );

}


/* =====================================================
   BORRAR CUENTA — ADMIN
===================================================== */

async function handleAdminDeleteUser(
  request,
  env,
  userId
){

  await requireAdmin(
    request,
    env
  );


  const id =
    Number(userId);


  if(!id){

    return errorResponse(
      "ID de usuario no válido."
    );

  }


  /*
    Eliminamos primero las relaciones
    para evitar problemas de claves.
  */

  await env.DB.prepare(`
    DELETE FROM notifications
    WHERE user_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE user_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM invites
    WHERE user_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM members
    WHERE user_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM community_messages
    WHERE user_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM users
    WHERE id = ?
  `)
  .bind(id)
  .run();


  return json({
    ok:true,

    message:
      "Cuenta eliminada."
  });

}


/* =====================================================
   BORRAR CLAN — ADMIN
===================================================== */

async function handleAdminDeleteClan(
  request,
  env,
  clanId
){

  await requireAdmin(
    request,
    env
  );


  const id =
    Number(clanId);


  if(!id){

    return errorResponse(
      "ID de clan no válido."
    );

  }


  await env.DB.prepare(`
    DELETE FROM notifications
    WHERE clan_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM members
    WHERE clan_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM invites
    WHERE clan_id = ?
  `)
  .bind(id)
  .run();


  await env.DB.prepare(`
    DELETE FROM challenges
    WHERE creator_clan_id = ?
       OR accepter_clan_id = ?
  `)
  .bind(
    id,
    id
  )
  .run();


  await env.DB.prepare(`
    DELETE FROM clans
    WHERE id = ?
  `)
  .bind(id)
  .run();


  return json({
    ok:true,

    message:
      "Clan eliminado."
  });

}


/* =====================================================
   RUTA PRINCIPAL
===================================================== */

async function router(
  request,
  env
){

  const path =
    routePath(
      request
    );


  const httpMethod =
    method(
      request
    );


  /*
    AUTH
  */

  if(
    path === "/api/register" &&
    httpMethod === "POST"
  ){

    return handleRegister(
      request,
      env
    );

  }


  if(
    path === "/api/login" &&
    httpMethod === "POST"
  ){

    return handleLogin(
      request,
      env
    );

  }


  if(
    path === "/api/logout" &&
    httpMethod === "POST"
  ){

    return handleLogout(
      request,
      env
    );

  }


  if(
    path === "/api/me" &&
    httpMethod === "GET"
  ){

    return handleMe(
      request,
      env
    );

  }


  if(
    path === "/api/me" &&
    httpMethod === "PUT"
  ){

    return handleUpdateMe(
      request,
      env
    );

  }


  /*
    STATS
  */

  if(
    path === "/api/stats" &&
    httpMethod === "GET"
  ){

    return handleStats(
      request,
      env
    );

  }


  /*
    CLANES
  */

  if(
    path === "/api/clans" &&
    httpMethod === "GET"
  ){

    return handleClans(
      request,
      env
    );

  }


  if(
    path === "/api/clans" &&
    httpMethod === "POST"
  ){

    return handleCreateClan(
      request,
      env
    );

  }


  if(
    path === "/api/me/clans" &&
    httpMethod === "GET"
  ){

    return handleMyClans(
      request,
      env
    );

  }


  const clanMatch =
    path.match(
      /^\/api\/clans\/(\d+)$/
    );


  if(
    clanMatch &&
    httpMethod === "GET"
  ){

    return handleClan(
      request,
      env,
      clanMatch[1]
    );

  }


  /*
    INVITACIONES
  */

  if(
    path === "/api/invites" &&
    httpMethod === "GET"
  ){

    return handleInvites(
      request,
      env
    );

  }


  if(
    path === "/api/invites" &&
    httpMethod === "POST"
  ){

    return handleCreateInvite(
      request,
      env
    );

  }


  const inviteAcceptMatch =
    path.match(
      /^\/api\/invites\/(\d+)\/accept$/
    );


  if(
    inviteAcceptMatch &&
    httpMethod === "POST"
  ){

    return handleAcceptInvite(
      request,
      env,
      inviteAcceptMatch[1]
    );

  }


  const inviteRejectMatch =
    path.match(
      /^\/api\/invites\/(\d+)\/reject$/
    );


  if(
    inviteRejectMatch &&
    httpMethod === "POST"
  ){

    return handleRejectInvite(
      request,
      env,
      inviteRejectMatch[1]
    );

  }


  /*
    NOTIFICACIONES
  */

  if(
    path === "/api/notifications" &&
    httpMethod === "GET"
  ){

    return handleNotifications(
      request,
      env
    );

  }


  if(
    path === "/api/notifications" &&
    httpMethod === "DELETE"
  ){

    return handleDeleteAllNotifications(
      request,
      env
    );

  }


  const notificationReadMatch =
    path.match(
      /^\/api\/notifications\/(\d+)\/read$/
    );


  if(
    notificationReadMatch &&
    httpMethod === "POST"
  ){

    return handleMarkNotificationRead(
      request,
      env,
      notificationReadMatch[1]
    );

  }


  if(
    path === "/api/notifications/read-all" &&
    httpMethod === "POST"
  ){

    return handleMarkAllNotificationsRead(
      request,
      env
    );

  }


  const notificationDeleteMatch =
    path.match(
      /^\/api\/notifications\/(\d+)$/
    );


  if(
    notificationDeleteMatch &&
    httpMethod === "DELETE"
  ){

    return handleDeleteNotification(
      request,
      env,
      notificationDeleteMatch[1]
    );

  }


  /*
    RETOS
  */

  if(
    path === "/api/challenges" &&
    httpMethod === "GET"
  ){

    return handleChallenges(
      request,
      env
    );

  }


  if(
    path === "/api/challenges" &&
    httpMethod === "POST"
  ){

    return handleCreateChallenge(
      request,
      env
    );

  }


  if(
    path === "/api/my-challenges" &&
    httpMethod === "GET"
  ){

    return handleMyChallenges(
      request,
      env
    );

  }


  const challengeAcceptMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/accept$/
    );


  if(
    challengeAcceptMatch &&
    httpMethod === "POST"
  ){

    return handleAcceptChallenge(
      request,
      env,
      challengeAcceptMatch[1]
    );

  }


  const challengeMatch =
    path.match(
      /^\/api\/challenges\/(\d+)$/
    );


  if(
    challengeMatch &&
    httpMethod === "GET"
  ){

    return handleChallenge(
      request,
      env,
      challengeMatch[1]
    );

  }


  /*
    COMUNIDAD
  */

  if(
    path === "/api/community" &&
    httpMethod === "GET"
  ){

    return handleCommunityGet(
      request,
      env
    );

  }


  if(
    path === "/api/community" &&
    httpMethod === "POST"
  ){

    return handleCommunityPost(
      request,
      env
    );

  }


  /*
    RANKING
  */

  if(
    path === "/api/ranking" &&
    httpMethod === "GET"
  ){

    return handleRanking(
      request,
      env
    );

  }


  /*
    ADMIN
  */

  if(
    path === "/api/admin/users" &&
    httpMethod === "GET"
  ){

    return handleAdminUsers(
      request,
      env
    );

  }


  const adminDeleteUserMatch =
    path.match(
      /^\/api\/admin\/users\/(\d+)$/
    );


  if(
    adminDeleteUserMatch &&
    httpMethod === "DELETE"
  ){

    return handleAdminDeleteUser(
      request,
      env,
      adminDeleteUserMatch[1]
    );

  }


  const adminDeleteClanMatch =
    path.match(
      /^\/api\/admin\/clans\/(\d+)$/
    );


  if(
    adminDeleteClanMatch &&
    httpMethod === "DELETE"
  ){

    return handleAdminDeleteClan(
      request,
      env,
      adminDeleteClanMatch[1]
    );

  }


  /*
    Ruta inexistente
  */

  return errorResponse(
    "Ruta no encontrada.",
    404
  );

}


/* =====================================================
   CORS
===================================================== */

function withCors(
  response,
  request
){

  const origin =
    request.headers.get(
      "Origin"
    );


  const headers =
    new Headers(
      response.headers
    );


  /*
    Permitimos la propia web.
    Si accedes directamente desde
    el dominio, no afecta.
  */

  if(origin){

    headers.set(
      "Access-Control-Allow-Origin",
      origin
    );

    headers.set(
      "Access-Control-Allow-Credentials",
      "true"
    );

  }


  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );


  headers.set(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,DELETE,OPTIONS"
  );


  return new Response(
    response.body,
    {
      status:
        response.status,

      statusText:
        response.statusText,

      headers
    }
  );

}


/* =====================================================
   WORKER
===================================================== */

export default {

  async fetch(
    request,
    env,
    ctx
  ){

    try{

      if(
        request.method ===
        "OPTIONS"
      ){

        return withCors(
          new Response(
            null,
            {
              status:204
            }
          ),
          request
        );

      }


      const response =
        await router(
          request,
          env
        );


      return withCors(
        response,
        request
      );


    }catch(error){

      console.error(
        error
      );


      return withCors(
        errorResponse(
          error?.message ||
          "Error interno del servidor.",
          500
        ),
        request
      );

    }

  }

};
