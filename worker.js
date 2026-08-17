const MAPS = ["Raid", "Standoff", "Meltdown", "Express"];
const COOKIE = "bol_session";
const MAX_PLAYERS = 6;
const MAX_STARTERS = 4;
const MAX_RESERVES = 2;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      ...extraHeaders
    }
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin");

  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true"
  };

  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return headers;
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  const match = cookies.match(
    new RegExp("(^|;\\s*)" + name + "=([^;]+)")
  );

  return match ? decodeURIComponent(match[2]) : null;
}

function sessionCookie(token) {
  return [
    `${COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "Max-Age=604800",
    "HttpOnly",
    "SameSite=Lax",
    "Secure"
  ].join("; ");
}

function deleteSessionCookie() {
  return [
    `${COOKIE}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "SameSite=Lax",
    "Secure"
  ].join("; ");
}


/* =========================
   CONTRASEÑAS
   ========================= */

async function passwordKey(password, salt) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),

      // Cloudflare Workers permite hasta 100000
      iterations: 100000,

      hash: "SHA-256"
    },
    key,
    256
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(bits))
  ).replaceAll("=", "");
}

async function hashPassword(password) {
  const salt = crypto.randomUUID();

  return salt + "." + await passwordKey(password, salt);
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(".")) {
    return false;
  }

  const parts = stored.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const hash = parts[1];

  return await passwordKey(password, salt) === hash;
}


/* =========================
   USUARIO
   ========================= */

async function getUser(request, env) {
  const token = getCookie(request, COOKIE);

  if (!token) {
    return null;
  }

  const result = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username,
        u.psn_id
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
      AND s.expires > ?
    `)
    .bind(token, Date.now())
    .first();

  return result || null;
}


/* =========================
   CLAN
   ========================= */

async function getClan(env, userId) {
  return await env.DB
    .prepare(`
      SELECT c.*
      FROM clans c
      JOIN members m
        ON m.clan_id = c.id
      WHERE m.user_id = ?
    `)
    .bind(userId)
    .first();
}

async function getClanMembers(env, clanId) {
  const result = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username,
        u.psn_id,
        COALESCE(m.role, 'titular') AS role,
        m.joined_at
      FROM members m
      JOIN users u
        ON u.id = m.user_id
      WHERE m.clan_id = ?
      ORDER BY
        CASE
          WHEN COALESCE(m.role, 'titular') = 'titular'
          THEN 0
          ELSE 1
        END,
        m.joined_at ASC
    `)
    .bind(clanId)
    .all();

  return result.results;
}


/* =========================
   MAPAS
   ========================= */

function randomMaps() {
  return [...MAPS]
    .sort(() => Math.random() - 0.5)
    .slice(0, 3);
}


/* =========================
   RETOS ACTIVOS
   ========================= */

async function hasActiveChallenge(env, clanId) {
  const result = await env.DB
    .prepare(`
      SELECT id
      FROM challenges
      WHERE
        status IN ('open', 'accepted')
        AND (
          creator_clan_id = ?
          OR accepter_clan_id = ?
        )
      LIMIT 1
    `)
    .bind(clanId, clanId)
    .first();

  return !!result;
}


/* =========================
   API
   ========================= */

async function api(request, env, path) {

  const headers = corsHeaders(request);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers
    });
  }

  let currentUser = null;

  try {
    currentUser = await getUser(request, env);
  } catch (error) {
    console.error("SESSION ERROR:", error);
  }


  /* =========================
     ME
     ========================= */

  if (
    request.method === "GET" &&
    path === "/api/me"
  ) {
    return json(
      {
        user: currentUser,
        clan: currentUser
          ? await getClan(env, currentUser.id)
          : null
      },
      200,
      headers
    );
  }


  /* =========================
     REGISTRO
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/register"
  ) {

    const data = await body(request);

    const username = String(
      data.username || ""
    ).trim();

    const password = String(
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

    if (password.length < 6) {
      return json(
        {
          error:
            "La contraseña debe tener al menos 6 caracteres."
        },
        400,
        headers
      );
    }

    const existing = await env.DB
      .prepare(
        "SELECT id FROM users WHERE username = ?"
      )
      .bind(username)
      .first();

    if (existing) {
      return json(
        {
          error: "Ese usuario ya existe."
        },
        400,
        headers
      );
    }

    try {

      const passwordHash =
        await hashPassword(password);

      const created = await env.DB
        .prepare(`
          INSERT INTO users
          (username, password_hash)
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

      await env.DB
        .prepare(`
          INSERT INTO sessions
          (token, user_id, expires)
          VALUES (?, ?, ?)
        `)
        .bind(
          token,
          userId,
          Date.now() + 604800000
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
            sessionCookie(token)
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
            error?.message || String(error)
        },
        500,
        headers
      );
    }
  }


  /* =========================
     LOGIN
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data = await body(request);

    const username = String(
      data.username || ""
    ).trim();

    const password = String(
      data.password || ""
    );

    const user = await env.DB
      .prepare(
        "SELECT * FROM users WHERE username = ?"
      )
      .bind(username)
      .first();

    if (!user) {
      return json(
        {
          error:
            "Usuario o contraseña incorrectos."
        },
        401,
        headers
      );
    }

    try {

      const valid =
        await verifyPassword(
          password,
          user.password_hash
        );

      if (!valid) {
        return json(
          {
            error:
              "Usuario o contraseña incorrectos."
          },
          401,
          headers
        );
      }

    } catch (error) {

      console.error(
        "LOGIN PASSWORD ERROR:",
        error
      );

      return json(
        {
          error:
            "No se pudo verificar la contraseña.",
          detail:
            error?.message || String(error)
        },
        500,
        headers
      );
    }

    const token =
      crypto.randomUUID();

    await env.DB
      .prepare(`
        INSERT INTO sessions
        (token, user_id, expires)
        VALUES (?, ?, ?)
      `)
      .bind(
        token,
        user.id,
        Date.now() + 604800000
      )
      .run();

    return json(
      {
        ok: true
      },
      200,
      {
        ...headers,
        "Set-Cookie":
          sessionCookie(token)
      }
    );
  }


  /* =========================
     LOGOUT
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/logout"
  ) {

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


  /* =========================
     TODO LO DEMÁS REQUIERE LOGIN
     ========================= */

  if (!currentUser) {
    return json(
      {
        error:
          "Debes iniciar sesión."
      },
      401,
      headers
    );
  }


  /* =========================
     GUARDAR ID PSN
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/profile/psn"
  ) {

    const data = await body(request);

    const psn = String(
      data.psn_id || ""
    ).trim();

    if (
      psn.length < 3 ||
      psn.length > 32
    ) {
      return json(
        {
          error:
            "El ID de PSN debe tener entre 3 y 32 caracteres."
        },
        400,
        headers
      );
    }

    const existing = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE LOWER(psn_id) = LOWER(?)
        AND id != ?
      `)
      .bind(
        psn,
        currentUser.id
      )
      .first();

    if (existing) {
      return json(
        {
          error:
            "Ese ID de PSN ya está registrado."
        },
        400,
        headers
      );
    }

    await env.DB
      .prepare(`
        UPDATE users
        SET psn_id = ?
        WHERE id = ?
      `)
      .bind(
        psn,
        currentUser.id
      )
      .run();

    return json(
      {
        ok: true,
        psn_id: psn
      },
      200,
      headers
    );
  }


  /* =========================
     INVITACIONES
     ========================= */

  if (
    request.method === "GET" &&
    path === "/api/invites"
  ) {

    const result = await env.DB
      .prepare(`
        SELECT
          i.id,
          i.clan_id,
          c.name AS clan,
          u.username AS inviter
        FROM invites i
        JOIN clans c
          ON c.id = i.clan_id
        JOIN users u
          ON u.id = i.inviter_id
        WHERE i.invitee_id = ?
        AND i.status = 'pending'
        ORDER BY i.id DESC
      `)
      .bind(currentUser.id)
      .all();

    return json(
      result.results,
      200,
      headers
    );
  }


  /* =========================
     INVITAR JUGADOR
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/clan/invite"
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
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

    const members =
      await getClanMembers(
        env,
        clan.id
      );

    if (members.length >= MAX_PLAYERS) {
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

    if (!username) {
      return json(
        {
          error:
            "Introduce el nombre del jugador."
        },
        400,
        headers
      );
    }

    const player =
      await env.DB
        .prepare(`
          SELECT id, username
          FROM users
          WHERE username = ?
        `)
        .bind(username)
        .first();

    if (!player) {
      return json(
        {
          error:
            "Jugador no encontrado."
        },
        404,
        headers
      );
    }

    if (player.id === currentUser.id) {
      return json(
        {
          error:
            "No puedes invitarte a ti mismo."
        },
        400,
        headers
      );
    }

    const playerClan =
      await getClan(
        env,
        player.id
      );

    if (playerClan) {
      return json(
        {
          error:
            "Ese jugador ya pertenece a un equipo."
        },
        400,
        headers
      );
    }

    const pending =
      await env.DB
        .prepare(`
          SELECT id
          FROM invites
          WHERE clan_id = ?
          AND invitee_id = ?
          AND status = 'pending'
        `)
        .bind(
          clan.id,
          player.id
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

    await env.DB
      .prepare(`
        INSERT INTO invites
        (clan_id, inviter_id, invitee_id, status)
        VALUES (?, ?, ?, 'pending')
      `)
      .bind(
        clan.id,
        currentUser.id,
        player.id
      )
      .run();

    return json(
      {
        ok: true,
        message:
          "Invitación enviada."
      },
      200,
      headers
    );
  }


  /* =========================
     ACEPTAR INVITACIÓN
     ========================= */

  const acceptInvite =
    path.match(
      /^\/api\/invites\/(\d+)\/accept$/
    );

  if (
    request.method === "POST" &&
    acceptInvite
  ) {

    const invite =
      await env.DB
        .prepare(`
          SELECT *
          FROM invites
          WHERE id = ?
          AND invitee_id = ?
          AND status = 'pending'
        `)
        .bind(
          acceptInvite[1],
          currentUser.id
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

    if (
      await getClan(
        env,
        currentUser.id
      )
    ) {
      return json(
        {
          error:
            "Ya perteneces a un equipo."
        },
        400,
        headers
      );
    }

    const members =
      await getClanMembers(
        env,
        invite.clan_id
      );

    if (members.length >= MAX_PLAYERS) {
      return json(
        {
          error:
            "El equipo ya tiene 6 jugadores."
        },
        400,
        headers
      );
    }

    const role =
      members.length < MAX_STARTERS
        ? "titular"
        : "reserva";

    await env.DB.batch([

      env.DB
        .prepare(`
          INSERT INTO members
          (clan_id, user_id, joined_at, role)
          VALUES (?, ?, CURRENT_TIMESTAMP, ?)
        `)
        .bind(
          invite.clan_id,
          currentUser.id,
          role
        ),

      env.DB
        .prepare(`
          UPDATE invites
          SET status = 'accepted'
          WHERE id = ?
        `)
        .bind(invite.id)

    ]);

    return json(
      {
        ok: true,
        role
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

    if (
      await getClan(
        env,
        currentUser.id
      )
    ) {
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

    if (
      name.length < 2 ||
      name.length > 24
    ) {
      return json(
        {
          error:
            "Nombre de clan: 2-24 caracteres."
        },
        400,
        headers
      );
    }

    try {

      const created =
        await env.DB
          .prepare(`
            INSERT INTO clans
            (name, captain_id)
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

        env.DB
          .prepare(`
            INSERT INTO members
            (clan_id, user_id, joined_at, role)
            VALUES (?, ?, CURRENT_TIMESTAMP, 'titular')
          `)
          .bind(
            clanId,
            currentUser.id
          ),

        env.DB
          .prepare(`
            INSERT INTO scores
            (clan_id, points, wins, losses, played)
            VALUES (?, 0, 0, 0, 0)
          `)
          .bind(clanId)

      ]);

      return json(
        {
          ok: true,
          clan_id: clanId
        },
        200,
        headers
      );

    } catch (error) {

      console.error(
        "CLAN ERROR:",
        error
      );

      return json(
        {
          error:
            "No se pudo crear el clan.",
          detail:
            error?.message || String(error)
        },
        500,
        headers
      );
    }
  }


  /* =========================
     MI CLAN
     ========================= */

  if (
    request.method === "GET" &&
    path === "/api/clan"
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (!clan) {
      return json(
        {
          clan: null,
          members: [],
          score: null
        },
        200,
        headers
      );
    }

    const members =
      await getClanMembers(
        env,
        clan.id
      );

    const score =
      await env.DB
        .prepare(
          "SELECT * FROM scores WHERE clan_id = ?"
        )
        .bind(clan.id)
        .first();

    return json(
      {
        clan,
        members,
        score
      },
      200,
      headers
    );
  }


  /* =========================
     CAMBIAR ROL
     ========================= */

  const roleMatch =
    path.match(
      /^\/api\/clan\/members\/(\d+)\/role$/
    );

  if (
    request.method === "POST" &&
    roleMatch
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
    ) {
      return json(
        {
          error:
            "Solo el capitán puede cambiar roles."
        },
        403,
        headers
      );
    }

    const data =
      await body(request);

    const role =
      data.role === "reserva"
        ? "reserva"
        : "titular";

    const member =
      await env.DB
        .prepare(`
          SELECT *
          FROM members
          WHERE clan_id = ?
          AND user_id = ?
        `)
        .bind(
          clan.id,
          roleMatch[1]
        )
        .first();

    if (!member) {
      return json(
        {
          error:
            "Jugador no encontrado en el equipo."
        },
        404,
        headers
      );
    }

    if (role === "titular") {

      const count =
        await env.DB
          .prepare(`
            SELECT COUNT(*) AS total
            FROM members
            WHERE clan_id = ?
            AND role = 'titular'
          `)
          .bind(clan.id)
          .first();

      if (Number(count.total) >= MAX_STARTERS) {
        return json(
          {
            error:
              "Ya hay 4 titulares."
          },
          400,
          headers
        );
      }
    }

    await env.DB
      .prepare(`
        UPDATE members
        SET role = ?
        WHERE clan_id = ?
        AND user_id = ?
      `)
      .bind(
        role,
        clan.id,
        roleMatch[1]
      )
      .run();

    return json(
      {
        ok: true,
        role
      },
      200,
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

    const result =
      await env.DB
        .prepare(`
          SELECT
            c.id,
            c.name,
            COALESCE(s.points, 0) AS points,
            COALESCE(s.wins, 0) AS wins,
            COALESCE(s.losses, 0) AS losses,
            COALESCE(s.played, 0) AS played
          FROM clans c
          LEFT JOIN scores s
            ON s.clan_id = c.id
          ORDER BY
            points DESC,
            wins DESC
        `)
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }


  /* =========================
     CREAR RETO
     ========================= */

  if (
    request.method === "POST" &&
    path === "/api/challenges"
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
    ) {
      return json(
        {
          error:
            "Solo el capitán puede crear retos."
        },
        403,
        headers
      );
    }

    if (
      await hasActiveChallenge(
        env,
        clan.id
      )
    ) {
      return json(
        {
          error:
            "Tu equipo ya tiene un reto activo. Cancélalo o termínalo antes de crear otro."
        },
        400,
        headers
      );
    }

    const members =
      await getClanMembers(
        env,
        clan.id
      );

    const starters =
      members.filter(
        m => m.role === "titular"
      );

    if (starters.length < MAX_STARTERS) {
      return json(
        {
          error:
            "Necesitas tener 4 titulares para publicar un reto."
        },
        400,
        headers
      );
    }

    const data =
      await body(request);

    const scheduledAt =
      String(
        data.scheduled_at || ""
      ).trim();

    if (!scheduledAt) {
      return json(
        {
          error:
            "Debes indicar el día y la hora del reto."
        },
        400,
        headers
      );
    }

    const date =
      new Date(scheduledAt);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return json(
        {
          error:
            "La fecha y hora no son válidas."
        },
        400,
        headers
      );
    }

    if (
      date.getTime() <= Date.now()
    ) {
      return json(
        {
          error:
            "El reto debe programarse para una fecha futura."
        },
        400,
        headers
      );
    }

    const selectedMaps =
      randomMaps();

    try {

      const created =
        await env.DB
          .prepare(`
            INSERT INTO challenges
            (
              creator_clan_id,
              accepter_clan_id,
              map1,
              map2,
              map3,
              scheduled_at,
              status
            )
            VALUES (?, NULL, ?, ?, ?, ?, 'open')
          `)
          .bind(
            clan.id,
            ...selectedMaps,
            scheduledAt
          )
          .run();

      return json(
        {
          ok: true,
          id: created.meta.last_row_id,
          scheduled_at: scheduledAt
        },
        200,
        headers
      );

    } catch (error) {

      console.error(
        "CHALLENGE CREATE ERROR:",
        error
      );

      return json(
        {
          error:
            "No se pudo crear el reto.",
          detail:
            error?.message || String(error)
        },
        500,
        headers
      );
    }
  }


  /* =========================
     LISTAR RETOS
     ========================= */

  if (
    request.method === "GET" &&
    path === "/api/challenges"
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    const clanId =
      clan?.id || -1;

    const result =
      await env.DB
        .prepare(`
          SELECT
            ch.*,
            a.name AS creator_name,
            b.name AS accepter_name
          FROM challenges ch
          JOIN clans a
            ON a.id = ch.creator_clan_id
          LEFT JOIN clans b
            ON b.id = ch.accepter_clan_id
          WHERE
            ch.status IN ('open', 'accepted')
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
        challenge => ({

          id: challenge.id,

          status: challenge.status,

          scheduled_at:
            challenge.scheduled_at,

          creator_name:
            challenge.creator_clan_id === clanId
              ? challenge.creator_name
              : null,

          accepter_name:
            challenge.accepter_clan_id === clanId
              ? challenge.accepter_name
              : null,

          maps:
            challenge.status === "accepted"
              ? [
                  challenge.map1,
                  challenge.map2,
                  challenge.map3
                ]
              : [],

          mine:
            challenge.creator_clan_id === clanId ||
            challenge.accepter_clan_id === clanId
        })
      );

    return json(
      challenges,
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

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
    ) {
      return json(
        {
          error:
            "Solo el capitán puede aceptar."
        },
        403,
        headers
      );
    }

    if (
      await hasActiveChallenge(
        env,
        clan.id
      )
    ) {
      return json(
        {
          error:
            "Tu equipo ya tiene un reto activo."
        },
        400,
        headers
      );
    }

    const challenge =
      await env.DB
        .prepare(`
          SELECT *
          FROM challenges
          WHERE id = ?
          AND status = 'open'
        `)
        .bind(
          acceptMatch[1]
        )
        .first();

    if (
      !challenge ||
      challenge.creator_clan_id === clan.id
    ) {
      return json(
        {
          error:
            "Reto no disponible."
        },
        400,
        headers
      );
    }

    const creatorActive =
      await hasActiveChallenge(
        env,
        challenge.creator_clan_id
      );

    if (!creatorActive) {
      return json(
        {
          error:
            "El reto ya no está disponible."
        },
        400,
        headers
      );
    }

    await env.DB
      .prepare(`
        UPDATE challenges
        SET
          accepter_clan_id = ?,
          status = 'accepted'
        WHERE id = ?
        AND status = 'open'
      `)
      .bind(
        clan.id,
        challenge.id
      )
      .run();

    return json(
      {
        ok: true,
        scheduled_at:
          challenge.scheduled_at,
        maps: [
          challenge.map1,
          challenge.map2,
          challenge.map3
        ]
      },
      200,
      headers
    );
  }


  /* =========================
     CANCELAR RETO
     ========================= */

  const cancelMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/cancel$/
    );

  if (
    request.method === "POST" &&
    cancelMatch
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
    ) {
      return json(
        {
          error:
            "Solo el capitán puede cancelar un reto."
        },
        403,
        headers
      );
    }

    const challenge =
      await env.DB
        .prepare(`
          SELECT *
          FROM challenges
          WHERE id = ?
          AND status IN ('open', 'accepted')
          AND (
            creator_clan_id = ?
            OR accepter_clan_id = ?
          )
        `)
        .bind(
          cancelMatch[1],
          clan.id,
          clan.id
        )
        .first();

    if (!challenge) {
      return json(
        {
          error:
            "No puedes cancelar este reto."
        },
        404,
        headers
      );
    }

    await env.DB
      .prepare(`
        UPDATE challenges
        SET
          status = 'cancelled',
          cancelled_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        challenge.id
      )
      .run();

    return json(
      {
        ok: true,
        message:
          "Reto cancelado correctamente."
      },
      200,
      headers
    );
  }


  /* =========================
     REPORTAR RESULTADO
     ========================= */

  const reportMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/report$/
    );

  if (
    request.method === "POST" &&
    reportMatch
  ) {

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      clan.captain_id !== currentUser.id
    ) {
      return json(
        {
          error:
            "Solo el capitán puede reportar."
        },
        403,
        headers
      );
    }

    const data =
      await body(request);

    const challenge =
      await env.DB
        .prepare(`
          SELECT *
          FROM challenges
          WHERE id = ?
          AND status = 'accepted'
        `)
        .bind(
          reportMatch[1]
        )
        .first();

    if (
      !challenge ||
      ![
        challenge.creator_clan_id,
        challenge.accepter_clan_id
      ].includes(clan.id)
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

    const winner =
      Number(
        data.winner_clan_id
      );

    if (
      winner !== challenge.creator_clan_id &&
      winner !== challenge.accepter_clan_id
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

    await env.DB
      .prepare(`
        INSERT OR REPLACE INTO reports
        (
          challenge_id,
          clan_id,
          winner_clan_id
        )
        VALUES (?, ?, ?)
      `)
      .bind(
        challenge.id,
        clan.id,
        winner
      )
      .run();

    const reports =
      await env.DB
        .prepare(`
          SELECT *
          FROM reports
          WHERE challenge_id = ?
        `)
        .bind(
          challenge.id
        )
        .all();

    const results =
      reports.results;

    if (
      results.length === 2 &&
      results[0].winner_clan_id ===
      results[1].winner_clan_id
    ) {

      const loser =
        winner === challenge.creator_clan_id
          ? challenge.accepter_clan_id
          : challenge.creator_clan_id;

      await env.DB.batch([

        env.DB
          .prepare(`
            UPDATE challenges
            SET
              status = 'completed',
              winner_clan_id = ?,
              completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `)
          .bind(
            winner,
            challenge.id
          ),

        env.DB
          .prepare(`
            UPDATE scores
            SET
              points =
                CASE
                  WHEN points + 10 < 0
                  THEN 0
                  ELSE points + 10
                END,
              wins = wins + 1,
              played = played + 1
            WHERE clan_id = ?
          `)
          .bind(winner),

        env.DB
          .prepare(`
            UPDATE scores
            SET
              points =
                CASE
                  WHEN points - 5 < 0
                  THEN 0
                  ELSE points - 5
                END,
              losses = losses + 1,
              played = played + 1
            WHERE clan_id = ?
          `)
          .bind(loser)

      ]);

      return json(
        {
          ok: true,
          completed: true,
          winner_clan_id: winner
        },
        200,
        headers
      );
    }

    return json(
      {
        ok: true,
        message:
          "Resultado enviado; falta confirmar al otro capitán."
      },
      200,
      headers
    );
  }


  /* =========================
     NO ENCONTRADO
     ========================= */

  return json(
    {
      error:
        "No encontrado."
    },
    404,
    headers
  );
}


/* =========================
   WORKER
   ========================= */

export default {

  async fetch(request, env) {

    try {

      const url =
        new URL(request.url);

      if (
        url.pathname.startsWith("/api/")
      ) {
        return await api(
          request,
          env,
          url.pathname
        );
      }

      if (env.ASSETS) {
        return await env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "ASSETS no está configurado.",
        {
          status: 500,
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {

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
        corsHeaders(request)
      );
    }
  }
};
