const MAPS = [
  "Raid",
  "Standoff",
  "Slums",
  "Yemen",
  "Meltdown",
  "Express"
];

const GAME_MODES = [
  "snd",
  "hardpoint",
  "ctf"
];

const COOKIE = "bol_session";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      ...headers
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

async function readBody(request) {
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

  return (
    await passwordKey(password, parts[0])
  ) === parts[1];
}

/* =========================
   SESIONES
========================= */

async function getUser(request, env) {
  const token = getCookie(request, COOKIE);

  if (!token) {
    return null;
  }

  return await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND s.expires > ?
    `)
    .bind(token, Date.now())
    .first();
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
        m.role,
        m.joined_at
      FROM members m
      JOIN users u
        ON u.id = m.user_id
      WHERE m.clan_id = ?
      ORDER BY
        CASE
          WHEN m.role = 'captain' THEN 0
          ELSE 1
        END,
        m.joined_at ASC
    `)
    .bind(clanId)
    .all();

  return result.results;
}

async function isCaptain(env, userId, clanId) {
  const clan = await env.DB
    .prepare(`
      SELECT id
      FROM clans
      WHERE id = ?
        AND captain_id = ?
    `)
    .bind(clanId, userId)
    .first();

  return !!clan;
}

/* =========================
   NOTIFICACIONES
========================= */

async function createNotification(
  env,
  userId,
  type,
  title,
  message = "",
  challengeId = null,
  clanId = null
) {
  await env.DB
    .prepare(`
      INSERT INTO notifications
      (
        user_id,
        type,
        title,
        message,
        challenge_id,
        clan_id
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      userId,
      type,
      title,
      message,
      challengeId,
      clanId
    )
    .run();
}

/* =========================
   MAPAS
========================= */

function randomMaps() {
  const copy = [...MAPS];

  copy.sort(() => Math.random() - 0.5);

  return copy.slice(0, 3);
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
        cancelled_at IS NULL
        AND status IN ('open', 'accepted')
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

  const currentUser =
    await getUser(request, env);

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

    const data = await readBody(request);

    const username =
      String(data.username || "").trim();

    const password =
      String(data.password || "");

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

    const existing =
      await env.DB
        .prepare(`
          SELECT id
          FROM users
          WHERE username = ?
        `)
        .bind(username)
        .first();

    if (existing) {
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
        await hashPassword(password);

      const created =
        await env.DB
          .prepare(`
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

      await env.DB
        .prepare(`
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
        "REGISTER ERROR",
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

  /* =========================
     LOGIN
  ========================= */

  if (
    request.method === "POST" &&
    path === "/api/login"
  ) {

    const data =
      await readBody(request);

    const username =
      String(data.username || "").trim();

    const password =
      String(data.password || "");

    const user =
      await env.DB
        .prepare(`
          SELECT *
          FROM users
          WHERE username = ?
        `)
        .bind(username)
        .first();

    if (
      !user ||
      !(await verifyPassword(
        password,
        user.password_hash
      ))
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

    const token =
      crypto.randomUUID();

    await env.DB
      .prepare(`
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
        Date.now() + 604800000
      )
      .run();

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          username: user.username
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

  /* =========================
     LOGOUT
  ========================= */

  if (
    request.method === "POST" &&
    path === "/api/logout"
  ) {

    const token =
      getCookie(request, COOKIE);

    if (token) {
      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token = ?
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

  /* TODO LO DEMÁS REQUIERE LOGIN */

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
     NOTIFICACIONES
  ========================= */

  if (
    request.method === "GET" &&
    path === "/api/notifications"
  ) {

    const result =
      await env.DB
        .prepare(`
          SELECT *
          FROM notifications
          WHERE user_id = ?
          ORDER BY id DESC
          LIMIT 50
        `)
        .bind(currentUser.id)
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }

  if (
    request.method === "POST" &&
    path === "/api/notifications/read"
  ) {

    await env.DB
      .prepare(`
        UPDATE notifications
        SET is_read = 1
        WHERE user_id = ?
      `)
      .bind(currentUser.id)
      .run();

    return json(
      { ok: true },
      200,
      headers
    );
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
          members: []
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
        .prepare(`
          SELECT *
          FROM scores
          WHERE clan_id = ?
        `)
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
            "Ya perteneces a un clan."
        },
        400,
        headers
      );
    }

    const data =
      await readBody(request);

    const name =
      String(data.name || "").trim();

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

        env.DB
          .prepare(`
            INSERT INTO members
            (
              clan_id,
              user_id,
              joined_at,
              role
            )
            VALUES (?, ?, CURRENT_TIMESTAMP, 'captain')
          `)
          .bind(
            clanId,
            currentUser.id
          ),

        env.DB
          .prepare(`
            INSERT INTO scores
            (clan_id)
            VALUES (?)
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

      return json(
        {
          error:
            "No se pudo crear el clan.",
          detail:
            error?.message ||
            String(error)
        },
        500,
        headers
      );
    }
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

    if (!clan) {
      return json(
        {
          error:
            "No perteneces a ningún clan."
        },
        400,
        headers
      );
    }

    if (
      clan.captain_id !==
      currentUser.id
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

    if (members.length >= 6) {
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
      await readBody(request);

    const username =
      String(data.username || "").trim();

    if (!username) {
      return json(
        {
          error:
            "Indica el nombre del jugador."
        },
        400,
        headers
      );
    }

    const user =
      await env.DB
        .prepare(`
          SELECT id, username
          FROM users
          WHERE username = ?
        `)
        .bind(username)
        .first();

    if (!user) {
      return json(
        {
          error:
            "No existe ese jugador."
        },
        404,
        headers
      );
    }

    if (user.id === currentUser.id) {
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
      await env.DB
        .prepare(`
          SELECT 1
          FROM members
          WHERE user_id = ?
        `)
        .bind(user.id)
        .first();

    if (already) {
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

    const created =
      await env.DB
        .prepare(`
          INSERT INTO invites
          (
            clan_id,
            invitee_id,
            status
          )
          VALUES (?, ?, 'pending')
        `)
        .bind(
          clan.id,
          user.id
        )
        .run();

    await createNotification(
      env,
      user.id,
      "clan_invite",
      "Invitación a equipo",
      `${clan.name} te ha invitado a unirte a su equipo.`,
      null,
      clan.id
    );

    return json(
      {
        ok: true,
        invite_id:
          created.meta.last_row_id
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

    const result =
      await env.DB
        .prepare(`
          SELECT
            i.id,
            i.clan_id,
            i.status,
            i.created_at,
            c.name AS clan_name
          FROM invites i
          JOIN clans c
            ON c.id = i.clan_id
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

  const inviteMatch =
    path.match(
      /^\/api\/invites\/(\d+)\/(accept|reject)$/
    );

  if (
    request.method === "POST" &&
    inviteMatch
  ) {

    const inviteId =
      Number(inviteMatch[1]);

    const action =
      inviteMatch[2];

    const invite =
      await env.DB
        .prepare(`
          SELECT
            i.*,
            c.name AS clan_name
          FROM invites i
          JOIN clans c
            ON c.id = i.clan_id
          WHERE i.id = ?
            AND i.invitee_id = ?
            AND i.status = 'pending'
        `)
        .bind(
          inviteId,
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

    if (action === "reject") {

      await env.DB
        .prepare(`
          UPDATE invites
          SET status = 'rejected'
          WHERE id = ?
        `)
        .bind(inviteId)
        .run();

      const captain =
        await env.DB
          .prepare(`
            SELECT captain_id
            FROM clans
            WHERE id = ?
          `)
          .bind(invite.clan_id)
          .first();

      if (captain) {
        await createNotification(
          env,
          captain.captain_id,
          "invite_rejected",
          "Invitación rechazada",
          `${currentUser.username} ha rechazado la invitación.`,
          null,
          invite.clan_id
        );
      }

      return json(
        { ok: true },
        200,
        headers
      );
    }

    const existingClan =
      await getClan(
        env,
        currentUser.id
      );

    if (existingClan) {
      return json(
        {
          error:
            "Ya perteneces a un equipo."
        },
        400,
        headers
      );
    }

    const memberCount =
      await env.DB
        .prepare(`
          SELECT COUNT(*) AS total
          FROM members
          WHERE clan_id = ?
        `)
        .bind(invite.clan_id)
        .first();

    if (
      Number(memberCount.total) >= 6
    ) {
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

      env.DB
        .prepare(`
          INSERT INTO members
          (
            clan_id,
            user_id,
            joined_at,
            role
          )
          VALUES (?, ?, CURRENT_TIMESTAMP, 'player')
        `)
        .bind(
          invite.clan_id,
          currentUser.id
        ),

      env.DB
        .prepare(`
          UPDATE invites
          SET status = 'accepted'
          WHERE id = ?
        `)
        .bind(inviteId)

    ]);

    const captain =
      await env.DB
        .prepare(`
          SELECT captain_id
          FROM clans
          WHERE id = ?
        `)
        .bind(invite.clan_id)
        .first();

    if (captain) {
      await createNotification(
        env,
        captain.captain_id,
        "invite_accepted",
        "Jugador incorporado",
        `${currentUser.username} se ha unido a ${invite.clan_name}.`,
        null,
        invite.clan_id
      );
    }

    return json(
      { ok: true },
      200,
      headers
    );
  }

  /* =========================
     RANKING
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

    if (!clan) {
      return json(
        {
          error:
            "Necesitas pertenecer a un equipo."
        },
        400,
        headers
      );
    }

    if (
      clan.captain_id !==
      currentUser.id
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

    const data =
      await readBody(request);

    const teamSize =
      Number(data.team_size || 4);

    if (
      ![2, 3, 4].includes(teamSize)
    ) {
      return json(
        {
          error:
            "El formato debe ser 2v2, 3v3 o 4v4."
        },
        400,
        headers
      );
    }

    let modes = data.game_modes;

    if (!Array.isArray(modes)) {
      modes = ["snd"];
    }

    modes =
      modes.filter(
        mode =>
          GAME_MODES.includes(mode)
      );

    if (modes.length === 0) {
      return json(
        {
          error:
            "Selecciona al menos un modo de juego."
        },
        400,
        headers
      );
    }

    const scheduledAt =
      data.scheduled_at
        ? String(data.scheduled_at)
        : null;

    if (scheduledAt) {

      const parsed =
        new Date(scheduledAt);

      if (
        Number.isNaN(parsed.getTime())
      ) {
        return json(
          {
            error:
              "La fecha del reto no es válida."
          },
          400,
          headers
        );
      }
    }

    const maps =
      randomMaps();

    try {

      const created =
        await env.DB
          .prepare(`
            INSERT INTO challenges
            (
              creator_clan_id,
              accepter_clan_id,
              status,
              map1,
              map2,
              map3,
              scheduled_at,
              team_size,
              game_modes
            )
            VALUES (?, NULL, 'open', ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            clan.id,
            maps[0],
            maps[1],
            maps[2],
            scheduledAt,
            teamSize,
            JSON.stringify(modes)
          )
          .run();

      return json(
        {
          ok: true,
          id:
            created.meta.last_row_id,
          team_size:
            teamSize,
          game_modes:
            modes,
          maps
        },
        200,
        headers
      );

    } catch (error) {

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
            ch.cancelled_at IS NULL
            AND (
              ch.status = 'open'
              OR ch.creator_clan_id = ?
              OR ch.accepter_clan_id = ?
            )
          ORDER BY ch.id DESC
        `)
        .bind(
          clanId,
          clanId
        )
        .all();

    const challenges =
      result.results.map(challenge => {

        let modes = [];

        try {
          modes =
            JSON.parse(
              challenge.game_modes || '["snd"]'
            );
        } catch {
          modes = ["snd"];
        }

        return {
          ...challenge,
          team_size:
            challenge.team_size || 4,
          game_modes:
            modes,
          maps: [
            challenge.map1,
            challenge.map2,
            challenge.map3
          ],
          mine:
            challenge.creator_clan_id === clanId ||
            challenge.accepter_clan_id === clanId
        };
      });

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

    const challengeId =
      Number(acceptMatch[1]);

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (!clan) {
      return json(
        {
          error:
            "Necesitas pertenecer a un equipo."
        },
        400,
        headers
      );
    }

    if (
      clan.captain_id !==
      currentUser.id
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
            AND cancelled_at IS NULL
        `)
        .bind(challengeId)
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

    if (
      challenge.creator_clan_id ===
      clan.id
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

    const creatorBusy =
      await hasActiveChallenge(
        env,
        challenge.creator_clan_id
      );

    if (creatorBusy) {
      return json(
        {
          error:
            "El equipo que publicó el reto ya tiene otro reto activo."
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
        challengeId
      )
      .run();

    const creator =
      await env.DB
        .prepare(`
          SELECT captain_id, name
          FROM clans
          WHERE id = ?
        `)
        .bind(
          challenge.creator_clan_id
        )
        .first();

    if (creator) {

      await createNotification(
        env,
        creator.captain_id,
        "challenge_accepted",
        "Reto aceptado",
        `${clan.name} ha aceptado tu reto.`,
        challengeId,
        clan.id
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

    const challengeId =
      Number(cancelMatch[1]);

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (!clan) {
      return json(
        {
          error:
            "No perteneces a ningún equipo."
        },
        400,
        headers
      );
    }

    if (
      clan.captain_id !==
      currentUser.id
    ) {
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
      await env.DB
        .prepare(`
          SELECT *
          FROM challenges
          WHERE id = ?
            AND status IN ('open', 'accepted')
            AND cancelled_at IS NULL
            AND (
              creator_clan_id = ?
              OR accepter_clan_id = ?
            )
        `)
        .bind(
          challengeId,
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

    const data =
      await readBody(request);

    const reason =
      String(
        data.reason ||
        "Reto cancelado."
      ).slice(0, 250);

    await env.DB
      .prepare(`
        UPDATE challenges
        SET
          status = 'cancelled',
          cancelled_at = CURRENT_TIMESTAMP,
          cancel_reason = ?
        WHERE id = ?
      `)
      .bind(
        reason,
        challengeId
      )
      .run();

    const otherClan =
      challenge.creator_clan_id === clan.id
        ? challenge.accepter_clan_id
        : challenge.creator_clan_id;

    if (otherClan) {

      const other =
        await env.DB
          .prepare(`
            SELECT captain_id
            FROM clans
            WHERE id = ?
          `)
          .bind(otherClan)
          .first();

      if (other) {

        await createNotification(
          env,
          other.captain_id,
          "challenge_cancelled",
          "Reto cancelado",
          `${clan.name} ha cancelado el reto.`,
          challengeId,
          clan.id
        );
      }
    }

    return json(
      {
        ok: true
      },
      200,
      headers
    );
  }

  /* =========================
     CHAT
  ========================= */

  const chatMatch =
    path.match(
      /^\/api\/challenges\/(\d+)\/chat$/
    );

  if (
    chatMatch &&
    request.method === "GET"
  ) {

    const challengeId =
      Number(chatMatch[1]);

    const challenge =
      await env.DB
        .prepare(`
          SELECT *
          FROM challenges
          WHERE id = ?
        `)
        .bind(challengeId)
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
      await getClan(
        env,
        currentUser.id
      );

    if (
      !clan ||
      (
        clan.id !== challenge.creator_clan_id &&
        clan.id !== challenge.accepter_clan_id
      )
    ) {
      return json(
        {
          error:
            "No tienes acceso a este chat."
        },
        403,
        headers
      );
    }

    const result =
      await env.DB
        .prepare(`
          SELECT
            m.id,
            m.message,
            m.created_at,
            u.username
          FROM chat_messages m
          JOIN users u
            ON u.id = m.user_id
          WHERE m.challenge_id = ?
          ORDER BY m.id ASC
          LIMIT 200
        `)
        .bind(challengeId)
        .all();

    return json(
      result.results,
      200,
      headers
    );
  }

  if (
    chatMatch &&
    request.method === "POST"
  ) {

    const challengeId =
      Number(chatMatch[1]);

    const data =
      await readBody(request);

    const message =
      String(
        data.message || ""
      ).trim();

    if (!message) {
      return json(
        {
          error:
            "Escribe un mensaje."
        },
        400,
        headers
      );
    }

    if (message.length > 1000) {
      return json(
        {
          error:
            "El mensaje es demasiado largo."
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
        `)
        .bind(challengeId)
        .first();

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (
      !challenge ||
      !clan ||
      (
        clan.id !== challenge.creator_clan_id &&
        clan.id !== challenge.accepter_clan_id
      )
    ) {
      return json(
        {
          error:
            "No tienes acceso a este chat."
        },
        403,
        headers
      );
    }

    await env.DB
      .prepare(`
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

    return json(
      {
        ok: true
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

    const challengeId =
      Number(reportMatch[1]);

    const data =
      await readBody(request);

    const winner =
      Number(data.winner_clan_id);

    const clan =
      await getClan(
        env,
        currentUser.id
      );

    if (!clan) {
      return json(
        {
          error:
            "No perteneces a ningún equipo."
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
            AND status = 'accepted'
            AND cancelled_at IS NULL
        `)
        .bind(challengeId)
        .first();

    if (!challenge) {
      return json(
        {
          error:
            "El reto no está disponible para reportar."
        },
        404,
        headers
      );
    }

    if (
      clan.id !== challenge.creator_clan_id &&
      clan.id !== challenge.accepter_clan_id
    ) {
      return json(
        {
          error:
            "No perteneces a este enfrentamiento."
        },
        403,
        headers
      );
    }

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
        challengeId,
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
        .bind(challengeId)
        .all();

    if (
      reports.results.length >= 2
    ) {

      const first =
        reports.results[0];

      const sameWinner =
        reports.results.every(
          r =>
            Number(r.winner_clan_id) ===
            Number(first.winner_clan_id)
        );

      if (sameWinner) {

        const winnerClan =
          Number(first.winner_clan_id);

        const loserClan =
          winnerClan ===
          challenge.creator_clan_id
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
              winnerClan,
              challengeId
            ),

          env.DB
            .prepare(`
              UPDATE scores
              SET
                points = MAX(0, points + 10),
                wins = wins + 1,
                played = played + 1
              WHERE clan_id = ?
            `)
            .bind(winnerClan),

          env.DB
            .prepare(`
              UPDATE scores
              SET
                points = MAX(0, points - 5),
                losses = losses + 1,
                played = played + 1
              WHERE clan_id = ?
            `)
            .bind(loserClan)

        ]);

        const winnerInfo =
          await env.DB
            .prepare(`
              SELECT captain_id, name
              FROM clans
              WHERE id = ?
            `)
            .bind(winnerClan)
            .first();

        const loserInfo =
          await env.DB
            .prepare(`
              SELECT captain_id, name
              FROM clans
              WHERE id = ?
            `)
            .bind(loserClan)
            .first();

        if (winnerInfo) {
          await createNotification(
            env,
            winnerInfo.captain_id,
            "match_completed",
            "Victoria confirmada 🏆",
            "El resultado del reto ha sido confirmado. +10 XP.",
            challengeId,
            winnerClan
          );
        }

        if (loserInfo) {
          await createNotification(
            env,
            loserInfo.captain_id,
            "match_completed",
            "Resultado confirmado",
            "El resultado del reto ha sido confirmado. -5 XP.",
            challengeId,
            loserClan
          );
        }

        return json(
          {
            ok: true,
            completed: true
          },
          200,
          headers
        );
      }
    }

    return json(
      {
        ok: true,
        completed: false,
        message:
          "Resultado guardado. Falta la confirmación del otro capitán."
      },
      200,
      headers
    );
  }

  /* =========================
     404
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
   FETCH PRINCIPAL
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
            "Content-Type":
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
