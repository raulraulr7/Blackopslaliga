const MAPS = ["Slums", "Standoff", "Yemen", "Express", "Raid", "Plaza"];
const COOKIE = "bol_session";

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
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
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
      iterations: 120000,
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

async function getUser(request, env) {
  const token = getCookie(request, COOKIE);

  if (!token) {
    return null;
  }

  const result = await env.DB
    .prepare(`
      SELECT u.id, u.username
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ?
      AND s.expires > ?
    `)
    .bind(token, Date.now())
    .first();

  return result || null;
}

async function getClan(env, userId) {
  return await env.DB
    .prepare(`
      SELECT c.*
      FROM clans c
      JOIN members m ON m.clan_id = c.id
      WHERE m.user_id = ?
    `)
    .bind(userId)
    .first();
}

function randomMaps() {
  return [...MAPS]
    .sort(() => Math.random() - 0.5)
    .slice(0, 3);
}

async function api(request, env, path) {

  const headers = corsHeaders(request);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers
    });
  }

  const currentUser = await getUser(request, env);

  /*
   * ME
   */
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

  /*
   * REGISTER
   */
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
        .bind(username, passwordHash)
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

  /*
   * LOGIN
   */
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

  /*
   * LOGOUT
   */
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

  /*
   * TODO LO DEMÁS REQUIERE LOGIN
   */
  if (!currentUser) {
    return json(
      {
        error: "Debes iniciar sesión."
      },
      401,
      headers
    );
  }

  /*
   * INVITACIONES
   */
  if (
    request.method === "GET" &&
    path === "/api/invites"
  ) {

    const result = await env.DB
      .prepare(`
        SELECT
          i.id,
          c.name AS clan
        FROM invites i
        JOIN clans c
          ON c.id = i.clan_id
        WHERE i.invitee_id = ?
        AND i.status = 'pending'
      `)
      .bind(currentUser.id)
      .all();

    return json(
      result.results,
      200,
      headers
    );
  }

  /*
   * CREAR CLAN
   */
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

    const data = await body(request);

    const name = String(
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

      const created = await env.DB
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
            (clan_id, user_id, joined_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
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
          ok: true
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

  /*
   * MI CLAN
   */
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
          clan: null
        },
        200,
        headers
      );
    }

    const members =
      await env.DB
        .prepare(`
          SELECT
            u.id,
            u.username,
            CASE
              WHEN u.id = ? THEN 1
              ELSE 0
            END AS captain
          FROM users u
          JOIN members m
            ON m.user_id = u.id
          WHERE m.clan_id = ?
        `)
        .bind(
          clan.captain_id,
          clan.id
        )
        .all();

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
        members: members.results,
        score
      },
      200,
      headers
    );
  }

  /*
   * LEADERBOARD
   */
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

  /*
   * CREAR RETO
   */
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

    const selectedMaps =
      randomMaps();

    const created =
      await env.DB
        .prepare(`
          INSERT INTO challenges
          (
            creator_clan_id,
            accepter_clan_id,
            map1,
            map2,
            map3
          )
          VALUES (?, NULL, ?, ?, ?)
        `)
        .bind(
          clan.id,
          ...selectedMaps
        )
        .run();

    return json(
      {
        ok: true,
        id: created.meta.last_row_id
      },
      200,
      headers
    );
  }

  /*
   * LISTAR RETOS
   */
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
            ch.status = 'open'
            OR ch.creator_clan_id = ?
            OR ch.accepter_clan_id = ?
          ORDER BY ch.id DESC
        `)
        .bind(
          clanId,
          clanId
        )
        .all();

    const challenges =
      result.results.map(
        challenge => ({
          ...challenge,
          maps:
            challenge.status === "open"
              ? []
              : [
                  challenge.map1,
                  challenge.map2,
                  challenge.map3
                ],
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

  /*
   * ACEPTAR RETO
   */
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

    await env.DB
      .prepare(`
        UPDATE challenges
        SET
          accepter_clan_id = ?,
          status = 'accepted'
        WHERE id = ?
      `)
      .bind(
        clan.id,
        challenge.id
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

  /*
   * REPORTAR RESULTADO
   */
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
      Number(data.winner_clan_id);

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
        .bind(challenge.id)
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
              points = points + 20,
              wins = wins + 1,
              played = played + 1
            WHERE clan_id = ?
          `)
          .bind(winner),

        env.DB
          .prepare(`
            UPDATE scores
            SET
              points = points + 5,
              losses = losses + 1,
              played = played + 1
            WHERE clan_id = ?
          `)
          .bind(loser)
      ]);

      return json(
        {
          ok: true,
          completed: true
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

  return json(
    {
      error: "No encontrado."
    },
    404,
    headers
  );
}

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
            error?.message || String(error)
        },
        500,
        corsHeaders(request)
      );
    }
  }
};
