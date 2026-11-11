// ============================================================
// RAPID ADS API — CLOUDFLARE WORKER
// Monetag Rewarded Interstitial + Rewarded Popup
// ============================================================

const CONFIG = {
  APP_NAME: "Rapid Ads",

  MONETAG_ZONE_ID: "12109194",

  // Rewarded Interstitial
  MONETAG_REWARD_UNITS: 50000,
  MONETAG_DAILY_LIMIT: 100,
  MONETAG_COOLDOWN_SECONDS: 60,
  MONETAG_RESERVATION_SECONDS: 120,

  // Rewarded Popup
  MONETAG_POPUP_REWARD_UNITS: 20000,
  MONETAG_POPUP_DAILY_LIMIT: 50,
  MONETAG_POPUP_COOLDOWN_SECONDS: 60,
  MONETAG_POPUP_REUSE_SECONDS: 900,
  MONETAG_POPUP_PREFIX: "rapop_",

  MONETAG_REWARD_CURRENCY: "USDT",
  REWARD_UNITS_PER_USDT: 100000000,

  FAUCETPAY_API_BASE: "https://faucetpay.io/api/v2",
  TELEGRAM_AUTH_MAX_AGE: 86400,

  PAYOUTS_ENABLED: true
};

// ============================================================
// MAIN WORKER
// ============================================================

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      if (path === "/health" && request.method === "GET") {
        return jsonResponse({
          ok: true,
          service: CONFIG.APP_NAME,
          status: "online",
          payouts_enabled: CONFIG.PAYOUTS_ENABLED,
          timestamp: new Date().toISOString()
        });
      }

      if (path === "/" && request.method === "GET") {
        return jsonResponse({
          ok: true,
          service: CONFIG.APP_NAME,
          message: "Rapid Ads API is running."
        });
      }

      if (path === "/faucetpay-email" && request.method === "POST") {
        return await handleFaucetPayEmail(request, env);
      }

      if (path === "/monetag-cooldown-start" && request.method === "POST") {
        return await handleMonetagCooldown(request, env);
      }

      if (path === "/monetag-register" && request.method === "POST") {
        return await handleMonetagRegister(request, env);
      }

      if (path === "/monetag-popup-prepare" && request.method === "POST") {
        return await handleMonetagPopupPrepare(request, env);
      }

      if (path === "/monetag-postback" && request.method === "GET") {
        return await handleMonetagPostback(request, env);
      }

      if (path === "/payment-history" && request.method === "POST") {
        return await handlePaymentHistory(request, env);
      }

      if (path === "/payment-status" && request.method === "POST") {
        return await handlePaymentStatus(request, env);
      }

      return jsonResponse({
        ok: false,
        error: "Route not found."
      }, 404);

    } catch (error) {
      console.error("Worker error:", error);

      return jsonResponse({
        ok: false,
        error: "Internal server error."
      }, 500);
    }
  }
};

// ============================================================
// RESPONSE HELPERS
// ============================================================

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json"
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders()
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function unixTime() {
  return Math.floor(Date.now() / 1000);
}

function utcDayStart() {
  return Math.floor(unixTime() / 86400) * 86400;
}

function utcDateKey() {
  return new Date().toISOString().slice(0, 10);
}

function randomId(prefix = "ra") {
  return prefix + "_" + crypto.randomUUID();
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

// ============================================================
// CRYPTOGRAPHIC HELPERS
// ============================================================

async function hmacSha256(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(message)
  );

  return new Uint8Array(signature);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

// ============================================================
// TELEGRAM AUTHENTICATION
// ============================================================

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) {
    throw new Error("Telegram authentication data is missing.");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    throw new Error("Invalid Telegram authentication hash.");
  }

  params.delete("hash");

  const entries = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b));

  const dataCheckString = entries
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = await hmacSha256(
    new TextEncoder().encode("WebAppData"),
    botToken
  );

  const calculatedHash = bytesToHex(
    await hmacSha256(secretKey, dataCheckString)
  );

  if (!timingSafeEqual(
    calculatedHash.toLowerCase(),
    receivedHash.toLowerCase()
  )) {
    throw new Error("Telegram authentication failed.");
  }

  const authDate = Number(params.get("auth_date"));
  const now = unixTime();

  if (
    !Number.isFinite(authDate) ||
    authDate > now + 60 ||
    now - authDate > CONFIG.TELEGRAM_AUTH_MAX_AGE
  ) {
    throw new Error("Telegram session has expired. Reopen the Mini App.");
  }

  let user;

  try {
    user = JSON.parse(params.get("user") || "null");
  } catch {
    throw new Error("Invalid Telegram user information.");
  }

  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0) {
    throw new Error("Invalid Telegram user ID.");
  }

  return {
    id: String(user.id),
    first_name: String(user.first_name || ""),
    username: String(user.username || "")
  };
}

// ============================================================
// DATABASE AND AUTHENTICATED REQUESTS
// ============================================================

function getDatabase(env) {
  if (!env.RAPID_ADS_DB) {
    throw new Error("RAPID_ADS_DB database binding is missing.");
  }

  return env.RAPID_ADS_DB;
}

async function authenticateRequest(request, env) {
  const body = await readJson(request);

  if (!body || typeof body.initData !== "string") {
    throw new Error("Telegram initData is required.");
  }

  const user = await verifyTelegramInitData(
    body.initData,
    env.TELEGRAM_BOT_TOKEN
  );

  return { body, user };
}

function validFaucetPayEmail(email) {
  if (typeof email !== "string" || email.length > 254) {
    return false;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// ============================================================
// IP REGISTRATION PROTECTION
// ============================================================

async function getIpHash(request, env) {
  if (!env.IP_HASH_SECRET) {
    throw new Error("IP_HASH_SECRET is not configured.");
  }

  // Only trust Cloudflare's connection IP header.
  // Never use a client-supplied IP address.
  const ip = String(
    request.headers.get("CF-Connecting-IP") || ""
  ).trim().toLowerCase();

  if (!ip || ip.length > 100) {
    throw new Error("Unable to identify your connection IP.");
  }

  const hash = await hmacSha256(
    new TextEncoder().encode(env.IP_HASH_SECRET),
    ip
  );

  return bytesToHex(hash);
}

function isConstraintError(error) {
  return String(error?.message || "")
    .toLowerCase()
    .includes("constraint");
}

async function registerFaucetPayEmail(
  db,
  request,
  env,
  user,
  email
) {
  if (!validFaucetPayEmail(email)) {
    throw new Error("Enter a valid FaucetPay email address.");
  }

  const normalizedEmail = email.trim().toLowerCase();
  const now = unixTime();

  const existingUser = await getRegisteredUser(db, user.id);

  // Existing accounts can update their email.
  // They do not need to claim another IP address.
  if (existingUser) {
    await db.prepare(`
      UPDATE users
      SET faucetpay_email = ?,
          updated_at = ?
      WHERE telegram_id = ?
    `).bind(
      normalizedEmail,
      now,
      user.id
    ).run();

    return {
      registered: true,
      faucetpay_email: normalizedEmail,
      existing_account: true
    };
  }

  const ipHash = await getIpHash(request, env);

  try {
    // D1 batch executes these statements transactionally.
    // If the IP claim violates a UNIQUE constraint,
    // the user insertion is rolled back as well.
    const results = await db.batch([
      db.prepare(`
        INSERT INTO users (
          telegram_id,
          faucetpay_email,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        user.id,
        normalizedEmail,
        now,
        now
      ),

      db.prepare(`
        INSERT INTO ip_registrations (
          ip_hash,
          telegram_id,
          created_at
        )
        VALUES (?, ?, ?)
      `).bind(
        ipHash,
        user.id,
        now
      )
    ]);

    if (
      Number(results[0]?.meta?.changes || 0) !== 1 ||
      Number(results[1]?.meta?.changes || 0) !== 1
    ) {
      throw new Error("Registration could not be completed.");
    }

    return {
      registered: true,
      faucetpay_email: normalizedEmail,
      existing_account: false
    };

  } catch (error) {
    if (!isConstraintError(error)) {
      throw error;
    }

    // Check whether another account already owns this IP.
    const ipOwner = await db.prepare(`
      SELECT telegram_id
      FROM ip_registrations
      WHERE ip_hash = ?
    `).bind(ipHash).first();

    if (ipOwner && ipOwner.telegram_id !== user.id) {
      throw new Error(
        "Registration blocked: another Telegram account has already registered from this public IP address."
      );
    }

    // A concurrent registration for this same Telegram account
    // may have completed first.
    const currentUser = await getRegisteredUser(db, user.id);

    if (currentUser) {
      await db.prepare(`
        UPDATE users
        SET faucetpay_email = ?,
            updated_at = ?
        WHERE telegram_id = ?
      `).bind(
        normalizedEmail,
        now,
        user.id
      ).run();

      return {
        registered: true,
        faucetpay_email: normalizedEmail,
        existing_account: true
      };
    }

    throw new Error("Registration failed. Please try again.");
  }
}

async function getRegisteredUser(db, telegramId) {
  return await db.prepare(`
    SELECT telegram_id, faucetpay_email, created_at
    FROM users
    WHERE telegram_id = ?
  `).bind(telegramId).first();
}

async function hasUnresolvedPayment(db, telegramId) {
  return await db.prepare(`
    SELECT p.id
    FROM payments p
    INNER JOIN monetag_sessions ms
      ON ms.id = p.session_id
    WHERE ms.telegram_id = ?
      AND p.status IN ('PROCESSING', 'UNKNOWN')
    LIMIT 1
  `).bind(telegramId).first();
}

// ============================================================
// FAUCETPAY EMAIL REGISTRATION
// ============================================================

async function handleFaucetPayEmail(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const result = await registerFaucetPayEmail(
      db,
      request,
      env,
      user,
      body.faucetpay_email
    );

    return jsonResponse({
      ok: true,
      ...result
    });

  } catch (error) {
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
}

// ============================================================
// MONETAG DAILY COUNTS
// ============================================================

async function getMonetagDailyCount(db, telegramId) {
  const daily = await db.prepare(`
    SELECT COUNT(*) AS total
    FROM monetag_sessions
    WHERE telegram_id = ?
      AND date(created_at, 'unixepoch') = ?
      AND ymid NOT LIKE 'rapop_%'
  `).bind(
    telegramId,
    utcDateKey()
  ).first();

  return Number(daily?.total || 0);
}

async function getPopupDailyCount(db, telegramId) {
  const daily = await db.prepare(`
    SELECT COUNT(*) AS total
    FROM monetag_sessions
    WHERE telegram_id = ?
      AND ymid LIKE 'rapop_%'
      AND verified_at IS NOT NULL
      AND date(verified_at, 'unixepoch') = ?
  `).bind(
    telegramId,
    utcDateKey()
  ).first();

  return Number(daily?.total || 0);
}

// ============================================================
// MONETAG INTERSTITIAL COOLDOWN
// ============================================================

async function getMonetagCooldown(db, telegramId) {
  const latest = await db.prepare(`
    SELECT finished_at
    FROM monetag_cooldowns
    WHERE telegram_id = ?
  `).bind(telegramId).first();

  if (!latest) {
    return 0;
  }

  return Math.max(
    0,
    CONFIG.MONETAG_COOLDOWN_SECONDS -
      (unixTime() - Number(latest.finished_at))
  );
}

async function ensureMonetagCooldown(db, session) {
  const now = unixTime();

  await db.prepare(`
    INSERT INTO monetag_cooldowns (
      telegram_id,
      session_id,
      finished_at
    )
    VALUES (?, ?, ?)
    ON CONFLICT(telegram_id)
    DO UPDATE SET
      session_id = excluded.session_id,
      finished_at = excluded.finished_at
    WHERE (
      SELECT rowid
      FROM monetag_sessions
      WHERE id = excluded.session_id
    ) > (
      SELECT rowid
      FROM monetag_sessions
      WHERE id = monetag_cooldowns.session_id
    )
  `).bind(
    session.telegram_id,
    session.id,
    now
  ).run();
}

// ============================================================
// MONETAG POPUP COOLDOWN
// ============================================================

async function getMonetagPopupCooldown(db, telegramId) {
  const latest = await db.prepare(`
    SELECT finished_at
    FROM monetag_popup_cooldowns
    WHERE telegram_id = ?
  `).bind(telegramId).first();

  if (!latest) {
    return 0;
  }

  return Math.max(
    0,
    CONFIG.MONETAG_POPUP_COOLDOWN_SECONDS -
      (unixTime() - Number(latest.finished_at))
  );
}

// ============================================================
// MONETAG INTERSTITIAL COOLDOWN ACTIONS
// ============================================================

async function handleMonetagCooldown(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const action = String(body.action || "check_cooldown");
    const now = unixTime();

    if (action === "cancel_watch") {
      const token = String(body.reservation_token || "");

      if (!token) {
        throw new Error("Reservation token is required.");
      }

      const result = await db.prepare(`
        DELETE FROM monetag_reservations
        WHERE telegram_id = ?
          AND reservation_token = ?
          AND NOT EXISTS (
            SELECT 1
            FROM monetag_sessions
            WHERE monetag_sessions.telegram_id = ?
              AND monetag_sessions.reservation_token = ?
          )
      `).bind(user.id, token, user.id, token).run();

      return jsonResponse({
        ok: true,
        cancelled: Number(result.meta?.changes || 0) > 0
      });
    }

    if (action === "finish_watch") {
      const token = String(body.reservation_token || "");
      const ymid = String(body.ymid || "");

      if (!token || !ymid) {
        throw new Error("Reservation token and session ID are required.");
      }

      const session = await db.prepare(`
        SELECT id, status, reservation_token
        FROM monetag_sessions
        WHERE telegram_id = ?
          AND ymid = ?
          AND ymid NOT LIKE 'rapop_%'
      `).bind(user.id, ymid).first();

      if (!session) {
        throw new Error("Monetag session not found.");
      }

      if (session.reservation_token !== token) {
        throw new Error("Reservation token does not match this session.");
      }

      await db.prepare(`
        INSERT INTO monetag_cooldowns (
          telegram_id,
          session_id,
          finished_at
        )
        VALUES (?, ?, ?)
        ON CONFLICT(telegram_id)
        DO UPDATE SET
          session_id = excluded.session_id,
          finished_at = excluded.finished_at
        WHERE
          monetag_cooldowns.session_id = excluded.session_id
          OR (
            SELECT rowid
            FROM monetag_sessions
            WHERE id = excluded.session_id
          ) > (
            SELECT rowid
            FROM monetag_sessions
            WHERE id = monetag_cooldowns.session_id
          )
      `).bind(user.id, session.id, now).run();

      const cooldown = await db.prepare(`
        SELECT session_id, finished_at
        FROM monetag_cooldowns
        WHERE telegram_id = ?
      `).bind(user.id).first();

      if (!cooldown) {
        throw new Error("Unable to record Monetag cooldown.");
      }

      await db.prepare(`
        DELETE FROM monetag_reservations
        WHERE telegram_id = ?
          AND reservation_token = ?
      `).bind(user.id, token).run();

      const remaining = Math.max(
        0,
        CONFIG.MONETAG_COOLDOWN_SECONDS -
          (now - Number(cooldown.finished_at))
      );

      return jsonResponse({
        ok: true,
        cooldown_started: true,
        cooldown_seconds: CONFIG.MONETAG_COOLDOWN_SECONDS,
        remaining_seconds: remaining,
        attempt_recorded: true,
        reward_credited: false,
        reward_eligible_for_review:
          cooldown.session_id === session.id &&
          session.status === "VERIFIED"
      });
    }

    if (action !== "check_cooldown" && action !== "reserve_watch") {
      throw new Error("Unsupported Monetag action.");
    }

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      return jsonResponse({
        ok: false,
        registered: false,
        can_watch: false,
        error: "Register your FaucetPay email before watching ads."
      }, 403);
    }

    if (await hasUnresolvedPayment(db, user.id)) {
      return jsonResponse({
        ok: false,
        can_watch: false,
        error: "You have an unresolved payment. Please wait for reconciliation before starting another ad session."
      }, 409);
    }

    const remaining = await getMonetagCooldown(db, user.id);
    const dailyCount = await getMonetagDailyCount(db, user.id);
    const dailyRemaining = Math.max(
      0,
      CONFIG.MONETAG_DAILY_LIMIT - dailyCount
    );

    if (action === "check_cooldown") {
      return jsonResponse({
        ok: true,
        can_watch: remaining === 0 && dailyRemaining > 0,
        remaining_seconds: remaining,
        daily_count: dailyCount,
        daily_remaining: dailyRemaining
      });
    }

    if (remaining > 0) {
      return jsonResponse({
        ok: true,
        can_watch: false,
        remaining_seconds: remaining
      });
    }

    if (dailyRemaining <= 0) {
      return jsonResponse({
        ok: false,
        can_watch: false,
        error: "Daily Monetag limit reached."
      }, 429);
    }

    const existingReservation = await db.prepare(`
      SELECT reservation_token, expires_at
      FROM monetag_reservations
      WHERE telegram_id = ?
    `).bind(user.id).first();

    if (
      existingReservation &&
      Number(existingReservation.expires_at) >= now
    ) {
      const existingSession = await db.prepare(`
        SELECT id
        FROM monetag_sessions
        WHERE telegram_id = ?
          AND reservation_token = ?
        LIMIT 1
      `).bind(user.id, existingReservation.reservation_token).first();

      if (!existingSession) {
        return jsonResponse({
          ok: true,
          can_watch: true,
          reservation_token: existingReservation.reservation_token,
          remaining_seconds: 0,
          reservation_reused: true
        });
      }

      return jsonResponse({
        ok: false,
        can_watch: false,
        error: "An advertisement session is already registered. Please wait for it to finish."
      }, 409);
    }

    await db.prepare(`
      DELETE FROM monetag_reservations
      WHERE telegram_id = ?
        AND expires_at < ?
    `).bind(user.id, now).run();

    const token = randomId("reservation");

    try {
      await db.prepare(`
        INSERT INTO monetag_reservations (
          telegram_id,
          reservation_token,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        user.id,
        token,
        now + CONFIG.MONETAG_RESERVATION_SECONDS,
        now
      ).run();

    } catch (error) {
      if (isConstraintError(error)) {
        return jsonResponse({
          ok: false,
          can_watch: false,
          error: "A watch reservation is already active."
        }, 409);
      }

      throw error;
    }

    return jsonResponse({
      ok: true,
      can_watch: true,
      reservation_token: token,
      remaining_seconds: 0
    });

  } catch (error) {
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
}

// ============================================================
// MONETAG REWARDED INTERSTITIAL REGISTRATION
// ============================================================

async function handleMonetagRegister(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const ymid = String(body.ymid || "");
    const reservationToken = String(body.reservation_token || "");

    if (
      !/^[a-zA-Z0-9_-]{1,150}$/.test(ymid) ||
      ymid.startsWith(CONFIG.MONETAG_POPUP_PREFIX)
    ) {
      throw new Error("Invalid Monetag session ID.");
    }

    if (!reservationToken) {
      throw new Error("Reservation token is required.");
    }

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      throw new Error("Register your FaucetPay email first.");
    }

    if (await hasUnresolvedPayment(db, user.id)) {
      throw new Error("You have an unresolved payment. Please wait for reconciliation.");
    }

    const now = unixTime();
    const id = randomId("monetag");
    const dayStart = utcDayStart();
    const dayEnd = dayStart + 86400;

    const results = await db.batch([
      db.prepare(`
        INSERT INTO monetag_sessions (
          id,
          telegram_id,
          ymid,
          status,
          reward_units,
          created_at,
          reservation_token,
          faucetpay_email
        )
        SELECT
          ?, ?, ?, 'PENDING', ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM monetag_reservations
          WHERE telegram_id = ?
            AND reservation_token = ?
            AND expires_at >= ?
        )
        AND NOT EXISTS (
          SELECT 1
          FROM monetag_sessions
          WHERE ymid = ?
        )
        AND NOT EXISTS (
          SELECT 1
          FROM payments p
          INNER JOIN monetag_sessions ms ON ms.id = p.session_id
          WHERE ms.telegram_id = ?
            AND p.status IN ('PROCESSING', 'UNKNOWN')
        )
        AND (
          SELECT COUNT(*)
FROM monetag_sessions
WHERE telegram_id = ?
  AND ymid LIKE 'rapop_%'
  AND verified_at IS NOT NULL
  AND date(verified_at, 'unixepoch') = ?
        ) < ?
      `).bind(
        id,
        user.id,
        ymid,
        CONFIG.MONETAG_REWARD_UNITS,
        now,
        reservationToken,
        registeredUser.faucetpay_email,
        user.id,
        reservationToken,
        now,
        ymid,
        user.id,
        user.id,
utcDateKey(),
CONFIG.MONETAG_POPUP_DAILY_LIMIT
      ),

      db.prepare(`
        DELETE FROM monetag_reservations
        WHERE telegram_id = ?
          AND reservation_token = ?
          AND EXISTS (
            SELECT 1
            FROM monetag_sessions
            WHERE id = ?
              AND telegram_id = ?
              AND ymid = ?
              AND reservation_token = ?
          )
      `).bind(
        user.id,
        reservationToken,
        id,
        user.id,
        ymid,
        reservationToken
      )
    ]);

    if (Number(results[0]?.meta?.changes || 0) !== 1) {
      throw new Error(
        "Registration failed. Your reservation may have expired, already been used, or your daily limit may have been reached."
      );
    }

    return jsonResponse({
      ok: true,
      registered: true,
      ymid,
      session_id: id
    });

  } catch (error) {
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
}

// ============================================================
// MONETAG REWARDED POPUP PREPARATION
// ============================================================

async function handleMonetagPopupPrepare(request, env) {
  try {
    const { user } = await authenticateRequest(request, env);
    const db = getDatabase(env);
    const now = unixTime();

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      return jsonResponse({
        ok: false,
        registered: false,
        error: "Register your FaucetPay email before opening ads."
      }, 403);
    }

    if (await hasUnresolvedPayment(db, user.id)) {
      return jsonResponse({
        ok: false,
        error: "You have an unresolved payment. Please wait for reconciliation."
      }, 409);
    }

    // Reuse a recent pending session.
    const existing = await db.prepare(`
      SELECT ymid, created_at
      FROM monetag_sessions
      WHERE telegram_id = ?
        AND ymid LIKE 'rapop_%'
        AND status = 'PENDING'
        AND created_at >= ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(
      user.id,
      now - CONFIG.MONETAG_POPUP_REUSE_SECONDS
    ).first();

    const dailyCount = await getPopupDailyCount(db, user.id);
    const dailyRemaining = Math.max(
      0,
      CONFIG.MONETAG_POPUP_DAILY_LIMIT - dailyCount
    );

    if (existing) {
      return jsonResponse({
        ok: true,
        prepared: true,
        reused: true,
        ymid: existing.ymid,
        daily_count: dailyCount,
        daily_remaining: dailyRemaining,
        cooldown_seconds: CONFIG.MONETAG_POPUP_COOLDOWN_SECONDS
      });
    }

    const remaining = await getMonetagPopupCooldown(db, user.id);

    if (remaining > 0) {
  return jsonResponse({
    ok: false,
    can_watch: false,
    remaining_seconds: remaining,
    daily_count: dailyCount,
    daily_remaining: dailyRemaining,
    error: "Rewarded Popup is on cooldown."
  }, 429);
}

    if (dailyRemaining <= 0) {
      return jsonResponse({
        ok: false,
        limit_reached: true,
        daily_count: dailyCount,
        daily_remaining: 0,
        error: "Daily Rewarded Popup limit reached."
      }, 429);
    }

    const ymid = CONFIG.MONETAG_POPUP_PREFIX + crypto.randomUUID();
    const id = randomId("popup");
    const dayStart = utcDayStart();
    const dayEnd = dayStart + 86400;

    // Session and cooldown are written together.
    // The cooldown starts at preparation time.
    const results = await db.batch([
      db.prepare(`
        INSERT INTO monetag_sessions (
          id,
          telegram_id,
          ymid,
          status,
          reward_units,
          created_at,
          reservation_token,
          faucetpay_email
        )
        SELECT
          ?, ?, ?, 'PENDING', ?, ?, NULL, ?
        WHERE
          (
            SELECT COUNT(*)
            FROM monetag_sessions
            WHERE telegram_id = ?
              AND ymid LIKE 'rapop_%'
              AND created_at >= ?
              AND created_at < ?
          ) < ?
          AND NOT EXISTS (
            SELECT 1
            FROM payments p
            INNER JOIN monetag_sessions ms ON ms.id = p.session_id
            WHERE ms.telegram_id = ?
              AND p.status IN ('PROCESSING', 'UNKNOWN')
          )
          AND NOT EXISTS (
            SELECT 1
            FROM monetag_popup_cooldowns
            WHERE telegram_id = ?
              AND finished_at > ?
          )
      `).bind(
        id,
        user.id,
        ymid,
        CONFIG.MONETAG_POPUP_REWARD_UNITS,
        now,
        registeredUser.faucetpay_email,
        user.id,
        dayStart,
        dayEnd,
        CONFIG.MONETAG_POPUP_DAILY_LIMIT,
        user.id,
        user.id,
        now - CONFIG.MONETAG_POPUP_COOLDOWN_SECONDS
      ),

      db.prepare(`
        INSERT INTO monetag_popup_cooldowns (
          telegram_id,
          session_id,
          finished_at
        )
        SELECT ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM monetag_sessions
          WHERE id = ?
            AND telegram_id = ?
            AND ymid = ?
        )
        ON CONFLICT(telegram_id)
        DO UPDATE SET
          session_id = excluded.session_id,
          finished_at = excluded.finished_at
        WHERE (
          SELECT rowid
          FROM monetag_sessions
          WHERE id = excluded.session_id
        ) > (
          SELECT rowid
          FROM monetag_sessions
          WHERE id = monetag_popup_cooldowns.session_id
        )
      `).bind(
        user.id,
        id,
        now,
        id,
        user.id,
        ymid
      )
    ]);

    if (
      Number(results[0]?.meta?.changes || 0) !== 1 ||
      Number(results[1]?.meta?.changes || 0) !== 1
    ) {
      return jsonResponse({
        ok: false,
        error: "Unable to prepare Popup session. Please check your cooldown and daily limit."
      }, 409);
    }

    const updatedCount = await getPopupDailyCount(db, user.id);

    return jsonResponse({
      ok: true,
      prepared: true,
      reused: false,
      ymid,
      daily_count: updatedCount,
      daily_remaining: Math.max(
        0,
        CONFIG.MONETAG_POPUP_DAILY_LIMIT - updatedCount
      ),
      cooldown_seconds: CONFIG.MONETAG_POPUP_COOLDOWN_SECONDS
    });

  } catch (error) {
    console.error("Popup preparation error:", error);

    return jsonResponse({
      ok: false,
      error: error.message || "Unable to prepare Popup session."
    }, 400);
  }
}

// ============================================================
// MONETAG POSTBACK
// ============================================================

async function handleMonetagPostback(request, env) {
  try {
    if (!env.MONETAG_POSTBACK_SECRET) {
      throw new Error("Monetag postback secret is not configured.");
    }

    const params = new URL(request.url).searchParams;

    if (!timingSafeEqual(
      params.get("secret") || "",
      env.MONETAG_POSTBACK_SECRET
    )) {
      return jsonResponse({
        ok: false,
        error: "Unauthorized postback."
      }, 401);
    }

    const ymid = params.get("ymid") || "";
    const zone = params.get("zone_id") || "";
    const event = params.get("event_type") || "";
    const rewardType = params.get("reward_event_type") || "";
    const requestVar = params.get("request_var") || "";

    // Passive In-App Interstitials never pay rewards.
    if (requestVar === "auto") {
      return jsonResponse({
        ok: true,
        ignored: true,
        payout_status: "NOT_REWARD_ELIGIBLE"
      });
    }

    let placement;
    let expectedRewardUnits;

    if (requestVar === "rapid_ads_watch") {
      placement = "interstitial";
      expectedRewardUnits = CONFIG.MONETAG_REWARD_UNITS;
    } else if (requestVar === "12109194_rapid_ads_popup") {
      placement = "popup";
      expectedRewardUnits = CONFIG.MONETAG_POPUP_REWARD_UNITS;
    } else {
      return jsonResponse({
        ok: true,
        ignored: true,
        payout_status: "NOT_REWARD_ELIGIBLE",
        message: "Unrecognised Monetag placement."
      });
    }

    if (
      !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid) ||
      zone !== CONFIG.MONETAG_ZONE_ID
    ) {
      return jsonResponse({
        ok: false,
        error: "Invalid Monetag postback details."
      }, 400);
    }

    // Both Interstitial and Popup accept valued impressions or valued clicks.
// Each ymid can only be rewarded once.
const eligibleEvent =
  ["impression", "click"].includes(event) &&
  rewardType === "valued";
    if (!eligibleEvent) {
      return jsonResponse({
        ok: true,
        ignored: true,
        payout_status: "NOT_REWARD_ELIGIBLE",
        message: "Event is not reward eligible."
      });
    }

    if (
      placement === "popup" &&
      !ymid.startsWith(CONFIG.MONETAG_POPUP_PREFIX)
    ) {
      return jsonResponse({
        ok: false,
        error: "Popup session ID does not match placement."
      }, 400);
    }

    if (
      placement === "interstitial" &&
      ymid.startsWith(CONFIG.MONETAG_POPUP_PREFIX)
    ) {
      return jsonResponse({
        ok: false,
        error: "Interstitial session ID does not match placement."
      }, 400);
    }

    const db = getDatabase(env);

    const session = await db.prepare(`
      SELECT
        id,
        telegram_id,
        status,
        reward_units,
        faucetpay_email,
        ymid
      FROM monetag_sessions
      WHERE ymid = ?
    `).bind(ymid).first();

    if (!session) {
      return jsonResponse({
        ok: false,
        error: "Monetag session not found."
      }, 404);
    }

    if (CONFIG.PAYOUTS_ENABLED) {
      const allowedTelegramId = String(
        env.FAUCETPAY_TEST_TELEGRAM_ID || ""
      ).trim();

      if (
        !allowedTelegramId ||
        String(session.telegram_id) !== allowedTelegramId
      ) {
        return jsonResponse({
          ok: true,
          ignored: true,
          payout_status: "TEST_RESTRICTED",
          message: "This account is not authorised for the temporary payout test."
        });
      }
    }

    const rewardUnits = Number(session.reward_units);

    if (
      !Number.isSafeInteger(rewardUnits) ||
      rewardUnits !== expectedRewardUnits
    ) {
      throw new Error("Invalid reward amount for this placement.");
    }

    // Popup never creates an Interstitial cooldown.
    // Interstitial cooldown is started by finish_watch.
    if (placement === "interstitial") {
      await ensureMonetagCooldown(db, session);
    }

    if (session.status !== "PENDING") {
      return jsonResponse({
        ok: true,
        duplicate: true,
        status: session.status
      });
    }

    const now = unixTime();

    if (!CONFIG.PAYOUTS_ENABLED) {
      const update = await db.prepare(`
        UPDATE monetag_sessions
        SET status = 'VERIFIED',
            verified_at = ?
        WHERE id = ?
          AND status = 'PENDING'
      `).bind(now, session.id).run();

      return jsonResponse({
        ok: true,
        verified: Number(update.meta?.changes || 0) === 1,
        payout_status: "DISABLED"
      });
    }

    const paymentResult = await sendFaucetPayPayment(
      db,
      env,
      session
    );

    if (
      paymentResult.status === "PROCESSING" ||
      paymentResult.status === "DUPLICATE"
    ) {
      return jsonResponse({
        ok: true,
        duplicate: true,
        payout_status: paymentResult.status,
        message: "A payment attempt already exists. No second payment was sent."
      });
    }

    if (paymentResult.status === "PAID") {
      await db.prepare(`
        UPDATE monetag_sessions
        SET status = 'PAID',
            verified_at = COALESCE(verified_at, ?),
            paid_at = ?
        WHERE id = ?
          AND status = 'PENDING'
      `).bind(now, now, session.id).run();

      return jsonResponse({
        ok: true,
        verified: true,
        payout_status: "PAID",
        payout_id: paymentResult.payout_id || null
      });
    }

    if (paymentResult.status === "UNKNOWN") {

  await db.prepare(`
    UPDATE monetag_sessions
    SET status = 'UNKNOWN',
        verified_at = COALESCE(verified_at, ?)
    WHERE id = ?
      AND status = 'PENDING'
  `).bind(
    now,
    session.id
  ).run();

  return jsonResponse({
    ok: true,
    verified: true,
    payout_status: "UNKNOWN",
    message: "Payment outcome is uncertain. Reconciliation is required. No retry was attempted."
  }, 202);
  }

    if (paymentResult.status === "FAILED") {
      await db.prepare(`
        UPDATE monetag_sessions
        SET status = 'FAILED',
            verified_at = ?
        WHERE id = ?
          AND status = 'PENDING'
      `).bind(now, session.id).run();

      return jsonResponse({
        ok: true,
        verified: true,
        payout_status: "FAILED",
        message: "Payment failed. No retry will be attempted."
      });
    }

    return jsonResponse({
      ok: false,
      verified: true,
      payout_status: "UNKNOWN",
      error: "Unexpected payment status. No retry was attempted."
    }, 500);

  } catch (error) {
    console.error("Monetag postback error:", error);

    return jsonResponse({
      ok: false,
      error: "Postback processing failed."
    }, 400);
  }
}

// ============================================================
// PAYMENT HISTORY
// ============================================================

async function handlePaymentHistory(request, env) {
  try {
    const { user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const payments = await db.prepare(`
      SELECT
        id,
        amount_units,
        currency,
        status,
        faucetpay_reference,
        created_at,
        updated_at
      FROM payments
      WHERE telegram_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(user.id).all();

    return jsonResponse({
      ok: true,
      payments: payments.results || []
    });

  } catch (error) {
    console.error("Payment history error:", error);

    return jsonResponse({
      ok: false,
      error: "Unable to retrieve payment history."
    }, 400);
  }
}

// ============================================================
// PAYMENT STATUS
// ============================================================

async function handlePaymentStatus(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const ymid = String(body.ymid || "").trim();

    if (!ymid || ymid.length > 200) {
      return jsonResponse({
        ok: false,
        error: "Invalid ad session ID."
      }, 400);
    }

    const db = getDatabase(env);

    const payment = await db.prepare(`
      SELECT
        ms.ymid,
        ms.status AS session_status,
        p.amount_units,
        p.currency,
        p.status AS payment_status,
        p.faucetpay_reference
      FROM monetag_sessions ms
      LEFT JOIN payments p
        ON p.session_id = ms.id
      WHERE ms.ymid = ?
        AND ms.telegram_id = ?
      LIMIT 1
    `).bind(ymid, user.id).first();

    if (!payment) {
      return jsonResponse({
        ok: true,
        status: "NOT_FOUND",
        message: "Ad session not found."
      });
    }

    return jsonResponse({
      ok: true,
      status: payment.payment_status || payment.session_status || "WAITING",
      amount_units: payment.amount_units || null,
      currency: payment.currency || null,
      faucetpay_reference: payment.faucetpay_reference || null
    });

  } catch (error) {
    console.error("Payment status error:", error);

    return jsonResponse({
      ok: false,
      error: "Unable to check payment status."
    }, 400);
  }
}

// ============================================================
// FAUCETPAY PAYMENT
// ============================================================

async function sendFaucetPayPayment(db, env, session) {
  if (!CONFIG.PAYOUTS_ENABLED) {
    return {
      ok: false,
      status: "DISABLED"
    };
  }

  const email = String(session?.faucetpay_email || "")
    .trim()
    .toLowerCase();

  const rewardUnits = Number(session?.reward_units);

  if (
    !email ||
    !session?.id ||
    !session?.telegram_id ||
    !Number.isSafeInteger(rewardUnits) ||
    rewardUnits <= 0
  ) {
    return {
      ok: false,
      status: "FAILED",
      error: "Invalid payment details."
    };
  }

  const now = unixTime();
  const paymentId = randomId("payment");
  const idempotencyKey = `rapid-ads-${session.id}`;

  // Claim the session's single permitted payment attempt.
  const inserted = await db.prepare(`
    INSERT INTO payments (
      id,
      telegram_id,
      faucetpay_email,
      amount_units,
      currency,
      status,
      idempotency_key,
      session_id,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, 'PROCESSING', ?, ?, ?, ?)
    ON CONFLICT(session_id) WHERE session_id IS NOT NULL DO NOTHING
  `).bind(
    paymentId,
    session.telegram_id,
    email,
    rewardUnits,
    CONFIG.MONETAG_REWARD_CURRENCY,
    idempotencyKey,
    session.id,
    now,
    now
  ).run();

  if (Number(inserted.meta?.changes || 0) !== 1) {
    const existing = await db.prepare(`
      SELECT status, faucetpay_reference
      FROM payments
      WHERE session_id = ?
    `).bind(session.id).first();

    return {
      ok: existing?.status === "PAID",
      status: existing?.status || "DUPLICATE",
      payout_id: existing?.faucetpay_reference || null
    };
  }

  try {
    if (!env.FAUCETPAY_API_KEY) {
      await db.prepare(`
        UPDATE payments
        SET status = 'FAILED',
            updated_at = ?
        WHERE id = ?
          AND session_id = ?
          AND status = 'PROCESSING'
      `).bind(unixTime(), paymentId, session.id).run();

      return {
        ok: false,
        status: "FAILED",
        error: "FaucetPay API key is not configured."
      };
    }

    // Exactly one outbound payment request. Do not retry.
    const response = await fetch(
      `${CONFIG.FAUCETPAY_API_BASE}/send`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.FAUCETPAY_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          idempotency_key: idempotencyKey,
          to: email,
          amount: rewardUnits,
          currency: CONFIG.MONETAG_REWARD_CURRENCY
        }),
        signal: AbortSignal.timeout(15000)
      }
    );

    let result;

    try {
      result = await response.json();
    } catch {
      result = null;
    }

    if (
      response.ok &&
      result?.success === true &&
      result.data?.payout_id
    ) {
      const payoutId = String(result.data.payout_id);

      const update = await db.prepare(`
        UPDATE payments
        SET status = 'PAID',
            faucetpay_reference = ?,
            updated_at = ?
        WHERE id = ?
          AND session_id = ?
          AND status = 'PROCESSING'
      `).bind(
        payoutId,
        unixTime(),
        paymentId,
        session.id
      ).run();

      if (Number(update.meta?.changes || 0) !== 1) {
        throw new Error(
          "FaucetPay confirmed payment, but D1 did not record PAID."
        );
      }

      return {
        ok: true,
        status: "PAID",
        payout_id: payoutId
      };
    }

    await db.prepare(`
      UPDATE payments
      SET status = 'UNKNOWN',
          updated_at = ?
      WHERE id = ?
        AND session_id = ?
        AND status = 'PROCESSING'
    `).bind(
      unixTime(),
      paymentId,
      session.id
    ).run();

    return {
      ok: false,
      status: "UNKNOWN",
      error: "Payment outcome requires reconciliation."
    };

  } catch (error) {
    console.error("FaucetPay payment error:", error);

    // The request may have reached FaucetPay. Never retry it.
    try {
      await db.prepare(`
        UPDATE payments
        SET status = 'UNKNOWN',
            updated_at = ?
        WHERE id = ?
          AND session_id = ?
          AND status = 'PROCESSING'
      `).bind(
        unixTime(),
        paymentId,
        session.id
      ).run();

    } catch (databaseError) {
      console.error(
        "Could not record uncertain FaucetPay payment:",
        databaseError
      );
    }

    return {
      ok: false,
      status: "UNKNOWN",
      error: "Payment outcome is uncertain. Reconciliation is required."
    };
  }
 }
// ==========================================
// MONETAG REWARD COORDINATOR
// READ-ONLY TEST VERSION
// ==========================================
export class MonetagRewardCoordinator {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const headers = {
      "Content-Type": "application/json"
    };

    const respond = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers
      });

    if (request.method !== "POST") {
      return respond({
        ok: false,
        error: "Method not allowed"
      }, 405);
    }

    let data;

    try {
      data = await request.json();
    } catch {
      return respond({
        ok: false,
        error: "Invalid JSON"
      }, 400);
    }

    // Preserve the existing read-only health check.
    if (data.action === "health_check") {
      return respond({
        ok: true,
        coordinator: "MonetagRewardCoordinator",
        mode: "read_only",
        message: "Coordinator is running. No rewards were credited."
      });
    }
    // Securely bind one Monetag session to an active reservation.
if (data.action === "bind_ymid") {
  const userId = String(data.user_id || "");
  const reservationToken = String(data.reservation_token || "");
  const ymid = String(data.ymid || "");

  if (
    !/^\d{1,25}$/.test(userId) ||
    !reservationToken ||
    !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
  ) {
    return respond({
      ok: false,
      error: "Invalid user ID, reservation token, or session ID"
    }, 400);
  }

  const reservationKey = `monetag:reservation:${userId}`;
  const now = Date.now();

  return await this.ctx.storage.transaction(async (txn) => {
    const reservation = await txn.get(reservationKey);

    if (
      !reservation ||
      reservation.token !== reservationToken ||
      Number(reservation.expires_at || 0) <= now
    ) {
      return respond({
        ok: false,
        error: "Reservation is invalid or expired"
      }, 409);
    }

    if (
      reservation.ymid &&
      reservation.ymid !== ymid
    ) {
      return respond({
        ok: false,
        error: "Reservation is already bound to another session"
      }, 409);
    }

    await txn.put(reservationKey, {
      ...reservation,
      ymid: ymid,
      bound_at: now
    });

    return respond({
      ok: true,
      bound: true,
      reward_credited: false,
      message: "Session bound to reservation. No reward was credited."
    });
  });
  }
        // Reserve one Monetag watch session without starting the cooldown.
    if (data.action === "reserve_watch") {
      const userId = String(data.user_id || "");

      if (!/^\d{1,25}$/.test(userId)) {
        return respond({
          ok: false,
          error: "Invalid user ID"
        }, 400);
      }

      const now = Date.now();
      const cooldownKey = `monetag:last_watch:${userId}`;
      const reservationKey = `monetag:reservation:${userId}`;
      const reservationLifetimeMs = 10 * 60 * 1000;

      return await this.ctx.storage.transaction(async (txn) => {
        const lastRaw = await txn.get(cooldownKey);
        const lastTime = Number(lastRaw || 0);
        const remaining = Math.max(
          0,
          60 - Math.floor((now - lastTime) / 1000)
        );

        if (remaining > 0) {
          return respond({
            ok: true,
            can_watch: false,
            remaining_seconds: remaining,
            message: "Cooldown is active."
          });
        }

        const existing = await txn.get(reservationKey);

        if (
          existing &&
          Number(existing.expires_at || 0) > now
        ) {
          return respond({
            ok: true,
            can_watch: false,
            reservation_active: true,
            message: "An advertisement session is already in progress."
          });
        }

        const reservationToken = crypto.randomUUID();

        await txn.put(reservationKey, {
          token: reservationToken,
          created_at: now,
          expires_at: now + reservationLifetimeMs
        });

        return respond({
          ok: true,
          can_watch: true,
          reservation_token: reservationToken,
          message: "Watch session reserved. Cooldown has not started."
        });
      });
    }

    // Finish a reserved ad attempt and start the 60-second cooldown.
    if (data.action === "finish_watch") {
const userId = String(data.user_id || "");
const reservationToken = String(data.reservation_token || "");

if (
!/^\d{1,25}$/.test(userId) ||
!reservationToken
) {
return respond({
ok: false,
error: "Invalid user ID or reservation token",
reward_credited: false
}, 400);
}

const reservationKey = `monetag:reservation:${userId}`;
const cooldownKey = `monetag:last_watch:${userId}`;
const now = Date.now();

return await this.ctx.storage.transaction(async (txn) => {
const reservation = await txn.get(reservationKey);

if (
  !reservation ||
  reservation.token !== reservationToken ||
  Number(reservation.expires_at || 0) <= now ||
  !reservation.ymid
) {
  return respond({
    ok: false,
    error: "Watch session is invalid, expired, or not registered",
    reward_credited: false
  }, 409);
}

const ymid = String(reservation.ymid);
const attemptKey = `monetag:attempt:${ymid}`;
const claimKey = `monetag:claim:${ymid}`;
const verifiedKey = `monetag:verified:${ymid}`;

const existingClaim = await txn.get(claimKey);

const matchingPostback =
  existingClaim &&
  String(existingClaim.user_id) === userId &&
  String(existingClaim.ymid) === ymid;

await txn.put(attemptKey, {
  user_id: userId,
  ymid: ymid,
  completed_at: now,
  reward_claimed: false
});

if (matchingPostback) {
  await txn.put(verifiedKey, {
    user_id: userId,
    ymid: ymid,
    attempt_recorded: true,
    valued_postback_recorded: true,
    matched_at: now,
    reward_eligible_for_review: true,
    reward_credited: false
  });
}

await txn.put(cooldownKey, now);
await txn.delete(reservationKey);

return respond({
  ok: true,
  cooldown_seconds: 60,
  remaining_seconds: 60,
  cooldown_started: true,
  attempt_recorded: true,
  postback_matched: Boolean(matchingPostback),
  reward_eligible_for_review: Boolean(matchingPostback),
  reward_credited: false,
  message: matchingPostback
    ? "Ad attempt and valued postback matched. No reward credited."
    : "Ad attempt recorded. Waiting for a matching valued postback. No reward credited."
});

});
  }

    // Cancel a reserved session if the ad fails to open.
    if (data.action === "cancel_watch") {
      const userId = String(data.user_id || "");
      const reservationToken = String(data.reservation_token || "");

      if (
        !/^\d{1,25}$/.test(userId) ||
        !reservationToken
      ) {
        return respond({
          ok: false,
          error: "Invalid user ID or reservation token"
        }, 400);
      }

      const reservationKey = `monetag:reservation:${userId}`;

      return await this.ctx.storage.transaction(async (txn) => {
        const reservation = await txn.get(reservationKey);

        if (!reservation || reservation.token !== reservationToken) {
          return respond({
            ok: false,
            error: "Watch session is invalid or already closed"
          }, 409);
        }

        await txn.delete(reservationKey);

        return respond({
          ok: true,
          cancelled: true,
          reward_credited: false,
          message: "Watch reservation cancelled. No reward was credited."
        });
      });
}
    // Read-only Monetag cooldown check (60 seconds)
if (data.action === "check_cooldown") {
  const userId = String(data.user_id || "");
  const now = Date.now();
  const cooldownSeconds = 60;

  if (!/^\d{1,25}$/.test(userId)) {
    return respond({
      ok: false,
      error: "Invalid user ID",
      read_only: true
    }, 400);
  }

  const lastKey = `monetag:last_watch:${userId}`;
  const lastRaw = await this.ctx.storage.get(lastKey);
  const lastTime = Number(lastRaw || 0);
  const remaining = Math.max(
    0,
    cooldownSeconds - Math.floor((now - lastTime) / 1000)
  );

  return respond({
    ok: true,
    user_id: userId,
    cooldown_seconds: cooldownSeconds,
    remaining_seconds: remaining,
    can_watch: remaining === 0,
    read_only: true,
    message: "Cooldown checked. No cooldown or reward data was changed."
  });
  }
        // TEST ONLY: start a 60-second cooldown without crediting rewards
    if (data.action === "test_start_cooldown") {
      const userId = String(data.user_id || "");

      if (!/^\d{1,25}$/.test(userId)) {
        return respond({
          ok: false,
          error: "Invalid user ID",
          test_only: true
        }, 400);
      }

      await this.ctx.storage.put(
        `monetag:last_watch:${userId}`,
        Date.now()
      );

      return respond({
        ok: true,
        user_id: userId,
        cooldown_seconds: 60,
        test_only: true,
        reward_credited: false,
        message: "Test cooldown started. No balance or reward was changed."
      });
        }
    // Atomically check and start the 60-second cooldown.
    // Atomically allow only one qualifying claim per Monetag session.
// This records a claim only; it does not credit any reward.
// TEMPORARY TEST: call the actual claim handler twice.
// No reward is credited by this test.
    if (data.action === "check_and_start_cooldown") {
      const userId = String(data.user_id || "");

      if (!/^\d{1,25}$/.test(userId)) {
        return respond({
          ok: false,
          error: "Invalid user ID"
        }, 400);
      }

      const key = `monetag:last_watch:${userId}`;
      const now = Date.now();
      const cooldownSeconds = 60;

      // Keep the read-and-write together to prevent concurrent requests
      // from both passing the cooldown check.
      return await this.ctx.storage.transaction(async (txn) => {
        const lastRaw = await txn.get(key);
        const lastTime = Number(lastRaw || 0);
        const elapsedSeconds = Math.floor((now - lastTime) / 1000);
        const remaining = Math.max(
          0,
          cooldownSeconds - elapsedSeconds
        );

        if (remaining > 0) {
          return respond({
            ok: true,
            user_id: userId,
            cooldown_seconds: cooldownSeconds,
            remaining_seconds: remaining,
            can_watch: false,
            cooldown_started: false,
            message: "Cooldown is active."
          });
        }

        await txn.put(key, now);

        return respond({
          ok: true,
          user_id: userId,
          cooldown_seconds: cooldownSeconds,
          remaining_seconds: cooldownSeconds,
          can_watch: true,
          cooldown_started: true,
          message: "Cooldown started. No reward was credited."
        });
      });
        }
    // Validate supplied records without changing anything.
    // Record one valued-event claim per Monetag session.
// This action never credits a reward.
if (data.action === "claim_valued_event") {
const userId = String(data.user_id || "");
const ymid = String(data.ymid || "");

if (
!/^\d{1,25}$/.test(userId) ||
!/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
) {
return respond({
ok: false,
error: "Invalid user ID or Monetag session ID",
credited: false
}, 400);
}

const claimKey = `monetag:claim:${ymid}`;
const attemptKey = `monetag:attempt:${ymid}`;
const verifiedKey = `monetag:verified:${ymid}`;

return await this.ctx.storage.transaction(async (txn) => {
const existing = await txn.get(claimKey);
const attempt = await txn.get(attemptKey);

if (existing && String(existing.user_id) !== userId) {
  return respond({
    ok: false,
    error: "Session is already associated with another user",
    credited: false
  }, 403);
}

if (!existing) {
  await txn.put(claimKey, {
    user_id: userId,
    ymid: ymid,
    claimed_at: Date.now(),
    credited: false
  });
}

const matchingAttempt =
  attempt &&
  String(attempt.user_id) === userId &&
  String(attempt.ymid) === ymid;

if (matchingAttempt) {
  await txn.put(verifiedKey, {
    user_id: userId,
    ymid: ymid,
    attempt_recorded: true,
    valued_postback_recorded: true,
    matched_at: Date.now(),
    reward_eligible_for_review: true,
    reward_credited: false
  });
}

return respond({
  ok: true,
  claimed: true,
  duplicate: Boolean(existing),
  attempt_matched: Boolean(matchingAttempt),
  reward_eligible_for_review: Boolean(matchingAttempt),
  credited: false,
  message: matchingAttempt
    ? "Valued postback matched with recorded ad attempt. No reward credited."
    : "Valued postback recorded; waiting for matching ad attempt. No reward credited."
});

});
}
    // Atomically reserve a verified session for reward processing.
// This action does not credit any balance.
if (data.action === "reserve_reward_processing") {
const userId = String(data.user_id || "");
const ymid = String(data.ymid || "");

  if (
    !/^\d{1,25}$/.test(userId) ||
    !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
  ) {
    return respond({
      ok: false,
      error: "Invalid user ID or session ID",
      reward_credited: false
    }, 400);
  }

  const verifiedKey = `monetag:verified:${ymid}`;
  const processingKey = `monetag:reward_processing:${ymid}`;

  return await this.ctx.storage.transaction(async (txn) => {
    const verified = await txn.get(verifiedKey);
    const existing = await txn.get(processingKey);

    if (
      !verified ||
      String(verified.user_id) !== userId ||
      String(verified.ymid) !== ymid
    ) {
      return respond({
        ok: false,
        reserved: false,
        error: "Verified Monetag session not found",
        reward_credited: false
      }, 403);
    }

    if (existing) {
      return respond({
        ok: true,
        reserved: false,
        duplicate: true,
        status: existing.status,
        reward_credited: false,
        message: "This session already has a reward-processing record."
      });
    }

    const now = Date.now();

    await txn.put(processingKey, {
      user_id: userId,
      ymid: ymid,
      status: "reserved",
      reserved_at: now,
      reward_credited: false
    });

    return respond({
      ok: true,
      reserved: true,
      duplicate: false,
      status: "reserved",
      reward_credited: false,
      message: "Reward processing reserved. No balance was changed."
    });
  });
}
    if (data.action === "authorize_reward_credit") {
  const userId = String(data.user_id || "");
  const ymid = String(data.ymid || "");

  if (!userId || !ymid) {
    return Response.json({
      ok: false,
      error: "Missing user_id or ymid."
    }, { status: 400 });
  }

  const result = await this.ctx.storage.transaction(async (txn) => {
    const verified = await txn.get("monetag:verified:" + ymid);
    const processing = await txn.get(
      "monetag:reward_processing:" + ymid
    );

    if (!verified || String(verified.user_id) !== userId) {
      return {
        ok: false,
        authorized: false,
        error: "Verified session not found for this user."
      };
    }

    if (!processing || String(processing.user_id) !== userId) {
      return {
        ok: false,
        authorized: false,
        error: "Reward processing reservation not found."
      };
    }

    if (processing.status !== "reserved") {
      return {
        ok: true,
        authorized: false,
        duplicate: true,
        status: processing.status,
        reward_credited: false,
        message: "This session has already moved beyond the reserved stage."
      };
    }

    const now = Date.now();

    processing.status = "crediting";
    processing.amount = 0.001;
    processing.currency = "USD";
    processing.credit_authorized_at = now;
    processing.reward_credited = false;

    await txn.put(
      "monetag:reward_processing:" + ymid,
      processing
    );

    return {
      ok: true,
      authorized: true,
      duplicate: false,
      status: "crediting",
      amount: 0.001,
      currency: "USD",
      reward_credited: false,
      message: "One credit attempt authorized. No balance was changed."
    };
  });

  return Response.json(result);
  }
    // TEST ONLY: Safely finalize a reserved reward-processing record.
// This action never credits a balance.
if (data.action === "finalize_reward_processing_test") {
  const userId = String(data.user_id || "");
  const ymid = String(data.ymid || "");

  if (
    !/^\d{1,25}$/.test(userId) ||
    !/^ra_[A-Za-z0-9_-]{1,120}$/.test(ymid)
  ) {
    return respond({
      ok: false,
      error: "Invalid user ID or session ID",
      reward_credited: false
    }, 400);
  }

  const verifiedKey = `monetag:verified:${ymid}`;
  const processingKey = `monetag:reward_processing:${ymid}`;

  return await this.ctx.storage.transaction(async (txn) => {
    const verified = await txn.get(verifiedKey);
    const processing = await txn.get(processingKey);

    if (
      !verified ||
      String(verified.user_id) !== userId ||
      !processing ||
      String(processing.user_id) !== userId
    ) {
      return respond({
        ok: false,
        finalized: false,
        error: "Matching verified session or processing record not found",
        reward_credited: false
      }, 403);
    }

    if (processing.status === "test_finalized") {
      return respond({
        ok: true,
        finalized: false,
        duplicate: true,
        status: "test_finalized",
        reward_credited: false
      });
    }

    if (processing.status !== "reserved") {
      return respond({
        ok: false,
        finalized: false,
        error: "Processing record is not in reserved status",
        reward_credited: false
      }, 409);
    }

    const now = Date.now();

    await txn.put(processingKey, {
      ...processing,
      status: "test_finalized",
      finalized_at: now,
      reward_credited: false
    });

    return respond({
      ok: true,
      finalized: true,
      duplicate: false,
      status: "test_finalized",
      reward_credited: false,
      message: "Test processing finalized. No balance was changed."
    });
  });
          }
    // TEST ONLY: Recover an interrupted reward-processing reservation.
// This action never credits a balance.
if (data.action === "recover_reward_processing_test") {
  const userId = String(data.user_id || "");
  const ymid = String(data.ymid || "");

  if (
    !/^\d{1,25}$/.test(userId) ||
    !/^ra_[A-Za-z0-9_-]{1,120}$/.test(ymid)
  ) {
    return respond({
      ok: false,
      recovered: false,
      error: "Invalid user ID or session ID",
      reward_credited: false
    }, 400);
  }

  const verifiedKey = `monetag:verified:${ymid}`;
  const processingKey = `monetag:reward_processing:${ymid}`;

  return await this.ctx.storage.transaction(async (txn) => {
    const verified = await txn.get(verifiedKey);
    const processing = await txn.get(processingKey);

    if (
      !verified ||
      String(verified.user_id) !== userId ||
      !processing ||
      String(processing.user_id) !== userId
    ) {
      return respond({
        ok: false,
        recovered: false,
        error: "Matching verified session or processing record not found",
        reward_credited: false
      }, 403);
    }

    if (processing.status === "test_recovered") {
      return respond({
        ok: true,
        recovered: false,
        duplicate: true,
        status: "test_recovered",
        reward_credited: false
      });
    }

    if (processing.status !== "reserved") {
      return respond({
        ok: false,
        recovered: false,
        error: "Only reserved records can be recovered",
        status: processing.status,
        reward_credited: false
      }, 409);
    }

    const now = Date.now();

    await txn.put(processingKey, {
      ...processing,
      status: "test_recovered",
      recovered_at: now,
      reward_credited: false
    });

    return respond({
      ok: true,
      recovered: true,
      duplicate: false,
      status: "test_recovered",
      reward_credited: false,
      message: "Test reservation recovered. No balance was changed."
    });
  });
      }
   if (data.action === "inspect_session") {
  const userId = String(data.user_id || "");
  const ymid = String(data.ymid || "");

  if (
    !/^\d{1,25}$/.test(userId) ||
    !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
  ) {
    return respond({
      ok: false,
      error: "Invalid user ID or session ID",
      read_only: true
    }, 400);
  }

  const attempt = await this.ctx.storage.get(
    `monetag:attempt:${ymid}`
  );

  const claim = await this.ctx.storage.get(
    `monetag:claim:${ymid}`
  );

  const verified = await this.ctx.storage.get(
    `monetag:verified:${ymid}`
  );

  return respond({
    ok: true,
    ymid: ymid,
    user_id: userId,
    attempt_found: Boolean(attempt),
    claim_found: Boolean(claim),
    verified_found: Boolean(verified),
    attempt_matches_user: Boolean(
      attempt && String(attempt.user_id) === userId
    ),
    claim_matches_user: Boolean(
      claim && String(claim.user_id) === userId
    ),
    verified_matches_user: Boolean(
      verified && String(verified.user_id) === userId
    ),
    reward_credited: false,
    read_only: true
  });
    }
        if (data.action === "inspect_reward_processing") {
      const userId = String(data.user_id || "");
      const ymid = String(data.ymid || "");

      if (
        !/^\d{1,25}$/.test(userId) ||
        !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
      ) {
        return respond({
          ok: false,
          error: "Invalid user ID or session ID",
          read_only: true
        }, 400);
      }

      const verified = await this.ctx.storage.get(
        `monetag:verified:${ymid}`
      );

      const processing = await this.ctx.storage.get(
        `monetag:reward_processing:${ymid}`
      );

      if (
        !verified ||
        String(verified.user_id) !== userId ||
        !processing ||
        String(processing.user_id) !== userId
      ) {
        return respond({
          ok: false,
          found: false,
          error: "Matching verified processing record not found",
          read_only: true
        });
      }

      return respond({
        ok: true,
        found: true,
        user_id: userId,
        ymid: ymid,
        status: processing.status,
        amount: processing.amount || 0,
        currency: processing.currency || "USD",
        reward_credited: processing.reward_credited === true,
        credit_authorized_at:
          processing.credit_authorized_at || null,
        read_only: true
      });
      }
        if (data.action === "claim_credit_execution_test") {
      const userId = String(data.user_id || "");
      const ymid = String(data.ymid || "");

      if (
        !/^\d{1,25}$/.test(userId) ||
        !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
      ) {
        return respond({
          ok: false,
          error: "Invalid user ID or session ID",
          test_only: true
        }, 400);
      }

      const result = await this.ctx.storage.transaction(async (txn) => {
        const processing = await txn.get(
          `monetag:reward_processing:${ymid}`
        );

        if (!processing || String(processing.user_id) !== userId) {
          return {
            ok: false,
            permitted: false,
            error: "Matching processing record not found."
          };
        }

        if (processing.status !== "crediting") {
          return {
            ok: true,
            permitted: false,
            duplicate: true,
            status: processing.status,
            message: "This session cannot receive another execution permit."
          };
        }

        processing.status = "test_permit_issued";
        processing.test_permit_issued_at = Date.now();
        processing.reward_credited = false;

        await txn.put(
          `monetag:reward_processing:${ymid}`,
          processing
        );

        return {
          ok: true,
          permitted: true,
          duplicate: false,
          status: "test_permit_issued",
          amount: processing.amount,
          currency: processing.currency,
          reward_credited: false,
          message: "Test permit issued. No balance was changed."
        };
      });

      return respond({
        ...result,
        test_only: true
      });
  }
    if (data.action === "validate_event") {
      const session = data.session;
      const event = data.event;

      if (
        !session ||
        !event ||
        typeof session !== "object" ||
        typeof event !== "object"
      ) {
        return respond({
          ok: false,
          valid: false,
          error: "Session and event records are required",
          read_only: true
        }, 400);
      }

      const sameUser =
        String(session.user_id || "") !== "" &&
        String(session.user_id) === String(event.user_id || "");

      const sameYmid =
        String(session.ymid || "") !== "" &&
        String(session.ymid) === String(event.ymid || "");

      const valuedEvent =
        event.reward_event_type === "valued" &&
        event.reward_eligible === true;

      const notCredited =
        event.credited === false;

      const valid =
        sameUser &&
        sameYmid &&
        valuedEvent &&
        notCredited;

      return respond({
        ok: true,
        valid: valid,
        checks: {
          session_user_matches_event: sameUser,
          session_ymid_matches_event: sameYmid,
          valued_event_is_eligible: valuedEvent,
          event_not_already_credited: notCredited
        },
        read_only: true,
        message: valid
          ? "Event passed preliminary validation. No reward was credited."
          : "Event failed one or more validation checks. No reward was credited."
      });
    }

    return respond({
      ok: false,
      error: "Unsupported action",
      read_only: true
    }, 400);
  }
}
