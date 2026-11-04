// ============================================================
// RAPID ADS API
// Fresh Cloudflare Worker
// ============================================================

const CONFIG = {
  APP_NAME: "Rapid Ads",

  MONETAG_ZONE_ID: "12109194",
  MONETAG_REWARD_UNITS: 50000,
  MONETAG_REWARD_CURRENCY: "USDT",
  MONETAG_COOLDOWN_SECONDS: 60,
  MONETAG_DAILY_LIMIT: 100,
  MONETAG_RESERVATION_SECONDS: 600,

  FAUCETPAY_API_BASE: "https://faucetpay.io/api/v2",

  TELEGRAM_AUTH_MAX_AGE: 86400,

  // Payouts are deliberately disabled.
  PAYOUTS_ENABLED: false
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

      if (path === "/monetag-postback" && request.method === "GET") {
        return await handleMonetagPostback(request, env);
      }

      if (path === "/payment-history" && request.method === "POST") {
        return await handlePaymentHistory(request, env);
      }

      if (path === "/claim-reward" && request.method === "POST") {
        return await handleClaimReward(request, env);
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
// TELEGRAM AUTHENTICATION
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

async function registerFaucetPayEmail(db, user, email) {
  if (!validFaucetPayEmail(email)) {
    throw new Error("Enter a valid FaucetPay email address.");
  }

  const normalizedEmail = email.trim().toLowerCase();

  await db.prepare(`
    INSERT INTO users (
      telegram_id,
      faucetpay_email,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?)
    ON CONFLICT(telegram_id)
    DO UPDATE SET
      faucetpay_email = excluded.faucetpay_email,
      updated_at = excluded.updated_at
  `).bind(
    user.id,
    normalizedEmail,
    unixTime(),
    unixTime()
  ).run();

  return {
    registered: true,
    faucetpay_email: normalizedEmail
  };
}

async function getRegisteredUser(db, telegramId) {
  return await db.prepare(`
    SELECT telegram_id, faucetpay_email, created_at
    FROM users
    WHERE telegram_id = ?
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
// MONETAG DAILY LIMIT AND COOLDOWN
// ============================================================

async function getMonetagDailyCount(db, telegramId) {
  const daily = await db.prepare(`
    SELECT COUNT(*) AS total
    FROM monetag_sessions
    WHERE telegram_id = ?
    AND date(created_at, 'unixepoch') = ?
  `).bind(
    telegramId,
    utcDateKey()
  ).first();

  return Number(daily?.total || 0);
}

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

// ============================================================
// MONETAG COOLDOWN ACTIONS
// ============================================================

async function handleMonetagCooldown(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const action = String(body.action || "check_cooldown");
    const now = unixTime();

    // --------------------------------------------------------
    // CANCEL RESERVATION
    // --------------------------------------------------------

    if (action === "cancel_watch") {
      const token = String(body.reservation_token || "");

      if (!token) {
        throw new Error("Reservation token is required.");
      }

      const result = await db.prepare(`
        DELETE FROM monetag_reservations
        WHERE telegram_id = ?
        AND reservation_token = ?
      `).bind(user.id, token).run();

      return jsonResponse({
        ok: true,
        cancelled: Number(result.meta?.changes || 0) > 0
      });
    }

    // --------------------------------------------------------
    // FINISH WATCH
    // --------------------------------------------------------

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
      `).bind(user.id, ymid).first();

      if (!session) {
        throw new Error("Monetag session not found.");
      }

      // Validate the token saved during registration.
      if (session.reservation_token !== token) {
        throw new Error("Reservation token does not match this session.");
      }

      // If this session was already finished, return its status.
      const existingCooldown = await db.prepare(`
        SELECT finished_at
        FROM monetag_cooldowns
        WHERE telegram_id = ?
        AND session_id = ?
      `).bind(user.id, session.id).first();

      if (existingCooldown) {
        const remaining = Math.max(
          0,
          CONFIG.MONETAG_COOLDOWN_SECONDS -
          (now - Number(existingCooldown.finished_at))
        );

        return jsonResponse({
          ok: true,
          cooldown_started: true,
          cooldown_seconds: CONFIG.MONETAG_COOLDOWN_SECONDS,
          remaining_seconds: remaining,
          attempt_recorded: true,
          reward_credited: false,
          reward_eligible_for_review: session.status === "VERIFIED"
        });
      }

      // Start or update the user's cooldown.
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
      `).bind(
        user.id,
        session.id,
        now
      ).run();

      // Remove the reservation after successful completion.
      await db.prepare(`
        DELETE FROM monetag_reservations
        WHERE telegram_id = ?
        AND reservation_token = ?
      `).bind(user.id, token).run();

      return jsonResponse({
        ok: true,
        cooldown_started: true,
        cooldown_seconds: CONFIG.MONETAG_COOLDOWN_SECONDS,
        remaining_seconds: CONFIG.MONETAG_COOLDOWN_SECONDS,
        attempt_recorded: true,
        reward_credited: false,
        reward_eligible_for_review: session.status === "VERIFIED"
      });
    }

    if (action !== "check_cooldown" && action !== "reserve_watch") {
      throw new Error("Unsupported Monetag action.");
    }

    // --------------------------------------------------------
    // REQUIRE FAUCETPAY EMAIL REGISTRATION
    // --------------------------------------------------------

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      return jsonResponse({
        ok: false,
        registered: false,
        can_watch: false,
        error: "Register your FaucetPay email before watching ads."
      }, 403);
    }

    // --------------------------------------------------------
    // DAILY LIMIT AND COOLDOWN
    // --------------------------------------------------------

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

    // --------------------------------------------------------
    // CREATE RESERVATION
    // --------------------------------------------------------

    const existingReservation = await db.prepare(`
      SELECT reservation_token, expires_at
      FROM monetag_reservations
      WHERE telegram_id = ?
    `).bind(user.id).first();

    if (
      existingReservation &&
      Number(existingReservation.expires_at) >= now
    ) {
      return jsonResponse({
        ok: false,
        can_watch: false,
        error: "A watch reservation is already active."
      }, 409);
    }

    await db.prepare(`
      DELETE FROM monetag_reservations
      WHERE telegram_id = ?
      AND expires_at < ?
    `).bind(user.id, now).run();

    const token = randomId("reservation");

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
// REGISTER MONETAG SESSION
// ============================================================

async function handleMonetagRegister(request, env) {
  try {
    const { body, user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    const ymid = String(body.ymid || "");
    const reservationToken = String(body.reservation_token || "");

    if (!ymid || ymid.length > 150) {
      throw new Error("Invalid Monetag session ID.");
    }

    if (!reservationToken) {
      throw new Error("Reservation token is required.");
    }

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      throw new Error("Register your FaucetPay email first.");
    }

    const now = unixTime();

    const reservation = await db.prepare(`
      SELECT reservation_token, expires_at
      FROM monetag_reservations
      WHERE telegram_id = ?
    `).bind(user.id).first();

    if (
      !reservation ||
      reservation.reservation_token !== reservationToken ||
      Number(reservation.expires_at) < now
    ) {
      throw new Error("Reservation is invalid or expired.");
    }

    const duplicate = await db.prepare(`
      SELECT id
      FROM monetag_sessions
      WHERE ymid = ?
    `).bind(ymid).first();

    if (duplicate) {
      throw new Error("This Monetag session has already been registered.");
    }

    const id = randomId("monetag");

    // Save the reservation token with the session.
    // Do not delete the reservation here.
    await db.prepare(`
      INSERT INTO monetag_sessions (
        id,
        telegram_id,
        ymid,
        status,
        reward_units,
        created_at,
        reservation_token
      )
      VALUES (?, ?, ?, 'PENDING', ?, ?, ?)
    `).bind(
      id,
      user.id,
      ymid,
      CONFIG.MONETAG_REWARD_UNITS,
      now,
      reservationToken
    ).run();

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
// MONETAG POSTBACK
// ============================================================

async function handleMonetagPostback(request, env) {
  try {
    if (!env.MONETAG_POSTBACK_SECRET) {
      throw new Error("Monetag postback secret is not configured.");
    }

    const url = new URL(request.url);
    const params = url.searchParams;

    const suppliedSecret = params.get("secret") || "";

    if (!timingSafeEqual(
      suppliedSecret,
      env.MONETAG_POSTBACK_SECRET
    )) {
      return jsonResponse({
        ok: false,
        error: "Unauthorized postback."
      }, 401);
    }

    const ymid = params.get("ymid");
    const zone = params.get("zone");
    const event = params.get("event");
    const rewardType = params.get("reward_type");

    if (!ymid || zone !== CONFIG.MONETAG_ZONE_ID) {
      throw new Error("Invalid Monetag postback details.");
    }

    if (
      event !== "impression" ||
      rewardType !== "valued"
    ) {
      return jsonResponse({
        ok: true,
        ignored: true,
        message: "Event is not reward eligible."
      });
    }

    const db = getDatabase(env);

    const session = await db.prepare(`
      SELECT id, telegram_id, status, reward_units
      FROM monetag_sessions
      WHERE ymid = ?
    `).bind(ymid).first();

    if (!session) {
      throw new Error("Monetag session not found.");
    }

    if (session.status !== "PENDING") {
      return jsonResponse({
        ok: true,
        duplicate: true,
        credited: false
      });
    }

    const now = unixTime();

    const result = await db.prepare(`
      UPDATE monetag_sessions
      SET status = 'VERIFIED',
          verified_at = ?
      WHERE id = ?
      AND status = 'PENDING'
    `).bind(now, session.id).run();

    if (!result.meta?.changes) {
      return jsonResponse({
        ok: true,
        duplicate: true,
        credited: false
      });
    }

    return jsonResponse({
      ok: true,
      verified: true,
      credited: false,
      reward_units: session.reward_units,
      currency: CONFIG.MONETAG_REWARD_CURRENCY
    });

  } catch (error) {
    return jsonResponse({
      ok: false,
      error: error.message
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
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
}

// ============================================================
// CLAIM REWARD
// ============================================================

async function handleClaimReward(request, env) {
  try {
    const { user } = await authenticateRequest(request, env);
    const db = getDatabase(env);

    if (!CONFIG.PAYOUTS_ENABLED) {
      return jsonResponse({
        ok: false,
        payouts_enabled: false,
        error: "Payouts are temporarily disabled while Rapid Ads is being tested."
      }, 503);
    }

    const registeredUser = await getRegisteredUser(db, user.id);

    if (!registeredUser?.faucetpay_email) {
      throw new Error("Register your FaucetPay email first.");
    }

    return jsonResponse({
      ok: false,
      error: "FaucetPay payout processing is not implemented yet."
    }, 501);

  } catch (error) {
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
    }
