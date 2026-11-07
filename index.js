// ============================================================
// RAPID ADS API
// Fresh Cloudflare Worker
// ============================================================

const CONFIG = {
  APP_NAME: "Rapid Ads",

  MONETAG_ZONE_ID: "12109194",
  MONETAG_REWARD_UNITS: 50000,
MONETAG_REWARD_CURRENCY: "USDT",
REWARD_UNITS_PER_USDT: 100000000,
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
  SELECT
    id,
    status,
    reservation_token,
    created_at,
    rowid AS session_order
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

      // Prevent an older session from overwriting a newer cooldown.
const latestCooldown = await db.prepare(`
  SELECT
    mc.session_id,
    mc.finished_at,
    ms.created_at,
    ms.rowid AS session_order
  FROM monetag_cooldowns mc
  JOIN monetag_sessions ms
    ON ms.id = mc.session_id
  WHERE mc.telegram_id = ?
`).bind(user.id).first();

if (latestCooldown) {
  const currentSessionOrder = Number(
  latestCooldown.session_order
);

const incomingSessionOrder = Number(
  session.session_order
);

if (currentSessionOrder > incomingSessionOrder) {
    const currentRemaining = Math.max(
      0,
      CONFIG.MONETAG_COOLDOWN_SECONDS -
      (now - Number(latestCooldown.finished_at))
    );

    return jsonResponse({
      ok: true,
      cooldown_started: true,
      cooldown_seconds: CONFIG.MONETAG_COOLDOWN_SECONDS,
      remaining_seconds: currentRemaining,
      attempt_recorded: true,
      reward_credited: false,
      reward_eligible_for_review: false
    });
  }
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
  const message = String(error.message || "");

  if (
    message.includes("UNIQUE constraint failed") ||
    message.includes("constraint failed")
  ) {
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
  SELECT reservation_token
  FROM monetag_reservations
  WHERE telegram_id = ?
    AND reservation_token = ?
    AND expires_at >= ?
`).bind(user.id, reservationToken, now).first();

if (!reservation) {
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

    // Insert the session only if its reservation still exists and is valid.
const insertResult = await db.prepare(`
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
  SELECT ?, ?, ?, 'PENDING', ?, ?, ?, ?
  WHERE EXISTS (
    SELECT 1
    FROM monetag_reservations
    WHERE telegram_id = ?
      AND reservation_token = ?
      AND expires_at >= ?
  )
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
  now
).run();

if (Number(insertResult.meta?.changes || 0) === 0) {
  throw new Error("Reservation is invalid, expired, or cancelled.");
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
    const zone = params.get("zone_id");
    const event = params.get("event_type");
    const rewardType = params.get("reward_event_type");

    if (!ymid || zone !== CONFIG.MONETAG_ZONE_ID) {
      throw new Error("Invalid Monetag postback details.");
    }

    if (
      !["impression", "click"].includes(event) ||
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
      SELECT
        id,
        telegram_id,
        status,
        reward_units,
        faucetpay_email
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
        status: session.status
      });
    }

    const rewardUnits = Number(session.reward_units);

    if (
      !Number.isSafeInteger(rewardUnits) ||
      rewardUnits !== CONFIG.MONETAG_REWARD_UNITS
    ) {
      throw new Error("Invalid reward amount.");
    }

    const now = unixTime();

    // Payouts disabled: verify the event without attempting payment.
    if (!CONFIG.PAYOUTS_ENABLED) {
      await db.prepare(`
        UPDATE monetag_sessions
        SET status = 'VERIFIED',
            verified_at = ?
        WHERE id = ?
          AND status = 'PENDING'
      `).bind(now, session.id).run();

      return jsonResponse({
        ok: true,
        verified: true,
        payout_status: "DISABLED",
        message: "Reward verified. Payouts are disabled."
      });
    }

    // Make exactly one payout attempt for this session.
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
  `).bind(
    now,
    now,
    session.id
  ).run();

  return jsonResponse({
    ok: true,
    verified: true,
    duplicate: false,
    payout_status: "PAID",
    payout_id: paymentResult.payout_id || null
  });
}

    const finalStatus =
      paymentResult.status === "PAID" ? "PAID" : "FAILED";

    await db.prepare(`
      UPDATE monetag_sessions
      SET status = ?,
          verified_at = ?,
          paid_at = CASE WHEN ? = 'PAID' THEN ? ELSE paid_at END
      WHERE id = ?
        AND status = 'PENDING'
    `).bind(
      finalStatus,
      now,
      finalStatus,
      now,
      session.id
    ).run();

    return jsonResponse({
      ok: true,
      verified: true,
      payout_status: finalStatus,
      payout_id: paymentResult.payout_id || null
    });

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
    return jsonResponse({
      ok: false,
      error: error.message
    }, 400);
  }
}
async function sendFaucetPayPayment(db, env, session) {
  if (!CONFIG.PAYOUTS_ENABLED) {
    return {
      ok: false,
      status: "DISABLED"
    };
  }

  if (!env.FAUCETPAY_API_KEY) {
    return {
      ok: false,
      status: "FAILED",
      error: "FaucetPay API key is not configured."
    };
  }

  const email = String(session.faucetpay_email || "")
    .trim()
    .toLowerCase();

  if (!email || !session.id || !session.telegram_id) {
    return {
      ok: false,
      status: "FAILED",
      error: "Invalid payment details."
    };
  }

  const now = unixTime();
  const paymentId = randomId("payment");
  const idempotencyKey = `rapid-ads-${session.id}`;

  // Claim this session's single payment attempt.
  // The unique session_id index prevents a second claim.
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
    ON CONFLICT(session_id) DO NOTHING
  `).bind(
    paymentId,
    session.telegram_id,
    email,
    CONFIG.MONETAG_REWARD_UNITS,
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
    // Exactly one outbound request. Never retry this request.
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
          amount: CONFIG.MONETAG_REWARD_UNITS,
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
        return {
          ok: false,
          status: "PROCESSING",
          error: "Payment confirmation could not be recorded."
        };
      }

      return {
        ok: true,
        status: "PAID",
        payout_id: payoutId
      };
    }

    await db.prepare(`
      UPDATE payments
      SET status = 'FAILED',
          updated_at = ?
      WHERE id = ?
        AND status = 'PROCESSING'
    `).bind(
      unixTime(),
      paymentId
    ).run();

    return {
      ok: false,
      status: "FAILED",
      error: "FaucetPay did not confirm the payment."
    };

  } catch (error) {
    console.error("FaucetPay payment error:", error);

    // Best-effort failure recording. Never retry the payout.
    try {
      await db.prepare(`
        UPDATE payments
        SET status = 'FAILED',
            updated_at = ?
        WHERE id = ?
          AND status = 'PROCESSING'
      `).bind(
        unixTime(),
        paymentId
      ).run();
    } catch (databaseError) {
      console.error(
        "Could not record FaucetPay failure:",
        databaseError
      );
    }

    return {
      ok: false,
      status: "FAILED",
      error: "Payment failed or its outcome is uncertain."
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
