export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    };

    const respond = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers
      });

    // Handle browser preflight requests.
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    // ==========================================
    // 1. HEALTH CHECK
    // ==========================================
    if (
      url.pathname === "/health" &&
      request.method === "GET"
    ) {
      let telegramBot = {
        checked: false,
        valid: false,
        message: "Telegram bot token is not configured"
      };

      if (env.TELEGRAM_BOT_TOKEN) {
        try {
          const telegramResponse = await fetch(
            "https://api.telegram.org/bot" +
              env.TELEGRAM_BOT_TOKEN +
              "/getMe"
          );

          const telegramResult =
            await telegramResponse.json();

          telegramBot = telegramResult.ok
            ? {
                checked: true,
                valid: true,
                username:
                  telegramResult.result.username
              }
            : {
                checked: true,
                valid: false,
                message:
                  "Telegram rejected the configured token"
              };
        } catch {
          telegramBot = {
            checked: true,
            valid: false,
            message: "Could not contact Telegram"
          };
        }
      }

      return respond({
        ok: true,
        service: "Rapid Ads API",
        status: "running",
        balanceStorageConfigured: Boolean(
          env.RAPID_ADS_BALANCES
        ),
        secretConfigured: Boolean(
          env.TBC_API_SECRET
        ),
        telegramBotTokenConfigured: Boolean(
          env.TELEGRAM_BOT_TOKEN
        ),
        telegramBot
      });
    }
// ==========================================
// REQUEST LIVE TBC BALANCE
// ==========================================
if (
  url.pathname === "/balance-request" &&
  request.method === "POST"
) {
  if (
    !env.TELEGRAM_BOT_TOKEN ||
    !env.TBC_TEST_WEBHOOK_URL ||
    !env.RAPID_ADS_BALANCES
  ) {
    return respond({
      ok: false,
      error: "Server configuration incomplete"
    }, 503);
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

  const initData = data.initData;

  if (
    typeof initData !== "string" ||
    initData.length === 0 ||
    initData.length > 10000
  ) {
    return respond({
      ok: false,
      error: "Missing Telegram authentication data"
    }, 400);
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");
    const authDate = Number(params.get("auth_date"));
    const userJson = params.get("user");

    if (
      !receivedHash ||
      !/^[a-f0-9]{64}$/i.test(receivedHash) ||
      !Number.isSafeInteger(authDate) ||
      !userJson
    ) {
      return respond({
        ok: false,
        error: "Invalid Telegram authentication data"
      }, 401);
    }

    const now = Math.floor(Date.now() / 1000);

    if (
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return respond({
        ok: false,
        error: "Telegram authentication has expired"
      }, 401);
    }

    params.delete("hash");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode("WebAppData"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const secretBytes = await crypto.subtle.sign(
      "HMAC",
      keyMaterial,
      encoder.encode(env.TELEGRAM_BOT_TOKEN)
    );

    const secretKey = await crypto.subtle.importKey(
      "raw",
      secretBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const hashBytes = await crypto.subtle.sign(
      "HMAC",
      secretKey,
      encoder.encode(dataCheckString)
    );

    const calculatedHash = Array.from(new Uint8Array(hashBytes))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    const expectedHash = receivedHash.toLowerCase();

    let difference = 0;

    for (let i = 0; i < calculatedHash.length; i++) {
      difference |=
        calculatedHash.charCodeAt(i) ^
        expectedHash.charCodeAt(i);
    }

    if (difference !== 0) {
      return respond({
        ok: false,
        error: "Telegram authentication failed"
      }, 401);
    }

    let telegramUser;

    try {
      telegramUser = JSON.parse(userJson);
    } catch {
      return respond({
        ok: false,
        error: "Invalid Telegram user data"
      }, 401);
    }

    const userId = String(telegramUser.id ?? "");

    if (!/^\d{1,20}$/.test(userId)) {
      return respond({
        ok: false,
        error: "Invalid Telegram user ID"
      }, 401);
    }

    const requestId = crypto.randomUUID();
    const pendingKey = `pending-balance:${requestId}`;
    const expiresAt = Date.now() + 120000;

    await env.RAPID_ADS_BALANCES.put(
      pendingKey,
      JSON.stringify({
        request_id: requestId,
        user_id: userId,
        expires_at: expiresAt
      }),
      { expirationTtl: 120 }
    );

    let webhookResponse;

    try {
      webhookResponse = await fetch(
        env.TBC_TEST_WEBHOOK_URL,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            request_id: requestId,
            user_id: userId
          })
        }
      );
    } catch (error) {
      await env.RAPID_ADS_BALANCES.delete(pendingKey);
      throw error;
    }

    if (!webhookResponse.ok) {
      await env.RAPID_ADS_BALANCES.delete(pendingKey);

      return respond({
        ok: false,
        error: "Telebot Creator request failed",
        upstream_status: webhookResponse.status
      }, 502);
    }

    return respond({
      ok: true,
      request_id: requestId,
      expires_in_seconds: 120,
      message: "Balance request sent"
    });
  } catch (error) {
    console.error("Balance request failed:", error);

    return respond({
      ok: false,
      error: "Could not start balance request"
    }, 500);
  }
        }
    // ==========================================
    // 2. GET BALANCE FOR AUTHENTICATED MINI APP
    // ==========================================
    if (
      url.pathname === "/balance" &&
      request.method === "POST"
    ) {
      if (
        !env.TELEGRAM_BOT_TOKEN ||
        !env.RAPID_ADS_BALANCES
      ) {
        return respond({
          ok: false,
          error: "Server configuration incomplete"
        }, 503);
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

      const initData = data.initData;

      if (
        typeof initData !== "string" ||
        initData.length === 0 ||
        initData.length > 10000
      ) {
        return respond({
          ok: false,
          error:
            "Missing or invalid Telegram authentication data"
        }, 400);
      }

      try {
        const params = new URLSearchParams(initData);

        const receivedHash = params.get("hash");
        const authDate = Number(
          params.get("auth_date")
        );
        const userJson = params.get("user");

        // Check the required authentication fields.
        if (
          !receivedHash ||
          !/^[a-f0-9]{64}$/i.test(receivedHash) ||
          !Number.isSafeInteger(authDate) ||
          !userJson
        ) {
          return respond({
            ok: false,
            error:
              "Invalid Telegram authentication data"
          }, 401);
        }

        // Reject authentication data older than 24 hours
        // or dated more than 60 seconds into the future.
        const now = Math.floor(Date.now() / 1000);

        if (
          authDate > now + 60 ||
          now - authDate > 86400
        ) {
          return respond({
            ok: false,
            error:
              "Telegram authentication has expired. Reopen the Mini App."
          }, 401);
        }

        // Build the data-check string.
        // Exclude the hash and sort the remaining fields.
        params.delete("hash");

        const dataCheckString = [...params.entries()]
          .sort(([a], [b]) => {
            if (a < b) return -1;
            if (a > b) return 1;
            return 0;
          })
          .map(
            ([key, value]) => `${key}=${value}`
          )
          .join("\n");

        const encoder = new TextEncoder();

        // IMPORTANT:
        // Telegram's Web App authentication algorithm:
        //
        // secret_key =
        // HMAC_SHA256(key="WebAppData", message=bot_token)
        //
        // calculated_hash =
        // HMAC_SHA256(key=secret_key, message=data_check_string)

        const secretKeyMaterial =
          await crypto.subtle.importKey(
            "raw",
            encoder.encode("WebAppData"),
            {
              name: "HMAC",
              hash: "SHA-256"
            },
            false,
            ["sign"]
          );

        const secretKeyBytes =
          await crypto.subtle.sign(
            "HMAC",
            secretKeyMaterial,
            encoder.encode(env.TELEGRAM_BOT_TOKEN)
          );

        const secretKey =
          await crypto.subtle.importKey(
            "raw",
            secretKeyBytes,
            {
              name: "HMAC",
              hash: "SHA-256"
            },
            false,
            ["sign"]
          );

        const calculatedHashBytes =
          await crypto.subtle.sign(
            "HMAC",
            secretKey,
            encoder.encode(dataCheckString)
          );

        const calculatedHash = Array.from(
          new Uint8Array(calculatedHashBytes)
        )
          .map(byte =>
            byte.toString(16).padStart(2, "0")
          )
          .join("");

        const normalizedReceivedHash =
          receivedHash.toLowerCase();

        // Reject a hash that does not match.
        if (
          calculatedHash.length !==
          normalizedReceivedHash.length
        ) {
          return respond({
            ok: false,
            error: "Telegram authentication failed"
          }, 401);
        }

        // Compare the hashes.
        let difference = 0;

        for (
          let i = 0;
          i < calculatedHash.length;
          i++
        ) {
          difference |=
            calculatedHash.charCodeAt(i) ^
            normalizedReceivedHash.charCodeAt(i);
        }

        if (difference !== 0) {
          return respond({
            ok: false,
            error: "Telegram authentication failed"
          }, 401);
        }

        // Parse the verified Telegram user.
        let telegramUser;

        try {
          telegramUser = JSON.parse(userJson);
        } catch {
          return respond({
            ok: false,
            error: "Invalid Telegram user data"
          }, 401);
        }

        const userId = String(
          telegramUser.id ?? ""
        );

        if (
          !/^\d+$/.test(userId) ||
          userId.length > 20
        ) {
          return respond({
            ok: false,
            error: "Invalid Telegram user ID"
          }, 401);
        }

        // Only the authenticated Telegram user ID
        // can be used to look up a balance.
        const savedRecord =
          await env.RAPID_ADS_BALANCES.get(
            `user:${userId}`
          );

        if (!savedRecord) {
          return respond({
            ok: true,
            user_id: userId,
            balance: null,
            synced: false,
            message:
              "No saved balance exists yet. Open the bot and use /balance first."
          });
        }

        let record;

        try {
          record = JSON.parse(savedRecord);
        } catch {
          return respond({
            ok: false,
            error: "Saved balance record is invalid"
          }, 500);
        }

        if (
          String(record.user_id) !== userId ||
          typeof record.balance !== "number" ||
          !Number.isFinite(record.balance) ||
          record.balance < 0
        ) {
          return respond({
            ok: false,
            error: "Saved balance record is invalid"
          }, 500);
        }

        return respond({
          ok: true,
          user_id: userId,
          balance: record.balance,
          synced: true,
          updated_at: record.updated_at
        });
      } catch {
        return respond({
          ok: false,
          error:
            "Authentication or storage operation failed"
        }, 500);
      }
    }

    // ==========================================
    // 3. SYNCHRONIZE BALANCE FROM TELEBOT CREATOR
    // ==========================================
    if (
      url.pathname === "/sync-balance" &&
      request.method === "POST"
    ) {
      if (
        !env.TBC_API_SECRET ||
        !env.RAPID_ADS_BALANCES
      ) {
        return respond({
          ok: false,
          error: "Server configuration incomplete"
        }, 503);
      }

      const authorization =
        request.headers.get("Authorization");

      if (
        !authorization ||
        authorization !==
          `Bearer ${env.TBC_API_SECRET}`
      ) {
        return respond({
          ok: false,
          error: "Unauthorized"
        }, 401);
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

      const userId = String(
        data.user_id ?? ""
      );

      const balance = Number(data.balance);

      if (
        !/^\d+$/.test(userId) ||
        userId.length > 20
      ) {
        return respond({
          ok: false,
          error: "Invalid user ID"
        }, 400);
      }

      if (
        data.balance === null ||
        data.balance === undefined ||
        data.balance === "" ||
        !Number.isFinite(balance) ||
        balance < 0 ||
        balance > 1000000000
      ) {
        return respond({
          ok: false,
          error: "Invalid balance"
        }, 400);
      }

      const record = {
        user_id: userId,
        balance: Number(balance.toFixed(8)),
        updated_at: new Date().toISOString()
      };

      try {
        await env.RAPID_ADS_BALANCES.put(
          `user:${userId}`,
          JSON.stringify(record)
        );

        return respond({
          ok: true,
          message: "Balance snapshot saved",
          user_id: userId
        });
      } catch {
        return respond({
          ok: false,
          error: "Storage operation failed"
        }, 500);
      }
    }
        // ==========================================
    // 4. REGISTER MONETAG ADVERTISEMENT SESSION
    // ==========================================
    if (
      url.pathname === "/monetag-register" &&
      request.method === "POST"
    ) {
      if (
        !env.TELEGRAM_BOT_TOKEN ||
        !env.RAPID_ADS_BALANCES
      ) {
        return respond({
          ok: false,
          error: "Server configuration incomplete"
        }, 503);
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

      const initData = data.initData;
      const ymid = data.ymid;

      if (
        typeof initData !== "string" ||
        initData.length === 0 ||
        initData.length > 10000 ||
        typeof ymid !== "string" ||
        !/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)
      ) {
        return respond({
          ok: false,
          error: "Invalid registration data"
        }, 400);
      }

      try {
        // Verify Telegram Mini App authentication.
        const params = new URLSearchParams(initData);
        const receivedHash = params.get("hash");
        const authDate = Number(params.get("auth_date"));
        const userJson = params.get("user");

        if (
          !receivedHash ||
          !/^[a-f0-9]{64}$/i.test(receivedHash) ||
          !Number.isSafeInteger(authDate) ||
          !userJson
        ) {
          return respond({
            ok: false,
            error: "Invalid Telegram authentication data"
          }, 401);
        }

        const now = Math.floor(Date.now() / 1000);

        if (
          authDate > now + 60 ||
          now - authDate > 86400
        ) {
          return respond({
            ok: false,
            error: "Telegram authentication has expired. Reopen the Mini App."
          }, 401);
        }

        params.delete("hash");

        const dataCheckString = [...params.entries()]
          .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
          .map(([key, value]) => `${key}=${value}`)
          .join("\n");

        const encoder = new TextEncoder();

        const secretKeyMaterial =
          await crypto.subtle.importKey(
            "raw",
            encoder.encode("WebAppData"),
            {
              name: "HMAC",
              hash: "SHA-256"
            },
            false,
            ["sign"]
          );

        const secretKeyBytes =
          await crypto.subtle.sign(
            "HMAC",
            secretKeyMaterial,
            encoder.encode(env.TELEGRAM_BOT_TOKEN)
          );

        const secretKey =
          await crypto.subtle.importKey(
            "raw",
            secretKeyBytes,
            {
              name: "HMAC",
              hash: "SHA-256"
            },
            false,
            ["sign"]
          );

        const calculatedHashBytes =
          await crypto.subtle.sign(
            "HMAC",
            secretKey,
            encoder.encode(dataCheckString)
          );

        const calculatedHash = Array.from(
          new Uint8Array(calculatedHashBytes)
        )
          .map(byte => byte.toString(16).padStart(2, "0"))
          .join("");

        const normalizedHash = receivedHash.toLowerCase();

        if (calculatedHash.length !== normalizedHash.length) {
          return respond({
            ok: false,
            error: "Telegram authentication failed"
          }, 401);
        }

        let difference = 0;

        for (let i = 0; i < calculatedHash.length; i++) {
          difference |=
            calculatedHash.charCodeAt(i) ^
            normalizedHash.charCodeAt(i);
        }

        if (difference !== 0) {
          return respond({
            ok: false,
            error: "Telegram authentication failed"
          }, 401);
        }

        let telegramUser;

        try {
          telegramUser = JSON.parse(userJson);
        } catch {
          return respond({
            ok: false,
            error: "Invalid Telegram user data"
          }, 401);
        }

        const userId = String(telegramUser.id ?? "");

        if (
          !/^\d+$/.test(userId) ||
          userId.length > 20
        ) {
          return respond({
            ok: false,
            error: "Invalid Telegram user ID"
          }, 401);
        }

        // Do not overwrite an existing session ID.
        const sessionKey = `monetag:session:${ymid}`;
        const existing =
          await env.RAPID_ADS_BALANCES.get(sessionKey);

        if (existing) {
          return respond({
            ok: false,
            error: "This advertisement session already exists"
          }, 409);
        }

        const session = {
          user_id: userId,
          ymid: ymid,
          created_at: new Date().toISOString(),
          credited: false
        };

        await env.RAPID_ADS_BALANCES.put(
          sessionKey,
          JSON.stringify(session),
          { expirationTtl: 7200 }
        );

        return respond({
          ok: true,
          registered: true,
          message: "Advertisement session registered"
        });

      } catch (error) {
        console.error("Monetag registration error:", error);

        return respond({
          ok: false,
          error: "Could not register advertisement session"
        }, 500);
      }
    }
    // ==========================================
    // 4. MONETAG POSTBACK — VERIFICATION ONLY
    // ==========================================
    if (
  url.pathname === "/monetag-postback" &&
  request.method === "GET"
) {
  if (
    !env.MONETAG_POSTBACK_SECRET ||
    !env.RAPID_ADS_BALANCES
  ) {
    return respond({
      ok: false,
      error: "Server configuration incomplete"
    }, 503);
  }

  // 1. Verify the private postback secret.
  const suppliedSecret = url.searchParams.get("secret");

  if (
    !suppliedSecret ||
    suppliedSecret !== env.MONETAG_POSTBACK_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized"
    }, 403);
  }

  // 2. Read the notification details.
  const ymid = url.searchParams.get("ymid");
  const rewardType =
    url.searchParams.get("reward_event_type");
  const eventType =
    url.searchParams.get("event_type");
  const zoneId = url.searchParams.get("zone_id");
  const telegramId =
    url.searchParams.get("telegram_id");
  const requestVar =
    url.searchParams.get("request_var");

  // 3. Validate the session ID.
  if (
    !ymid ||
    ymid.length > 200 ||
    !/^[a-zA-Z0-9_-]+$/.test(ymid)
  ) {
    return respond({
      ok: false,
      error: "Invalid ymid"
    }, 400);
  }

  // 4. Accept only the expected ad zone and values.
  if (
    zoneId !== "12109194" ||
    !["valued", "non_valued"].includes(rewardType) ||
    !["impression", "click"].includes(eventType) ||
    requestVar !== "rapid_ads_watch"
  ) {
    return respond({
      ok: false,
      error: "Invalid postback parameters"
    }, 400);
  }

  try {
    // 5. Find the session created by the Mini App.
    const sessionKey = `monetag:session:${ymid}`;
    const sessionText =
      await env.RAPID_ADS_BALANCES.get(sessionKey);

    if (!sessionText) {
      return respond({
        ok: false,
        error: "Advertisement session not found or expired"
      }, 404);
    }

    let session;

    try {
      session = JSON.parse(sessionText);
    } catch {
      return respond({
        ok: false,
        error: "Invalid stored session"
      }, 500);
    }

    // 6. Confirm the notification belongs to this session.
    if (
      !session.user_id ||
      String(session.user_id) !== String(telegramId) ||
      String(session.ymid) !== String(ymid)
    ) {
      return respond({
        ok: false,
        error: "Session user verification failed"
      }, 403);
    }

    // 7. Record the event separately by event and reward type.
    // This allows a non-valued event to arrive before a valued event.
    const eventKey =
      `monetag:event:${ymid}:${eventType}:${rewardType}`;

    const existing =
      await env.RAPID_ADS_BALANCES.get(eventKey);

    if (existing) {
      return respond({
        ok: true,
        duplicate: true,
        credited: false,
        message: "This notification was already recorded"
      });
    }

    const record = {
      ymid: ymid,
      user_id: String(session.user_id),
      event_type: eventType,
      reward_event_type: rewardType,
      zone_id: zoneId,
      request_var: requestVar,
      received_at: new Date().toISOString(),
      reward_eligible: rewardType === "valued",
      credited: false
    };

    await env.RAPID_ADS_BALANCES.put(
      eventKey,
      JSON.stringify(record),
      { expirationTtl: 604800 }
    );

    return respond({
      ok: true,
      recorded: true,
      reward_eligible: rewardType === "valued",
      credited: false,
      message: "Verified Monetag notification recorded; no reward credited"
    });

  } catch (error) {
    console.error("Monetag postback processing failed:", error);

    return respond({
      ok: false,
      error: "Could not process notification"
    }, 500);
  }
    }
    // ==========================================
// TBC BALANCE RESULT CALLBACK — READ ONLY
// ==========================================
if (
  url.pathname === "/tbc-balance-result" &&
  request.method === "POST"
) {
  if (
    !env.TBC_API_SECRET ||
    !env.RAPID_ADS_BALANCES
  ) {
    return respond({
      ok: false,
      error: "Server configuration incomplete"
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    `Bearer ${env.TBC_API_SECRET}`
  ) {
    return respond({
      ok: false,
      error: "Unauthorized"
    }, 401);
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

  const requestId = String(data.request_id || "");
  const userId = String(data.user_id || "");
  const balance = data.balance;

  if (
    !/^[a-zA-Z0-9_-]{16,100}$/.test(requestId) ||
    !/^\d{1,20}$/.test(userId) ||
    typeof balance !== "number" ||
    !Number.isFinite(balance) ||
    balance < 0 ||
    balance > 1000000000
  ) {
    return respond({
      ok: false,
      error: "Invalid balance result"
    }, 400);
  }

  const pendingKey = `pending-balance:${requestId}`;
  const resultKey = `balance-result:${requestId}`;

  try {
    const pending =
      await env.RAPID_ADS_BALANCES.get(
        pendingKey,
        "json"
      );

    if (
      !pending ||
      String(pending.user_id) !== userId ||
      pending.request_id !== requestId ||
      typeof pending.expires_at !== "number" ||
      pending.expires_at <= Date.now()
    ) {
      return respond({
        ok: false,
        error: "No matching valid pending request"
      }, 403);
    }

    const existing =
      await env.RAPID_ADS_BALANCES.get(resultKey);

    if (existing) {
      return respond({
        ok: false,
        error: "Request already has a result"
      }, 409);
    }

    const result = {
      request_id: requestId,
      user_id: userId,
      balance: Number(balance.toFixed(8)),
      received_at: new Date().toISOString(),
      read_only: true
    };

    await env.RAPID_ADS_BALANCES.put(
      resultKey,
      JSON.stringify(result),
      { expirationTtl: 300 }
    );

    await env.RAPID_ADS_BALANCES.delete(pendingKey);

    return respond({
      ok: true,
      received: true,
      read_only: true
    });
  } catch (error) {
    console.error(
      "TBC balance callback failed:",
      error
    );

    return respond({
      ok: false,
      error: "Could not validate or save balance result"
    }, 500);
  }
      }
// ==========================================
// TEST: SEND JSON TO TELEBOT CREATOR
// ==========================================
if (
url.pathname === "/tbc-test" &&
request.method === "POST"
) {
if (!env.TBC_TEST_WEBHOOK_URL) {
return respond({
ok: false,
error: "TBC test webhook secret is not configured"
}, 503);
}

const authorization = request.headers.get("Authorization");

if (
!env.TBC_API_SECRET ||
authorization !== `Bearer ${env.TBC_API_SECRET}`
) {
return respond({
ok: false,
error: "Unauthorized"
}, 401);
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

const testId = String(data.test_id || "");

if (testId !== "rapid-ads-tbc-connection-test") {
return respond({
ok: false,
error: "Invalid test identifier"
}, 400);
}

try {
const tbcResponse = await fetch(
env.TBC_TEST_WEBHOOK_URL,
{
method: "POST",
headers: {
"Content-Type": "application/json"
},
body: JSON.stringify({
source: "Rapid Ads Cloudflare Worker",
test_id: testId,
test_only: true,
reward_crediting: false
})
}
);

const responseText = await tbcResponse.text();

console.log("TBC TEST HTTP STATUS:", tbcResponse.status);
console.log("TBC TEST RESPONSE:", responseText.slice(0, 500));

return respond({
  ok: tbcResponse.ok,
  test_only: true,
  tbc_http_status: tbcResponse.status,
  tbc_response: responseText.slice(0, 500),
  message: tbcResponse.ok
    ? "TBC webhook request sent"
    : "TBC webhook returned an error"
}, tbcResponse.ok ? 200 : 502);

} catch (error) {
console.error("TBC test webhook failed:", error);

return respond({
  ok: false,
  error: "Could not contact TBC webhook"
}, 502);

}
}
    // ==========================================
    // 5. HANDLE OTHER REQUESTS
    // ==========================================
    // ==========================================
    // 4. HANDLE OTHER REQUESTS
    // ==========================================
    // ==========================================
// TBC BALANCE RESULT CHECK — PROTECTED TEST
// ==========================================
if (url.pathname === "/tbc-balance-result-check") {
if (request.method !== "POST") {
return respond({
ok: false,
error: "Method not allowed"
}, 405);
}

  if (
    !env.TBC_API_SECRET ||
    request.headers.get("Authorization") !==
      "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized"
    }, 401);
  }

  const body = await request.json();
  const requestId = body.request_id;

  if (
    typeof requestId !== "string" ||
    !/^[a-zA-Z0-9_-]{16,100}$/.test(requestId)
  ) {
    return respond({
      ok: false,
      error: "Invalid request_id"
    }, 400);
  }

  const result = await env.RAPID_ADS_BALANCES.get(
    "balance-result:" + requestId,
    "json"
  );

  if (!result) {
return respond({
ok: false,
error: "No saved result found",
request_id: requestId
}, 200);
  }

  return respond({
    ok: true,
    result: result
  });
}
// ==========================================
// SECURE MINI APP BALANCE RESULT CHECK
// ==========================================
if (
  url.pathname === "/balance-result" &&
  request.method === "POST"
) {
  if (
    !env.TELEGRAM_BOT_TOKEN ||
    !env.RAPID_ADS_BALANCES
  ) {
    return respond({
      ok: false,
      error: "Server configuration incomplete"
    }, 503);
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

  const initData = data.initData;
  const requestId = String(data.request_id || "");

  if (
    typeof initData !== "string" ||
    !initData ||
    initData.length > 10000 ||
    !/^[a-zA-Z0-9_-]{16,100}$/.test(requestId)
  ) {
    return respond({
      ok: false,
      error: "Invalid request"
    }, 400);
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");
    const authDate = Number(params.get("auth_date"));
    const userJson = params.get("user");

    if (
      !receivedHash ||
      !/^[a-f0-9]{64}$/i.test(receivedHash) ||
      !Number.isSafeInteger(authDate) ||
      !userJson
    ) {
      return respond({
        ok: false,
        error: "Invalid Telegram authentication"
      }, 401);
    }

    const now = Math.floor(Date.now() / 1000);

    if (authDate > now + 60 || now - authDate > 86400) {
      return respond({
        ok: false,
        error: "Telegram authentication expired"
      }, 401);
    }

    params.delete("hash");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode("WebAppData"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const secretBytes = await crypto.subtle.sign(
      "HMAC",
      keyMaterial,
      encoder.encode(env.TELEGRAM_BOT_TOKEN)
    );

    const secretKey = await crypto.subtle.importKey(
      "raw",
      secretBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const hashBytes = await crypto.subtle.sign(
      "HMAC",
      secretKey,
      encoder.encode(dataCheckString)
    );

    const calculatedHash = Array.from(new Uint8Array(hashBytes))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    const expectedHash = receivedHash.toLowerCase();
    let difference = 0;

    for (let i = 0; i < calculatedHash.length; i++) {
      difference |=
        calculatedHash.charCodeAt(i) ^
        expectedHash.charCodeAt(i);
    }

    if (difference !== 0) {
      return respond({
        ok: false,
        error: "Telegram authentication failed"
      }, 401);
    }

    let telegramUser;

    try {
      telegramUser = JSON.parse(userJson);
    } catch {
      return respond({
        ok: false,
        error: "Invalid Telegram user data"
      }, 401);
    }

    const userId = String(telegramUser.id ?? "");

    if (!/^\d{1,20}$/.test(userId)) {
      return respond({
        ok: false,
        error: "Invalid Telegram user ID"
      }, 401);
    }

    const result = await env.RAPID_ADS_BALANCES.get(
      `balance-result:${requestId}`,
      "json"
    );

    if (!result) {
      return respond({
        ok: true,
        ready: false,
        message: "Balance result is not available yet"
      });
    }

    if (String(result.user_id) !== userId) {
      return respond({
        ok: false,
        error: "This result does not belong to your account"
      }, 403);
    }

    return respond({
      ok: true,
      ready: true,
      user_id: userId,
      balance: result.balance,
      read_only: true
    });
  } catch (error) {
    console.error("Balance result check failed:", error);

    return respond({
      ok: false,
      error: "Could not check balance result"
    }, 500);
  }
}
// ==========================================
// END SECURE MINI APP BALANCE RESULT CHECK
// ==========================================
// ==========================================
// END PROTECTED BALANCE RESULT CHECK
// ==========================================
// ==========================================
// MONETAG WEBHOOK TEST — READ ONLY
// ==========================================
if (request.method === "POST" && url.pathname === "/tbc-monetag-webhook-test") {
  try {
    const auth = request.headers.get("Authorization") || "";

    if (!env.TBC_API_SECRET || auth !== `Bearer ${env.TBC_API_SECRET}`) {
      return new Response(
        JSON.stringify({ ok: false, error: "Unauthorized" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (!env.TBC_MONETAG_REWARD_WEBHOOK_URL) {
      return new Response(
        JSON.stringify({
          ok: false,
          error: "Monetag reward webhook secret is not configured"
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const body = await request.json();

    if (body.test_id !== "rapid-ads-monetag-webhook-test") {
      return new Response(
        JSON.stringify({ ok: false, error: "Invalid test request" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const requestId = crypto.randomUUID();

    const webhookResponse = await fetch(
      env.TBC_MONETAG_REWARD_WEBHOOK_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          user_id: "6694470603",
          request_id: requestId,
          ymid: "test_" + requestId
        })
      }
    );

    const responseText = await webhookResponse.text();

    return new Response(
      JSON.stringify({
        ok: webhookResponse.ok,
        webhook_http_status: webhookResponse.status,
        request_id: requestId,
        response_preview: responseText.slice(0, 500),
        read_only: true,
        message: "Test completed. No balance was changed by this test route."
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: String(error),
        read_only: true
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
// ==========================================
// END MONETAG WEBHOOK TEST
// ==========================================   
    // ==========================================
// TEMPORARY MONETAG EVENT CHECK — READ ONLY
// ==========================================
if (
  url.pathname === "/monetag-check" &&
  request.method === "POST"
) {
  if (
    !env.TBC_API_SECRET ||
    !env.RAPID_ADS_BALANCES
  ) {
    return respond({
      ok: false,
      error: "Server configuration incomplete"
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized"
    }, 401);
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

  const ymid = String(data.ymid || "");

  if (!/^[a-zA-Z0-9_-]{1,200}$/.test(ymid)) {
    return respond({
      ok: false,
      error: "Invalid ymid"
    }, 400);
  }

  try {
    const session = await env.RAPID_ADS_BALANCES.get(
      "monetag:session:" + ymid,
      "json"
    );

    const events = [];

    for (const eventType of ["impression", "click"]) {
      for (const rewardType of ["valued", "non_valued"]) {
        const key =
          "monetag:event:" +
          ymid + ":" +
          eventType + ":" +
          rewardType;

        const record =
          await env.RAPID_ADS_BALANCES.get(key, "json");

        if (record) {
          events.push({
  user_id: String(record.user_id || ""),
  event_type: record.event_type,
  reward_event_type: record.reward_event_type,
  reward_eligible: record.reward_eligible,
  credited: record.credited,
  received_at: record.received_at
});
        }
      }
    }

    return respond({
      ok: true,
      ymid: ymid,
      session_found: Boolean(session),
      session_user_matches_events: session
  ? events.every(
      event => String(event.user_id) === String(session.user_id)
    )
  : false,
      event_count: events.length,
      events: events,
      read_only: true,
      message: "Diagnostic completed. No balance changed."
    });
  } catch (error) {
    console.error("Monetag diagnostic failed:", error);

    return respond({
      ok: false,
      error: "Could not read Monetag diagnostic records"
    }, 500);
  }
}
// ==========================================
// END TEMPORARY MONETAG EVENT CHECK
// ==========================================
    // ==========================================
// MONETAG COORDINATOR HEALTH CHECK — READ ONLY
// ==========================================
if (
  url.pathname === "/monetag-coordinator-health" &&
  request.method === "POST"
) {
  if (
    !env.TBC_API_SECRET ||
    !env.MONETAG_REWARD_COORDINATOR
  ) {
    return respond({
      ok: false,
      error: "Coordinator binding or API secret is missing"
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized"
    }, 401);
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

  if (data.test_id !== "rapid-ads-coordinator-health-test") {
    return respond({
      ok: false,
      error: "Invalid test identifier"
    }, 400);
  }

  try {
    const coordinatorId =
      env.MONETAG_REWARD_COORDINATOR.idFromName(
        "rapid-ads-health-check"
      );

    const coordinator =
      env.MONETAG_REWARD_COORDINATOR.get(coordinatorId);

    const coordinatorResponse = await coordinator.fetch(
      "https://coordinator.internal/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action: "health_check"
        })
      }
    );

    const responseText =
      await coordinatorResponse.text();

    let coordinatorResult;

    try {
      coordinatorResult = JSON.parse(responseText);
    } catch {
      coordinatorResult = {
        message: "Coordinator returned an invalid response"
      };
    }

    return respond({
      ok: coordinatorResponse.ok,
      coordinator_http_status: coordinatorResponse.status,
      coordinator_result: coordinatorResult,
      read_only: true,
      message: coordinatorResponse.ok
        ? "Coordinator health check completed. No rewards were credited."
        : "Coordinator responded with an error."
    }, coordinatorResponse.ok ? 200 : 502);

  } catch (error) {
    console.error("Coordinator health check failed:", error);

    return respond({
      ok: false,
      error: "Could not contact the reward coordinator",
      read_only: true
    }, 502);
  }
}
    // ==========================================
// MONETAG COOLDOWN CHECK — READ ONLY
// ==========================================
if (
  url.pathname === "/monetag-cooldown-check" &&
  request.method === "POST"
) {
  if (!env.TBC_API_SECRET || !env.MONETAG_REWARD_COORDINATOR) {
    return respond({
      ok: false,
      error: "Required API configuration is missing",
      read_only: true
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized",
      read_only: true
    }, 401);
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return respond({
      ok: false,
      error: "Invalid JSON",
      read_only: true
    }, 400);
  }

  const userId = String(data.user_id || "");

  if (!/^\d{1,25}$/.test(userId)) {
    return respond({
      ok: false,
      error: "Invalid user ID",
      read_only: true
    }, 400);
  }

  try {
    const coordinatorId =
      env.MONETAG_REWARD_COORDINATOR.idFromName(
        "cooldown:" + userId
      );

    const coordinator =
      env.MONETAG_REWARD_COORDINATOR.get(coordinatorId);

    const coordinatorResponse = await coordinator.fetch(
      "https://coordinator.internal/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action: "check_cooldown",
          user_id: userId
        })
      }
    );

    const result = await coordinatorResponse.json();

    return respond({
      ok: coordinatorResponse.ok,
      coordinator_http_status: coordinatorResponse.status,
      result: result,
      read_only: true,
      message: "Cooldown check completed. No rewards were credited."
    }, coordinatorResponse.ok ? 200 : 502);

  } catch (error) {
    console.error("Monetag cooldown check failed:", error);

    return respond({
      ok: false,
      error: "Cooldown check failed",
      read_only: true
    }, 500);
  }
}
    // ==========================================
// MONETAG COOLDOWN START — TEST ONLY
// ==========================================
if (
  url.pathname === "/monetag-cooldown-start-test" &&
  request.method === "POST"
) {
  if (!env.TBC_API_SECRET || !env.MONETAG_REWARD_COORDINATOR) {
    return respond({
      ok: false,
      error: "Required API configuration is missing",
      test_only: true
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized",
      test_only: true
    }, 401);
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return respond({
      ok: false,
      error: "Invalid JSON",
      test_only: true
    }, 400);
  }

  const userId = String(data.user_id || "");

  if (!/^\d{1,25}$/.test(userId)) {
    return respond({
      ok: false,
      error: "Invalid user ID",
      test_only: true
    }, 400);
  }

  try {
    const coordinatorId =
      env.MONETAG_REWARD_COORDINATOR.idFromName(
        "cooldown:" + userId
      );

    const coordinator =
      env.MONETAG_REWARD_COORDINATOR.get(coordinatorId);

    const coordinatorResponse = await coordinator.fetch(
      "https://coordinator.internal/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action: "test_start_cooldown",
          user_id: userId
        })
      }
    );

    const result = await coordinatorResponse.json();

    return respond({
      ok: coordinatorResponse.ok,
      coordinator_http_status: coordinatorResponse.status,
      result: result,
      test_only: true,
      message: "Test cooldown started. No rewards were credited."
    }, coordinatorResponse.ok ? 200 : 502);

  } catch (error) {
    console.error("Monetag test cooldown start failed:", error);

    return respond({
      ok: false,
      error: "Test cooldown start failed",
      test_only: true
    }, 500);
  }
    }
// ==========================================
// END MONETAG COOLDOWN CHECK
// ==========================================
// ==========================================
// END MONETAG COORDINATOR HEALTH CHECK
// ==========================================
    // ==========================================
// MONETAG EVENT VALIDATION — READ ONLY
// ==========================================
if (
  url.pathname === "/monetag-validate-event" &&
  request.method === "POST"
) {
  if (!env.TBC_API_SECRET || !env.MONETAG_REWARD_COORDINATOR) {
    return respond({
      ok: false,
      error: "Required API configuration is missing",
      read_only: true
    }, 503);
  }

  if (
    request.headers.get("Authorization") !==
    "Bearer " + env.TBC_API_SECRET
  ) {
    return respond({
      ok: false,
      error: "Unauthorized",
      read_only: true
    }, 401);
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return respond({
      ok: false,
      error: "Invalid JSON",
      read_only: true
    }, 400);
  }

  const ymid = String(data.ymid || "");
  const telegramId = String(data.user_id || "");

  if (
    !/^ra_[A-Za-z0-9_-]{1,120}$/.test(ymid) ||
    !/^\d{1,25}$/.test(telegramId)
  ) {
    return respond({
      ok: false,
      error: "Invalid session ID or user ID",
      read_only: true
    }, 400);
  }

  try {
    const sessionRaw =
      await env.RAPID_ADS_BALANCES.get(`monetag:session:${ymid}`);

    if (!sessionRaw) {
      return respond({
        ok: true,
        valid: false,
        reason: "Session not found",
        read_only: true
      });
    }

    let session;

    try {
      session = JSON.parse(sessionRaw);
    } catch {
      return respond({
        ok: false,
        error: "Stored session data is invalid",
        read_only: true
      }, 500);
    }

    if (
      !session ||
      String(session.user_id || "") !== telegramId ||
      String(session.ymid || "") !== ymid
    ) {
      return respond({
        ok: true,
        valid: false,
        reason: "Session user verification failed",
        read_only: true
      });
    }

    const eventTypes = ["impression", "click"];
    const rewardTypes = ["valued", "non_valued"];
    const events = [];

    for (const eventType of eventTypes) {
      for (const rewardType of rewardTypes) {
        const eventKey =
          `monetag:event:${ymid}:${eventType}:${rewardType}`;

        const eventRaw =
          await env.RAPID_ADS_BALANCES.get(eventKey);

        if (!eventRaw) {
          continue;
        }

        let event;

        try {
          event = JSON.parse(eventRaw);
        } catch {
          continue;
        }

        if (
          !event ||
          String(event.ymid || "") !== ymid ||
          String(event.user_id || "") !== telegramId ||
          event.event_type !== eventType ||
          event.reward_event_type !== rewardType
        ) {
          continue;
        }

        events.push(event);
      }
    }

    if (events.length === 0) {
      return respond({
        ok: true,
        valid: false,
        reason: "No matching stored event found",
        read_only: true
      });
    }

    const results = [];

    for (const event of events) {
      const coordinatorId =
        env.MONETAG_REWARD_COORDINATOR.idFromName(
          `validate:${ymid}:${event.event_type}:${event.reward_event_type}`
        );

      const coordinator =
        env.MONETAG_REWARD_COORDINATOR.get(coordinatorId);

      const coordinatorResponse = await coordinator.fetch(
        "https://coordinator.internal/",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            action: "validate_event",
            session: {
              user_id: String(session.user_id),
              ymid: String(session.ymid)
            },
            event: {
              ymid: String(event.ymid),
              user_id: String(event.user_id),
              event_type: event.event_type,
              reward_event_type: event.reward_event_type,
              reward_eligible: event.reward_eligible === true,
              credited: event.credited === false
                ? false
                : event.credited
            }
          })
        }
      );

      let coordinatorResult;

      try {
        coordinatorResult = await coordinatorResponse.json();
      } catch {
        coordinatorResult = {
          ok: false,
          error: "Invalid coordinator response"
        };
      }

      results.push({
        event_type: event.event_type,
        reward_event_type: event.reward_event_type,
        coordinator_http_status: coordinatorResponse.status,
        validation: coordinatorResult
      });
    }

    return respond({
      ok: true,
      ymid: ymid,
      session_found: true,
      event_count: results.length,
      results: results,
      read_only: true,
      message: "Validation completed. No balance or event record was changed."
    });

  } catch (error) {
    console.error("Monetag event validation failed:", error);

    return respond({
      ok: false,
      error: "Could not complete event validation",
      read_only: true
    }, 500);
  }
}
// ==========================================
// END MONETAG EVENT VALIDATION
// ==========================================
    if (request.method !== "GET") {
      return respond({
        ok: false,
        error: "Method not allowed"
      }, 405);
    }

    return respond({
      ok: true,
      service: "Rapid Ads API",
      message:
        "Backend is running. No rewards have been credited."
    });
  }
};
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
    // Validate supplied records without changing anything.
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
