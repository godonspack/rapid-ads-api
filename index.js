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

  const authorization =
    request.headers.get("Authorization");

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

  if (
    testId !== "rapid-ads-tbc-connection-test"
  ) {
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

    const responseText =
      await tbcResponse.text();

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
