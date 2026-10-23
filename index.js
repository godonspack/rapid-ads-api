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

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    // Health check
    if (url.pathname === "/health" && request.method === "GET") {
      return respond({
        ok: true,
        service: "Rapid Ads API",
        status: "running",
        balanceStorageConfigured: Boolean(
          env.RAPID_ADS_BALANCES
        ),
        secretConfigured: Boolean(env.TBC_API_SECRET),
        telegramBotTokenConfigured: Boolean(
          env.TELEGRAM_BOT_TOKEN
        )
      });
    }

    // Retrieve a balance using verified Telegram Mini App data
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
          error: "Missing or invalid Telegram authentication data"
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

        // Reject authentication data older than 24 hours
        // or dated too far in the future.
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
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => `${key}=${value}`)
          .join("\n");

        const encoder = new TextEncoder();

        // Telegram's Web App validation:
        // HMAC key = bot token; message = "WebAppData".
        const tokenKey = await crypto.subtle.importKey(
          "raw",
          encoder.encode(env.TELEGRAM_BOT_TOKEN),
          {
            name: "HMAC",
            hash: "SHA-256"
          },
          false,
          ["sign"]
        );

        const secretKeyBytes = await crypto.subtle.sign(
          "HMAC",
          tokenKey,
          encoder.encode("WebAppData")
        );

        const secretKey = await crypto.subtle.importKey(
          "raw",
          secretKeyBytes,
          {
            name: "HMAC",
            hash: "SHA-256"
          },
          false,
          ["sign"]
        );

        const calculatedHashBytes = await crypto.subtle.sign(
          "HMAC",
          secretKey,
          encoder.encode(dataCheckString)
        );

        const calculatedHash = Array.from(
          new Uint8Array(calculatedHashBytes)
        )
          .map(byte => byte.toString(16).padStart(2, "0"))
          .join("");

        if (
          calculatedHash.length !== receivedHash.length ||
          !crypto.subtle
        ) {
          return respond({
            ok: false,
            error: "Telegram authentication failed"
          }, 401);
        }

        // Compare the two hashes without an early character-by-character exit.
        let difference = 0;

        for (let i = 0; i < calculatedHash.length; i++) {
          difference |=
            calculatedHash.charCodeAt(i) ^
            receivedHash.toLowerCase().charCodeAt(i);
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

        // Only the verified Telegram ID is used to select a KV record.
        const savedRecord = await env.RAPID_ADS_BALANCES.get(
          `user:${userId}`
        );

        if (!savedRecord) {
          return respond({
            ok: true,
            user_id: userId,
            balance: null,
            synced: false,
            message: "No balance snapshot exists yet. Synchronize the TBC balance first."
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
          error: "Authentication or storage operation failed"
        }, 500);
      }
    }

    // Synchronize a balance from the trusted TBC command
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

      const userId = String(data.user_id ?? "");
      const balance = Number(data.balance);

      if (!/^\d+$/.test(userId) || userId.length > 20) {
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

    if (request.method !== "GET") {
      return respond({
        ok: false,
        error: "Method not allowed"
      }, 405);
    }

    return respond({
      ok: true,
      service: "Rapid Ads API",
      message: "Backend is running. No rewards have been credited."
    });
  }
};
