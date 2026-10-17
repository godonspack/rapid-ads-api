export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    if (request.method !== "GET") {
      return Response.json(
        { ok: false, error: "Method not allowed" },
        { status: 405, headers }
      );
    }

    if (url.pathname === "/health") {
      return Response.json(
        {
          ok: true,
          service: "Rapid Ads API",
          status: "running",
          databaseConfigured: Boolean(env.SUPABASE_URL)
        },
        { headers }
      );
    }

    return Response.json(
      {
        ok: true,
        service: "Rapid Ads API",
        message: "Backend is running. No rewards have been credited."
      },
      { headers }
    );
  }
};
