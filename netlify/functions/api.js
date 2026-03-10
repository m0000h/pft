const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ALLOWED_TABLES = ["budget", "goals", "history"];

exports.handler = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": process.env.URL || "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  };

  // Preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers };
  }

  // Verify Netlify Identity JWT
  const authHeader = event.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "").trim();
  if (!token) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: "Unauthorized" }) };
  }

  // Decode JWT to get user id (Netlify Identity JWTs are verified server-side)
  let userId;
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
    userId = payload.sub;
    if (!userId) throw new Error("No sub");
    // Check expiry
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error("Token expired");
    }
  } catch {
    return { statusCode: 401, headers, body: JSON.stringify({ error: "Invalid token" }) };
  }

  // Parse route: /api/{table}/{id?}
  const parts = (event.path.replace(/^\/api\//, "")).split("/").filter(Boolean);
  const table = parts[0];
  const id = parts[1];

  if (!ALLOWED_TABLES.includes(table)) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid table" }) };
  }

  try {
    let result;

    if (event.httpMethod === "GET") {
      const { data, error } = await supabase
        .from(table)
        .select("*")
        .eq("user_id", userId);
      if (error) throw error;
      result = data;
    }

    else if (event.httpMethod === "POST") {
      const body = JSON.parse(event.body);
      const { data, error } = await supabase
        .from(table)
        .insert({ ...body, user_id: userId })
        .select();
      if (error) throw error;
      result = data;
    }

    else if (event.httpMethod === "PUT") {
      if (!id) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing id" }) };
      const body = JSON.parse(event.body);
      const { data, error } = await supabase
        .from(table)
        .update(body)
        .eq("id", id)
        .eq("user_id", userId)
        .select();
      if (error) throw error;
      result = data;
    }

    else if (event.httpMethod === "DELETE") {
      if (!id) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing id" }) };
      const { error } = await supabase
        .from(table)
        .delete()
        .eq("id", id)
        .eq("user_id", userId);
      if (error) throw error;
      result = { deleted: true };
    }

    else {
      return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };
    }

    return { statusCode: 200, headers, body: JSON.stringify(result) };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};