import dns from "node:dns/promises";

const ALLOWED_ORIGINS = [
  "https://waytosubscribe.github.io"
];

const IP_CODES = {
  "127.0.0.2": "SBL",
  "127.0.0.3": "SBL-CSS",
  "127.0.0.4": "XBL",
  "127.0.0.9": "DROP",
  "127.0.0.10": "PBL - Network Maintained",
  "127.0.0.11": "PBL - Spamhaus Maintained"
};

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

function reverseIPv4(ip) {
  return ip.split(".").reverse().join(".");
}

function isIPv4(value) {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every(p => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)
  );
}

function classifyIP(code) {
  return IP_CODES[code] || `Spamhaus code ${code}`;
}

function classifyDomain(code) {
  const parts = code.split(".");
  if (parts.length !== 4) return `Spamhaus code ${code}`;

  const third = Number(parts[2]);
  const fourth = Number(parts[3]);

  if (third === 1 && fourth >= 2 && fourth <= 99) {
    return "DBL - Bad/Low Reputation";
  }

  if (third === 1 && fourth >= 102 && fourth <= 199) {
    return "DBL - Abused-Legit";
  }

  if (code === "127.0.1.255") {
    return "DBL - Invalid query with an IP";
  }

  return `Spamhaus code ${code}`;
}

export async function GET(request) {
  const url = new URL(request.url);

  const target = (url.searchParams.get("target") || "").trim().toLowerCase();
  const type = (url.searchParams.get("type") || "").trim().toLowerCase();

  const configuredOrigin = request.headers.get("origin") || "";

  const allowedOrigin =
    ALLOWED_ORIGINS.includes(configuredOrigin)
      ? configuredOrigin
      : ALLOWED_ORIGINS[0];

  if (!target) {
    return json(
      { ok: false, error: "Missing target" },
      400,
      allowedOrigin
    );
  }

  if (type !== "ip" && type !== "domain") {
    return json(
      { ok: false, error: "type must be ip or domain" },
      400,
      allowedOrigin
    );
  }

  const key = process.env.SPAMHAUS_DQS_KEY;

  if (!key) {
    return json(
      { ok: false, error: "Spamhaus DQS key is not configured" },
      500,
      allowedOrigin
    );
  }

  try {
    let hostname;

    if (type === "ip") {
      if (!isIPv4(target)) {
        return json(
          { ok: false, error: "Invalid IPv4 address" },
          400,
          allowedOrigin
        );
      }

      hostname =
        `${reverseIPv4(target)}.${key}.zen.dq.spamhaus.net`;
    } else {
      hostname =
        `${target}.${key}.dbl.dq.spamhaus.net`;
    }

    let records = [];

    try {
      records = await dns.resolve4(hostname);
    } catch (error) {
      if (
        error.code === "ENOTFOUND" ||
        error.code === "ENODATA" ||
        error.code === "ESERVFAIL"
      ) {
        return json(
          {
            ok: true,
            target,
            type,
            listed: false,
            status: "CLEAR",
            codes: [],
            categories: [],
            query: hostname
          },
          200,
          allowedOrigin
        );
      }

      throw error;
    }

    const uniqueCodes = [...new Set(records)];

    const categories =
      type === "ip"
        ? uniqueCodes.map(classifyIP)
        : uniqueCodes.map(classifyDomain);

    return json(
      {
        ok: true,
        target,
        type,
        listed: uniqueCodes.length > 0,
        status: uniqueCodes.length > 0 ? "LISTED" : "CLEAR",
        codes: uniqueCodes,
        categories,
        query: hostname
      },
      200,
      allowedOrigin
    );

  } catch (error) {
    console.error("Spamhaus lookup error:", error);

    return json(
      {
        ok: false,
        error: "Spamhaus lookup failed"
      },
      500,
      allowedOrigin
    );
  }
}

export async function OPTIONS(request) {
  const origin = request.headers.get("origin") || "";

  const allowedOrigin =
    ALLOWED_ORIGINS.includes(origin)
      ? origin
      : ALLOWED_ORIGINS[0];

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}
