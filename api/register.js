
const {
  readJSON,
  writeJSON
} = require("../lib/github-storage");

const {
  normalizeUsername,
  normalizeEmail,
  validUsername,
  hashPassword,
  setSessionCookie,
  createPersistentSessionToken,
  setCors
} = require("../lib/auth");

function send(res, status, data) {
  return res.status(status).json(data);
}

function createId() {
  return (
    Date.now().toString(36) +
    Math.random().toString(36).slice(2, 12)
  );
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  const allowedOrigin = process.env.TUNEVA_FRONTEND_ORIGIN;

  if (
    allowedOrigin &&
    req.headers.origin &&
    req.headers.origin !== allowedOrigin
  ) {
    return send(res, 403, {
      ok: false,
      message: "Origin not allowed."
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");

    return send(res, 405, {
      ok: false,
      message: "Method not allowed."
    });
  }

  try {
    const body = req.body || {};

    const fullName = String(body.fullName || "").trim();
    const username = normalizeUsername(body.username);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const phone = String(body.phone || "").trim();
    const country = String(body.country || "").trim();
    const countryCode = String(body.countryCode || "").trim();

    if (fullName.split(/\s+/).length < 2) {
      return send(res, 400, {
        ok: false,
        message: "Enter your full name."
      });
    }

    if (!validUsername(username)) {
      return send(res, 400, {
        ok: false,
        message: "Username must contain 3–20 letters, numbers or underscores."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return send(res, 400, {
        ok: false,
        message: "Enter a valid email address."
      });
    }

    if (password.length < 8) {
      return send(res, 400, {
        ok: false,
        message: "Password must contain at least 8 characters."
      });
    }

    if (!phone) {
      return send(res, 400, {
        ok: false,
        message: "Enter your phone number."
      });
    }

    if (body.termsAccepted !== true) {
      return send(res, 400, {
        ok: false,
        message: "Please accept the terms."
      });
    }

    const file = await readJSON("data/users.json", {
      users: []
    });

    const users = Array.isArray(file.data)
      ? file.data
      : Array.isArray(file.data?.users)
        ? file.data.users
        : [];

    const duplicate = users.find(function (user) {
      return (
        normalizeUsername(user.username) === username ||
        normalizeEmail(user.email) === email
      );
    });

    if (duplicate) {
      return send(res, 409, {
        ok: false,
        message: "Username or email is already registered."
      });
    }

    const passwordHash = await hashPassword(password);

    const user = {
      id: createId(),
      fullName,
      username,
      email,
      phone,
      country,
      countryCode,
      passwordHash,
      status: "active",
      sessionVersion: 1,
      termsAccepted: true,
      createdAt: new Date().toISOString()
    };

    users.push(user);

    await writeJSON(
      "data/users.json",
      { users },
      file.sha
    );

    const authToken = createPersistentSessionToken(user);

    setSessionCookie(res, user);

    return send(res, 201, {
      ok: true,
      authToken,
      user: {
        id: user.id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        phone: user.phone,
        status: user.status
      }
    });

  } catch (error) {
    console.error("[TUNEVA REGISTER]", error);

    return send(res, 500, {
      ok: false,
      message: "Unable to create your account. Please try again."
    });
  }
};
                                 
