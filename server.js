const { createServer } = require("node:http");
const { mkdirSync } = require("node:fs");
const { readFile } = require("node:fs/promises");
const path = require("node:path");
const { promisify } = require("node:util");
const {
  randomBytes,
  scrypt: scryptCallback,
  timingSafeEqual,
  createHash
} = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const scrypt = promisify(scryptCallback);
const root = __dirname;
const dataDirectory = path.resolve(process.env.DATA_DIR || path.join(root, "data"));
mkdirSync(dataDirectory, { recursive: true });
const database = new DatabaseSync(path.join(dataDirectory, "khdemli.sqlite"));
const host = process.env.HOST || (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
const port = Number(process.env.PORT || 3000);
const sessionLifetime = 30 * 24 * 60 * 60 * 1000;
const loginWindow = 15 * 60 * 1000;
const loginLimit = 10;
const loginAttempts = new Map();
const adminLoginAttempts = new Map();
const adminPassword = process.env.ADMIN_PASSWORD || "";
const adminEnabled = adminPassword.length >= 16 && adminPassword.length <= 128;

database.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    wilaya TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    area TEXT NOT NULL,
    price INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL,
    UNIQUE(service_id, requester_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, id);
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reviewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider_id, reviewer_id)
  );
  CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS admin_sessions_expiry_idx ON admin_sessions(expires_at);
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const statements = {
  userById: database.prepare("SELECT * FROM users WHERE id = ?"),
  userByEmail: database.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE"),
  allUsers: database.prepare("SELECT id, first_name, last_name, wilaya FROM users ORDER BY id"),
  allServices: database.prepare(`
    SELECT services.*, users.first_name, users.last_name
    FROM services JOIN users ON users.id = services.owner_id
    ORDER BY services.created_at DESC
  `),
  userConversations: database.prepare(`
    SELECT conversations.*, services.owner_id
    FROM conversations JOIN services ON services.id = conversations.service_id
    WHERE conversations.requester_id = ? OR services.owner_id = ?
    ORDER BY conversations.updated_at DESC
  `),
  conversationMessages: database.prepare(`
    SELECT id, sender_id, text, created_at FROM messages
    WHERE conversation_id = ? ORDER BY id
  `),
  sessionUser: database.prepare(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `),
  conversationById: database.prepare("SELECT * FROM conversations WHERE id = ?"),
  serviceById: database.prepare("SELECT * FROM services WHERE id = ?"),
  deleteExpiredSessions: database.prepare("DELETE FROM sessions WHERE expires_at <= ?"),
  deleteExpiredAdminSessions: database.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?")
};

function json(response, status, value) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(value));
}

function fail(response, status, message) {
  json(response, status, { error: message });
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: Number(user.id),
    firstName: user.first_name,
    lastName: user.last_name,
    name: `${user.first_name} ${user.last_name}`,
    email: user.email,
    wilaya: user.wilaya
  };
}

function publicAccount(user) {
  return {
    id: Number(user.id),
    firstName: user.first_name,
    lastName: user.last_name,
    name: `${user.first_name} ${user.last_name}`,
    wilaya: user.wilaya
  };
}

function publicService(service) {
  return {
    id: service.id,
    owner: Number(service.owner_id),
    ownerName: `${service.first_name} ${service.last_name}`,
    title: service.title,
    category: service.category,
    area: service.area,
    price: Number(service.price),
    description: service.description,
    createdAt: service.created_at
  };
}

function getUserFromRequest(request) {
  const cookies = Object.fromEntries(
    (request.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split(/=(.*)/s).slice(0, 2))
      .filter(([name, value]) => name && value !== undefined)
  );
  const token = cookies.session;
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  return statements.sessionUser.get(tokenHash, Date.now()) || null;
}

function getCookie(request, name) {
  const cookie = (request.headers.cookie || "").split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1) : "";
}

function isAdminAuthenticated(request) {
  const token = getCookie(request, "admin_session");
  if (!/^[a-f0-9]{64}$/.test(token)) return false;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  return Boolean(database.prepare(
    "SELECT 1 FROM admin_sessions WHERE token_hash = ? AND expires_at > ?"
  ).get(tokenHash, Date.now()));
}

function requireAdmin(request, response) {
  if (isAdminAuthenticated(request)) return true;
  fail(response, 401, "سجّل الدخول إلى غرفة الإدارة أولاً.");
  return false;
}

function setAdminSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`
  );
}

function clearAdminSessionCookie(response) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`
  );
}

function recordAdminAction(action, resourceId) {
  database.prepare(
    "INSERT INTO admin_audit_log (action, resource_id, created_at) VALUES (?, ?, ?)"
  ).run(action, String(resourceId), new Date().toISOString());
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`
  );
}

function clearSessionCookie(response) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function issueSession(response, userId) {
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  database.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .run(tokenHash, userId, Date.now() + sessionLifetime);
  setSessionCookie(response, token);
}

async function readJson(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body) > 1024 * 1024) {
      const error = new Error("حجم الطلب أكبر من المسموح.");
      error.status = 413;
      throw error;
    }
  }
  if (!body) return {};
  try {
    const value = JSON.parse(body);
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error();
    return value;
  } catch {
    const error = new Error("صيغة البيانات غير صحيحة.");
    error.status = 400;
    throw error;
  }
}

function requireUser(user, response) {
  if (user) return true;
  fail(response, 401, "سجّل الدخول لمتابعة العملية.");
  return false;
}

function isValidEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function loginIsLimited(request) {
  const key = request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const current = loginAttempts.get(key);
  if (!current || now - current.startedAt >= loginWindow) {
    loginAttempts.set(key, { startedAt: now, count: 0 });
    return false;
  }
  return current.count >= loginLimit;
}

function recordLoginFailure(request) {
  const key = request.socket.remoteAddress || "unknown";
  const current = loginAttempts.get(key);
  if (current) current.count += 1;
}

function loginIsRateLimited(request, attempts) {
  const key = request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const current = attempts.get(key);
  if (!current || now - current.startedAt >= loginWindow) {
    attempts.set(key, { startedAt: now, count: 0 });
    return false;
  }
  return current.count >= loginLimit;
}

function recordRateLimitedFailure(request, attempts) {
  const key = request.socket.remoteAddress || "unknown";
  const current = attempts.get(key);
  if (current) current.count += 1;
}

function getConversationForUser(conversationId, userId) {
  const conversation = statements.conversationById.get(conversationId);
  if (!conversation) return null;
  const service = statements.serviceById.get(conversation.service_id);
  if (!service || (Number(userId) !== Number(conversation.requester_id) &&
      Number(userId) !== Number(service.owner_id))) return null;
  return { conversation, service };
}

function getBootstrap(user) {
  const accounts = statements.allUsers.all().map(publicAccount);
  const services = statements.allServices.all().map(publicService);
  const conversations = user
    ? statements.userConversations.all(user.id, user.id).map((conversation) => {
      const participants = [...new Set([
        Number(conversation.requester_id),
        Number(conversation.owner_id)
      ])];
      return {
        id: conversation.id,
        serviceId: conversation.service_id,
        participants,
        messages: statements.conversationMessages.all(conversation.id).map((message) => ({
          id: Number(message.id),
          sender: Number(message.sender_id),
          text: message.text,
          createdAt: message.created_at
        }))
      };
    })
    : [];
  return { user: publicUser(user), accounts, services, conversations };
}

async function handleApi(request, response, url) {
  const route = url.pathname;
  const method = request.method;
  const user = getUserFromRequest(request);
  if (method === "GET" && route === "/api/bootstrap") {
    return json(response, 200, getBootstrap(user));
  }
  if (method === "GET" && route === "/api/admin/auth/me") {
    return json(response, 200, {
      enabled: adminEnabled,
      authenticated: adminEnabled && isAdminAuthenticated(request)
    });
  }
  if (method === "POST" && route === "/api/admin/auth/login") {
    if (!adminEnabled) {
      return fail(response, 503, "اضبط ADMIN_PASSWORD بطول 16 إلى 128 حرفاً لتفعيل غرفة الإدارة.");
    }
    if (loginIsRateLimited(request, adminLoginAttempts)) {
      return fail(response, 429, "محاولات كثيرة. انتظر 15 دقيقة ثم أعد المحاولة.");
    }
    const body = await readJson(request);
    const password = typeof body.password === "string" ? body.password : "";
    const provided = Buffer.from(password);
    const expected = Buffer.from(adminPassword);
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      recordRateLimitedFailure(request, adminLoginAttempts);
      return fail(response, 401, "كلمة مرور المشرف غير صحيحة.");
    }
    adminLoginAttempts.delete(request.socket.remoteAddress || "unknown");
    const token = randomBytes(32).toString("hex");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    database.prepare("INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)")
      .run(tokenHash, Date.now() + sessionLifetime);
    setAdminSessionCookie(response, token);
    return json(response, 200, { authenticated: true });
  }
  if (method === "POST" && route === "/api/admin/auth/logout") {
    const token = getCookie(request, "admin_session");
    if (/^[a-f0-9]{64}$/.test(token)) {
      database.prepare("DELETE FROM admin_sessions WHERE token_hash = ?")
        .run(createHash("sha256").update(token).digest("hex"));
    }
    clearAdminSessionCookie(response);
    return json(response, 200, { ok: true });
  }
  if (route === "/api/admin/services" && method === "GET") {
    if (!adminEnabled) return fail(response, 503, "غرفة الإدارة غير مفعّلة.");
    if (!requireAdmin(request, response)) return;
    return json(response, 200, { services: statements.allServices.all().map(publicService) });
  }
  if (route === "/api/admin/conversations" && method === "GET") {
    if (!adminEnabled) return fail(response, 503, "غرفة الإدارة غير مفعّلة.");
    if (!requireAdmin(request, response)) return;
    const conversations = database.prepare(`
      SELECT conversations.id, conversations.service_id, conversations.requester_id,
        requester.first_name AS requester_first, requester.last_name AS requester_last,
        provider.first_name AS provider_first, provider.last_name AS provider_last,
        services.title AS service_title, COUNT(messages.id) AS message_count
      FROM conversations
      JOIN services ON services.id = conversations.service_id
      JOIN users AS requester ON requester.id = conversations.requester_id
      JOIN users AS provider ON provider.id = services.owner_id
      LEFT JOIN messages ON messages.conversation_id = conversations.id
      GROUP BY conversations.id
      ORDER BY conversations.updated_at DESC
    `).all().map((conversation) => ({
      id: conversation.id,
      serviceId: conversation.service_id,
      requesterName: `${conversation.requester_first} ${conversation.requester_last}`,
      providerName: `${conversation.provider_first} ${conversation.provider_last}`,
      serviceTitle: conversation.service_title,
      messageCount: Number(conversation.message_count)
    }));
    return json(response, 200, { conversations });
  }
  const adminConversationMatch = route.match(/^\/api\/admin\/conversations\/([a-f0-9]+)$/i);
  if (adminConversationMatch && method === "GET") {
    if (!adminEnabled) return fail(response, 503, "غرفة الإدارة غير مفعّلة.");
    if (!requireAdmin(request, response)) return;
    const conversation = database.prepare(`
      SELECT conversations.id, conversations.service_id,
        requester.first_name AS requester_first, requester.last_name AS requester_last,
        provider.first_name AS provider_first, provider.last_name AS provider_last,
        services.title AS service_title
      FROM conversations
      JOIN services ON services.id = conversations.service_id
      JOIN users AS requester ON requester.id = conversations.requester_id
      JOIN users AS provider ON provider.id = services.owner_id
      WHERE conversations.id = ?
    `).get(adminConversationMatch[1]);
    if (!conversation) return fail(response, 404, "لم نعثر على المحادثة.");
    recordAdminAction("view_conversation", conversation.id);
    const messages = database.prepare(`
      SELECT messages.text, messages.created_at, users.first_name, users.last_name
      FROM messages JOIN users ON users.id = messages.sender_id
      WHERE messages.conversation_id = ? ORDER BY messages.id
    `).all(conversation.id).map((message) => ({
      text: message.text,
      createdAt: message.created_at,
      senderName: `${message.first_name} ${message.last_name}`
    }));
    return json(response, 200, {
      conversation: {
        id: conversation.id,
        requesterName: `${conversation.requester_first} ${conversation.requester_last}`,
        providerName: `${conversation.provider_first} ${conversation.provider_last}`,
        serviceTitle: conversation.service_title
      },
      messages
    });
  }
  const adminDeleteServiceMatch = route.match(/^\/api\/admin\/services\/([a-f0-9]+)$/i);
  if (adminDeleteServiceMatch && method === "DELETE") {
    if (!adminEnabled) return fail(response, 503, "غرفة الإدارة غير مفعّلة.");
    if (!requireAdmin(request, response)) return;
    const serviceId = adminDeleteServiceMatch[1];
    if (!statements.serviceById.get(serviceId)) return fail(response, 404, "لم نعثر على الخدمة.");
    recordAdminAction("delete_service", serviceId);
    database.prepare("DELETE FROM services WHERE id = ?").run(serviceId);
    response.writeHead(204, { "Cache-Control": "no-store" });
    return response.end();
  }
  if (method === "POST" && route === "/api/auth/signup") {
    const body = await readJson(request);
    const firstName = typeof body.firstName === "string" ? body.firstName.trim() : "";
    const lastName = typeof body.lastName === "string" ? body.lastName.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const wilaya = typeof body.wilaya === "string" ? body.wilaya.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!firstName || firstName.length > 40 || !lastName || lastName.length > 40 ||
        !isValidEmail(email) || !wilaya || wilaya.length > 60) {
      return fail(response, 400, "تحقق من الاسم واللقب والبريد الإلكتروني والولاية.");
    }
    if (password.length < 8 || password.length > 128 ||
        !/[A-Za-z\u0600-\u06FF]/.test(password) || !/[0-9]/.test(password)) {
      return fail(response, 400, "كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل وحرف ورقم.");
    }
    const salt = randomBytes(16);
    const passwordHash = await scrypt(password, salt, 64);
    try {
      const result = database.prepare(`
        INSERT INTO users (first_name, last_name, email, wilaya, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(firstName, lastName, email, wilaya, salt.toString("hex"), passwordHash.toString("hex"), new Date().toISOString());
      issueSession(response, Number(result.lastInsertRowid));
      return json(response, 201, { user: publicUser(statements.userById.get(Number(result.lastInsertRowid))) });
    } catch (error) {
      if (/UNIQUE constraint failed/i.test(error.message)) {
        return fail(response, 409, "هذا البريد الإلكتروني مسجل بالفعل.");
      }
      throw error;
    }
  }
  if (method === "POST" && route === "/api/auth/login") {
    if (loginIsLimited(request)) return fail(response, 429, "محاولات كثيرة. انتظر 15 دقيقة ثم أعد المحاولة.");
    const body = await readJson(request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const account = statements.userByEmail.get(email);
    const salt = account ? Buffer.from(account.password_salt, "hex") : Buffer.alloc(16);
    const expected = account ? Buffer.from(account.password_hash, "hex") : Buffer.alloc(64);
    const actual = Buffer.from(await scrypt(password.slice(0, 128), salt, 64));
    if (!account || actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      recordLoginFailure(request);
      return fail(response, 401, "البريد الإلكتروني أو كلمة المرور غير صحيحة.");
    }
    loginAttempts.delete(request.socket.remoteAddress || "unknown");
    issueSession(response, Number(account.id));
    return json(response, 200, { user: publicUser(account) });
  }
  if (method === "POST" && route === "/api/auth/logout") {
    const cookies = (request.headers.cookie || "").split(";").map((part) => part.trim());
    const sessionCookie = cookies.find((part) => part.startsWith("session="));
    if (sessionCookie) {
      const token = sessionCookie.slice("session=".length);
      if (/^[a-f0-9]{64}$/.test(token)) {
        database.prepare("DELETE FROM sessions WHERE token_hash = ?")
          .run(createHash("sha256").update(token).digest("hex"));
      }
    }
    clearSessionCookie(response);
    return json(response, 200, { ok: true });
  }
  if (method === "POST" && route === "/api/auth/migrate-password") {
    return fail(response, 400, "استعادة الحسابات القديمة غير متاحة في هذا الخادم.");
  }
  if (method === "POST" && route === "/api/services") {
    if (!requireUser(user, response)) return;
    const body = await readJson(request);
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const category = typeof body.category === "string" ? body.category : "";
    const area = typeof body.area === "string" ? body.area.trim() : "";
    const description = typeof body.description === "string" ? body.description.trim() : "";
    const price = Number(body.price);
    const categories = new Set(["design", "programming", "writing", "marketing", "video", "business"]);
    if (!title || title.length > 100 || !categories.has(category) || !area || area.length > 60 ||
        !Number.isSafeInteger(price) || price < 1 || price > 100000000 ||
        description.length < 20 || description.length > 3000) {
      return fail(response, 400, "تحقق من عنوان الخدمة وتصنيفها وولايتها وسعرها ووصفها.");
    }
    const id = randomBytes(16).toString("hex");
    database.prepare(`
      INSERT INTO services (id, owner_id, title, category, area, price, description, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, user.id, title, category, area, price, description, new Date().toISOString());
    return json(response, 201, { id });
  }
  if (method === "DELETE" && route.startsWith("/api/services/")) {
    if (!requireUser(user, response)) return;
    const id = decodeURIComponent(route.slice("/api/services/".length));
    const service = statements.serviceById.get(id);
    if (!service) return fail(response, 404, "لم نعثر على الخدمة.");
    if (Number(service.owner_id) !== Number(user.id)) return fail(response, 403, "لا يمكنك حذف خدمة مستخدم آخر.");
    database.prepare("DELETE FROM services WHERE id = ?").run(id);
    response.writeHead(204, { "Cache-Control": "no-store" });
    return response.end();
  }
  if (method === "POST" && route === "/api/conversations") {
    if (!requireUser(user, response)) return;
    const body = await readJson(request);
    const service = statements.serviceById.get(String(body.serviceId || ""));
    if (!service) return fail(response, 404, "لم نعثر على الخدمة.");
    if (Number(service.owner_id) === Number(user.id)) return fail(response, 400, "لا يمكنك بدء محادثة مع نفسك.");
    let conversation = database.prepare(
      "SELECT * FROM conversations WHERE service_id = ? AND requester_id = ?"
    ).get(service.id, user.id);
    if (!conversation) {
      const id = randomBytes(16).toString("hex");
      const now = new Date().toISOString();
      database.prepare(`
        INSERT INTO conversations (id, service_id, requester_id, updated_at) VALUES (?, ?, ?, ?)
      `).run(id, service.id, user.id, now);
      conversation = statements.conversationById.get(id);
    }
    return json(response, 200, {
      conversation: {
        id: conversation.id,
        serviceId: conversation.service_id,
        participants: [Number(conversation.requester_id), Number(service.owner_id)],
        messages: statements.conversationMessages.all(conversation.id).map((message) => ({
          id: Number(message.id),
          sender: Number(message.sender_id),
          text: message.text,
          createdAt: message.created_at
        }))
      }
    });
  }
  if (method === "POST" && route === "/api/messages") {
    if (!requireUser(user, response)) return;
    const body = await readJson(request);
    const conversationId = typeof body.conversationId === "string" ? body.conversationId : "";
    const text = typeof body.text === "string" ? body.text.trim() : "";
    if (!text || text.length > 1000) return fail(response, 400, "يجب أن تكون الرسالة بين حرف واحد و1000 حرف.");
    const result = getConversationForUser(conversationId, user.id);
    if (!result) return fail(response, 404, "لم نعثر على محادثة تخص حسابك.");
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO messages (conversation_id, sender_id, text, created_at) VALUES (?, ?, ?, ?)
    `).run(conversationId, user.id, text, now);
    database.prepare("UPDATE conversations SET updated_at = ? WHERE id = ?").run(now, conversationId);
    return json(response, 201, { ok: true });
  }
  const profileMatch = route.match(/^\/api\/accounts\/(\d+)\/profile$/);
  if (method === "GET" && profileMatch) {
    const accountId = Number(profileMatch[1]);
    const account = statements.userById.get(accountId);
    if (!account) return fail(response, 404, "لم نعثر على الحساب.");
    const summary = database.prepare(
      "SELECT AVG(rating) AS average, COUNT(*) AS count FROM reviews WHERE provider_id = ?"
    ).get(accountId);
    const reviews = database.prepare(`
      SELECT reviews.*, users.first_name, users.last_name
      FROM reviews JOIN users ON users.id = reviews.reviewer_id
      WHERE reviews.provider_id = ? ORDER BY reviews.updated_at DESC
    `).all(accountId).map((review) => ({
      rating: Number(review.rating),
      comment: review.comment,
      reviewerName: `${review.first_name} ${review.last_name}`,
      createdAt: review.created_at,
      updatedAt: review.updated_at
    }));
    const ownReview = user ? database.prepare(
      "SELECT rating, comment FROM reviews WHERE provider_id = ? AND reviewer_id = ?"
    ).get(accountId, user.id) : null;
    const canReview = Boolean(user && Number(user.id) !== accountId &&
      database.prepare(`
        SELECT 1 FROM conversations
        JOIN services ON services.id = conversations.service_id
        JOIN messages ON messages.conversation_id = conversations.id
        WHERE (conversations.requester_id = ? AND services.owner_id = ?)
           OR (conversations.requester_id = ? AND services.owner_id = ?)
        LIMIT 1
      `).get(user.id, accountId, accountId, user.id));
    return json(response, 200, {
      account: publicAccount(account),
      rating: { average: summary.average === null ? null : Number(summary.average), count: Number(summary.count) },
      reviews,
      canReview,
      ownReview: ownReview ? { rating: Number(ownReview.rating), comment: ownReview.comment } : null
    });
  }
  const reviewMatch = route.match(/^\/api\/accounts\/(\d+)\/reviews$/);
  if (method === "POST" && reviewMatch) {
    if (!requireUser(user, response)) return;
    const providerId = Number(reviewMatch[1]);
    if (providerId === Number(user.id) || !statements.userById.get(providerId)) {
      return fail(response, 404, "لا يمكن تقييم هذا الحساب.");
    }
    const body = await readJson(request);
    const rating = Number(body.rating);
    const comment = typeof body.comment === "string" ? body.comment.trim() : "";
    if (!Number.isInteger(rating) || rating < 1 || rating > 5 || comment.length < 5 || comment.length > 1000) {
      return fail(response, 400, "تحقق من التقييم والتعليق.");
    }
    const canReview = database.prepare(`
      SELECT 1 FROM conversations
      JOIN services ON services.id = conversations.service_id
      JOIN messages ON messages.conversation_id = conversations.id
      WHERE (conversations.requester_id = ? AND services.owner_id = ?)
         OR (conversations.requester_id = ? AND services.owner_id = ?)
      LIMIT 1
    `).get(user.id, providerId, providerId, user.id);
    if (!canReview) return fail(response, 403, "يتاح التقييم بعد تبادل الرسائل مع مقدم الخدمة.");
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO reviews (provider_id, reviewer_id, rating, comment, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider_id, reviewer_id) DO UPDATE SET
        rating = excluded.rating, comment = excluded.comment, updated_at = excluded.updated_at
    `).run(providerId, user.id, rating, comment, now, now);
    return json(response, 200, { ok: true });
  }
  return fail(response, 404, "المسار المطلوب غير موجود.");
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) {
      return await handleApi(request, response, url);
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return fail(response, 405, "الطريقة غير مدعومة.");
    }
    if (url.pathname !== "/" && url.pathname !== "/index.html") {
      return fail(response, 404, "الصفحة غير موجودة.");
    }
    const page = await readFile(path.join(root, "index.html"));
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      "X-Content-Type-Options": "nosniff"
    });
    return response.end(request.method === "HEAD" ? undefined : page);
  } catch (error) {
    console.error("Request failed:", error);
    if (!response.headersSent) {
      return fail(response, error.status || 500, error.status ? error.message : "حدث خطأ داخلي في الخادم.");
    }
    response.destroy();
  }
});

statements.deleteExpiredSessions.run(Date.now());
statements.deleteExpiredAdminSessions.run(Date.now());
server.listen(port, host, () => {
  console.log(`KHDEMLI server: http://${host}:${port}`);
  console.log(`SQLite database: ${path.join(dataDirectory, "khdemli.sqlite")}`);
});

function closeServer() {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on("SIGINT", closeServer);
process.on("SIGTERM", closeServer);
