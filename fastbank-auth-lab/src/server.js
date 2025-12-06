const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcryptjs"); 
const csrf = require("csurf");

const app = express();
const PORT = 3001;

// Session expiration: 30 minutes
const SESSION_LIFETIME = 30 * 60 * 1000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// Enable CSRF protection using cookies
app.use(csrf({ cookie: true }));

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

//Vulnerable Fake User DB
const users = [
  {
    id: 1,
    username: "student",
    // Secure: bcrypt hash with salt and cost factor 12
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

const sessions = {}; 

function findUser(username) {
  return users.find((u) => u.username === username);
}

// Middleware: Validate session expiration
function requireValidSession(req, res, next) {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];

  // Expired → delete + force logout
  if (session.expiresAt < Date.now()) {
    delete sessions[token];
    return res.status(401).json({ authenticated: false, message: "Session expired" });
  }

  next();
}

//Show Current User
app.get("/api/me", requireValidSession, (req, res) => {
  const token = req.cookies.session;
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);

  res.json({ authenticated: true, username: user.username });
});

//LOGIN ENDPOINT
app.post("/api/login", (req, res) => {
  const { username, password, _csrf } = req.body;
  
  // CSRF validation
  if (!_csrf || _csrf !== req.csrfToken()) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  const user = findUser(username);
  const failResponse = { success: false, message: "Invalid credentials" };

  if (!user) {
    return res.status(401).json(failResponse);
  }

  const passwordMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordMatch) {
    return res.status(401).json(failResponse);
  }

  // Secure: random, high-entropy token
  const token = crypto.randomBytes(32).toString("hex");

  // ADD EXPIRATION
  sessions[token] = { 
    userId: user.id,
    expiresAt: Date.now() + SESSION_LIFETIME
  };

  // Secure cookie settings
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: SESSION_LIFETIME   // Helps Semgrep detect expiration
  });

  res.json({ success: true, token });
});

//Logout Endpoint
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

//Start Server
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
