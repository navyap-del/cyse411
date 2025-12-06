const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcryptjs"); 
const csrf = require("csurf");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

app.use(csrf({ cookie: true }));

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

const sessions = {}; 

function findUser(username) {
  return users.find((u) => u.username === username);
}

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

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

  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });

  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
