require("dotenv").config(); // Load .env variables

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = process.env.JWT_SECRET || "fallback_secret_key";

// MySQL connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Helper query
function query(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
}

// Email transporter (dotenv)
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Email templates
const verificationEmail = (username, token) => `
<div style="background:#111; padding:30px; font-family:Arial; color:#fff;">
  <div style="max-width:600px; margin:auto; background:#1a1a1a; padding:25px; border-radius:8px;">
    <h2 style="color:#ff3b3b;">Welcome to SMR Portal, ${username}!</h2>
    <p>Click below to verify your account:</p>
    <a href="http://localhost:5500/frontend/verify.html?token=${token}"
       style="background:#ff3b3b;color:#fff;padding:12px 25px;text-decoration:none;border-radius:6px;">
       Verify Account
    </a>
  </div>
</div>
`;

const resetPasswordEmail = (username, token) => `
<div style="background:#111; padding:30px; font-family:Arial; color:#fff;">
  <div style="max-width:600px; margin:auto; background:#1a1a1a; padding:25px; border-radius:8px;">
    <h2 style="color:#ff3b3b;">Password Reset</h2>
    <p>Hello ${username}, click below to reset your password:</p>
    <a href="http://localhost:5500/frontend/reset.html?token=${token}"
       style="background:#ff3b3b;color:#fff;padding:12px 25px;text-decoration:none;border-radius:6px;">
       Reset Password
    </a>
  </div>
</div>
`;

// Middleware: JWT auth
function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ message: "No token" });

    const token = header.split(" ")[1];
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(401).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
}

// Middleware: Admin only
function adminOnly(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Admin only" });
    }
    next();
}

/* -------------------------
   REGISTER
-------------------------- */
app.post("/api/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
        return res.status(400).json({ message: "Missing fields" });

    try {
        const hashed = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString("hex");

        await query(
            "INSERT INTO users (username, email, password, verification_token) VALUES (?, ?, ?, ?)",
            [username, email, hashed, token]
        );

        await transporter.sendMail({
            from: "SMR Labs",
            to: email,
            subject: "Verify your SMR Labs account",
            html: verificationEmail(username, token)
        });

        res.json({ message: "Registration successful. Check your email." });

    } catch (err) {
        if (err.code === "ER_DUP_ENTRY")
            return res.status(400).json({ message: "User or email already exists" });

        console.error(err);
        res.status(500).json({ message: "Database error" });
    }
});

/* -------------------------
   EMAIL VERIFICATION
-------------------------- */
app.get("/api/verify/:token", async (req, res) => {
    const { token } = req.params;

    const rows = await query("SELECT * FROM users WHERE verification_token = ?", [token]);
    if (rows.length === 0) return res.status(400).send("Invalid verification link");

    await query("UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?", [
        rows[0].id
    ]);

    res.send("Your account has been verified!");
});

/* -------------------------
   LOGIN
-------------------------- */
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ error: "Missing fields" });

    try {
        const users = await query("SELECT * FROM users WHERE email = ?", [email]);

        if (users.length === 0)
            return res.status(401).json({ error: "User not found" });

        const user = users[0];

        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ error: "Wrong password" });

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            email: user.email,
            role: user.role,
            token
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});

/* -------------------------
   PASSWORD RESET
-------------------------- */
app.post("/api/request-reset", async (req, res) => {
    const { email } = req.body;

    const rows = await query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
        return res.json({ message: "If this email exists, a reset link was sent" });

    const user = rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 3600000);

    await query(
        "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
        [user.id, token, expires]
    );

    await transporter.sendMail({
        from: "SMR Labs",
        to: email,
        subject: "Reset your password",
        html: resetPasswordEmail(user.username, token)
    });

    res.json({ message: "Reset link sent" });
});

app.post("/api/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    const rows = await query(
        "SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()",
        [token]
    );

    if (rows.length === 0)
        return res.status(400).json({ message: "Invalid or expired token" });

    const reset = rows[0];
    const hashed = await bcrypt.hash(password, 10);

    await query("UPDATE users SET password = ? WHERE id = ?", [hashed, reset.user_id]);
    await query("DELETE FROM password_resets WHERE id = ?", [reset.id]);

    res.json({ message: "Password updated successfully" });
});

/* -------------------------
   ROLE REQUESTS
-------------------------- */
app.post("/api/request-role", auth, async (req, res) => {
    const { message } = req.body;

    await query(
        "INSERT INTO role_requests (user_id, message) VALUES (?, ?)",
        [req.user.id, message]
    );

    res.json({ message: "Request submitted" });
});

app.get("/api/admin/role-requests", auth, adminOnly, async (req, res) => {
    const rows = await query(`
        SELECT r.id, r.message, r.status, r.created_at, u.username
        FROM role_requests r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    `);

    res.json(rows);
});

app.post("/api/admin/role-requests/:id/approve", auth, adminOnly, async (req, res) => {
    const { id } = req.params;

    const rows = await query("SELECT * FROM role_requests WHERE id = ?", [id]);
    if (rows.length === 0) return res.status(404).json({ message: "Not found" });

    const reqData = rows[0];

    await query("UPDATE users SET role = 'SMR Team' WHERE id = ?", [reqData.user_id]);
    await query("UPDATE role_requests SET status = 'approved' WHERE id = ?", [id]);

    res.json({ message: "Request approved" });
});

app.post("/api/admin/role-requests/:id/reject", auth, adminOnly, async (req, res) => {
    const { id } = req.params;

    await query("UPDATE role_requests SET status = 'rejected' WHERE id = ?", [id]);

    res.json({ message: "Request rejected" });
});

/* -------------------------
   ADMIN USERS
-------------------------- */
app.get("/api/users", auth, adminOnly, async (req, res) => {
    const users = await query(
        "SELECT id, username, email, role, verified, created_at FROM users ORDER BY created_at DESC"
    );
    res.json(users);
});

app.put("/api/users/:id/role", auth, adminOnly, async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    await query("UPDATE users SET role = ? WHERE id = ?", [role, id]);
    res.json({ message: "Role updated" });
});

app.delete("/api/users/:id", auth, adminOnly, async (req, res) => {
    const { id } = req.params;

    await query("DELETE FROM users WHERE id = ?", [id]);
    res.json({ message: "User deleted" });
});

/* -------------------------
   SEMINARS
-------------------------- */
app.get("/api/seminars", async (req, res) => {
    const rows = await query("SELECT * FROM seminars ORDER BY date DESC");
    res.json(rows);
});

app.post("/api/seminars", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Forbidden" });

    const { title, description, date } = req.body;

    await query(
        "INSERT INTO seminars (title, description, date) VALUES (?, ?, ?)",
        [title, description, date]
    );

    res.json({ message: "Seminar created" });
});

app.delete("/api/seminars/:id", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Forbidden" });

    await query("DELETE FROM seminars WHERE id = ?", [req.params.id]);
    res.json({ message: "Seminar deleted" });
});

/* -------------------------
   VOLUNTEERING
-------------------------- */
app.get("/api/volunteering", async (req, res) => {
    const rows = await query("SELECT * FROM volunteering ORDER BY date DESC");
    res.json(rows);
});

app.post("/api/volunteering", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Forbidden" });

    const { title, description, location, date } = req.body;

    await query(
        "INSERT INTO volunteering (title, description, location, date) VALUES (?, ?, ?, ?)",
        [title, description, location, date]
    );

    res.json({ message: "Volunteering created" });
});

app.delete("/api/volunteering/:id", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Forbidden" });

    await query("DELETE FROM volunteering WHERE id = ?", [req.params.id]);
    res.json({ message: "Volunteering deleted" });
});

/* -------------------------
   LIBRARY (SMR Team + Admin ONLY)
-------------------------- */
app.get("/api/library", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Access denied" });

    const rows = await query("SELECT * FROM library_items ORDER BY created_at DESC");
    res.json(rows);
});

app.post("/api/library", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Access denied" });

    const { title, type, url } = req.body;

    await query(
        "INSERT INTO library_items (title, type, url) VALUES (?, ?, ?)",
        [title, type, url]
    );

    res.json({ message: "Library item created" });
});

app.delete("/api/library/:id", auth, async (req, res) => {
    if (req.user.role !== "SMR Team" && req.user.role !== "admin")
        return res.status(403).json({ message: "Access denied" });

    await query("DELETE FROM library_items WHERE id = ?", [req.params.id]);
    res.json({ message: "Library item deleted" });
});

/* -------------------------
   START SERVER
-------------------------- */
const PORT = 3000;

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
