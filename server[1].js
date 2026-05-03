// ============================================================
//  server.js — Job & Internship Scam Detection System
//  Stack: Node.js + Express + MySQL2
// ============================================================

const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'scam_detect_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));   // serves frontend/index.html

// ─── DB Connection Pool ───────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASS     || '',
  database: process.env.DB_NAME     || 'scam_detection_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── Auth Middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

// ============================================================
//  AUTH ROUTES
// ============================================================

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { full_name, email, password, phone, college } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required' });

  const hash = await bcrypt.hash(password, 10);
  const [result] = await pool.query(
    'INSERT INTO Users (full_name, email, password_hash, phone, college) VALUES (?,?,?,?,?)',
    [full_name, email, hash, phone || null, college || null]
  );
  res.status(201).json({ message: 'Registered successfully', user_id: result.insertId });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const [[user]] = await pool.query('SELECT * FROM Users WHERE email = ?', [email]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });

  const token = jwt.sign({ user_id: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, role: user.role, full_name: user.full_name });
});

// ============================================================
//  JOB POSTINGS
// ============================================================

// GET /api/jobs  — list all active jobs with company info
app.get('/api/jobs', async (req, res) => {
  const { status, type, search } = req.query;
  let sql = `
    SELECT jp.*, c.company_name, c.is_verified,
           COUNT(DISTINCT r.report_id) AS report_count,
           ROUND(AVG(rv.rating), 1)    AS avg_rating
    FROM Job_Postings jp
    JOIN Companies c ON jp.company_id = c.company_id
    LEFT JOIN Reports r  ON jp.job_id = r.job_id
    LEFT JOIN Reviews rv ON jp.job_id = rv.job_id
    WHERE 1=1
  `;
  const params = [];

  if (status) { sql += ' AND jp.status = ?'; params.push(status); }
  if (type)   { sql += ' AND jp.job_type = ?'; params.push(type); }
  if (search) { sql += ' AND (jp.title LIKE ? OR c.company_name LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

  sql += ' GROUP BY jp.job_id ORDER BY jp.created_at DESC';
  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

// GET /api/jobs/:id
app.get('/api/jobs/:id', async (req, res) => {
  const [[job]] = await pool.query(`
    SELECT jp.*, c.company_name, c.website, c.is_verified
    FROM Job_Postings jp
    JOIN Companies c ON jp.company_id = c.company_id
    WHERE jp.job_id = ?`, [req.params.id]);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
});

// POST /api/jobs  (admin only)
app.post('/api/jobs', authMiddleware, adminOnly, async (req, res) => {
  const { title, description, company_id, job_type, location, salary_range, application_url, deadline } = req.body;
  const [result] = await pool.query(
    `INSERT INTO Job_Postings (title, description, company_id, posted_by, job_type, location, salary_range, application_url, deadline)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [title, description, company_id, req.user.user_id, job_type, location, salary_range, application_url, deadline]
  );
  res.status(201).json({ job_id: result.insertId });
});

// PATCH /api/jobs/:id/status  (admin only)
app.patch('/api/jobs/:id/status', authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;
  await pool.query('UPDATE Job_Postings SET status = ? WHERE job_id = ?', [status, req.params.id]);
  res.json({ message: 'Status updated' });
});

// ============================================================
//  COMPANIES
// ============================================================

app.get('/api/companies', async (req, res) => {
  const [rows] = await pool.query(`
    SELECT c.*,
           COUNT(DISTINCT jp.job_id) AS total_jobs,
           COUNT(DISTINCT r.report_id) AS total_reports,
           ROUND(AVG(rv.rating), 1) AS avg_rating
    FROM Companies c
    LEFT JOIN Job_Postings jp ON c.company_id = jp.company_id
    LEFT JOIN Reports r  ON c.company_id = r.company_id
    LEFT JOIN Reviews rv ON c.company_id = rv.company_id
    GROUP BY c.company_id
    ORDER BY c.created_at DESC`);
  res.json(rows);
});

app.post('/api/companies', authMiddleware, adminOnly, async (req, res) => {
  const { company_name, website, contact_email, contact_phone, industry, address } = req.body;
  const [result] = await pool.query(
    `INSERT INTO Companies (company_name, website, contact_email, contact_phone, industry, address, added_by)
     VALUES (?,?,?,?,?,?,?)`,
    [company_name, website, contact_email, contact_phone, industry, address, req.user.user_id]
  );
  res.status(201).json({ company_id: result.insertId });
});

// ============================================================
//  REPORTS
// ============================================================

// POST /api/reports  (logged-in students)
app.post('/api/reports', authMiddleware, async (req, res) => {
  const { job_id, company_id, reason, description, evidence_url } = req.body;
  if (!job_id && !company_id)
    return res.status(400).json({ error: 'Provide either job_id or company_id' });

  const [result] = await pool.query(
    `INSERT INTO Reports (job_id, company_id, reported_by, reason, description, evidence_url)
     VALUES (?,?,?,?,?,?)`,
    [job_id || null, company_id || null, req.user.user_id, reason, description, evidence_url || null]
  );
  res.status(201).json({ report_id: result.insertId, message: 'Report submitted. Thank you!' });
});

// GET /api/reports  (admin only)
app.get('/api/reports', authMiddleware, adminOnly, async (req, res) => {
  const [rows] = await pool.query(`
    SELECT r.*, u.full_name AS reporter,
           jp.title AS job_title, c.company_name
    FROM Reports r
    JOIN Users u ON r.reported_by = u.user_id
    LEFT JOIN Job_Postings jp ON r.job_id = jp.job_id
    LEFT JOIN Companies c ON r.company_id = c.company_id
    ORDER BY r.created_at DESC`);
  res.json(rows);
});

// PATCH /api/reports/:id/status  (admin)
app.patch('/api/reports/:id/status', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('UPDATE Reports SET status = ? WHERE report_id = ?', [req.body.status, req.params.id]);
  res.json({ message: 'Report status updated' });
});

// ============================================================
//  REVIEWS
// ============================================================

app.get('/api/reviews/:type/:id', async (req, res) => {
  const col = req.params.type === 'job' ? 'rv.job_id' : 'rv.company_id';
  const [rows] = await pool.query(`
    SELECT rv.*, u.full_name
    FROM Reviews rv
    JOIN Users u ON rv.reviewed_by = u.user_id
    WHERE ${col} = ?
    ORDER BY rv.created_at DESC`, [req.params.id]);
  res.json(rows);
});

app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { job_id, company_id, rating, title, body, is_anonymous } = req.body;
  if (!job_id && !company_id)
    return res.status(400).json({ error: 'Provide job_id or company_id' });

  const [result] = await pool.query(
    `INSERT INTO Reviews (job_id, company_id, reviewed_by, rating, title, body, is_anonymous)
     VALUES (?,?,?,?,?,?,?)`,
    [job_id || null, company_id || null, req.user.user_id, rating, title, body, is_anonymous || false]
  );
  res.status(201).json({ review_id: result.insertId });
});

// ============================================================
//  VERIFICATION
// ============================================================

app.post('/api/verify', authMiddleware, adminOnly, async (req, res) => {
  const { entity_type, entity_id, status, notes } = req.body;
  const [result] = await pool.query(
    `INSERT INTO Verification (entity_type, entity_id, verified_by, status, notes, verified_at)
     VALUES (?,?,?,?,?, NOW())`,
    [entity_type, entity_id, req.user.user_id, status, notes || null]
  );

  // Also update the source table
  if (entity_type === 'company') {
    const verified = status === 'verified';
    await pool.query('UPDATE Companies SET is_verified = ? WHERE company_id = ?', [verified, entity_id]);
  } else if (entity_type === 'job_posting') {
    const jobStatus = status === 'flagged' ? 'flagged' : status === 'rejected' ? 'removed' : 'active';
    await pool.query('UPDATE Job_Postings SET status = ? WHERE job_id = ?', [jobStatus, entity_id]);
  }
  res.status(201).json({ verification_id: result.insertId });
});

// ============================================================
//  DASHBOARD STATS  (admin)
// ============================================================
app.get('/api/stats', authMiddleware, adminOnly, async (req, res) => {
  const [[jobs]]     = await pool.query('SELECT COUNT(*) AS total FROM Job_Postings');
  const [[flagged]]  = await pool.query("SELECT COUNT(*) AS total FROM Job_Postings WHERE status='flagged'");
  const [[reports]]  = await pool.query("SELECT COUNT(*) AS total FROM Reports WHERE status='pending'");
  const [[companies]]= await pool.query('SELECT COUNT(*) AS total FROM Companies');
  const [[users]]    = await pool.query("SELECT COUNT(*) AS total FROM Users WHERE role='student'");
  res.json({
    total_jobs:        jobs.total,
    flagged_jobs:      flagged.total,
    pending_reports:   reports.total,
    total_companies:   companies.total,
    total_students:    users.total,
  });
});

// ─── Start ────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅  Server running at http://localhost:${PORT}`));
