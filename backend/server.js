// ============================================================
// SPICE & SOUL RESTAURANT - Backend Server
// Run: node server.js  OR  npm start
// API runs on http://localhost:3001
// ============================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3001;
const JWT_SECRET = 'spice_soul_secret_2024'; // Change in production!

// ── Middleware ──────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname))); // Serve HTML files

// ── Simple File-Based "Database" ────────────────────────────
const DB_FILE = path.join(__dirname, 'db.json');

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], orders: [], reservations: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ── Auth Middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

  const db = readDB();
  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now().toString(),
    name,
    email,
    phone: phone || '',
    password: hashedPassword,
    role: 'customer',
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  writeDB(db);

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const db = readDB();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// GET /api/auth/me  (verify token & get profile)
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role });
});

// ══════════════════════════════════════════════════════════════
// ORDER ROUTES
// ══════════════════════════════════════════════════════════════

// POST /api/orders  (place order)
app.post('/api/orders', authMiddleware, (req, res) => {
  const { items, total } = req.body;
  if (!items || items.length === 0) return res.status(400).json({ error: 'No items in order' });

  const db = readDB();
  const order = {
    id: 'ORD-' + Date.now(),
    userId: req.user.id,
    userName: req.user.name,
    userEmail: req.user.email,
    items,
    total,
    status: 'Pending',
    createdAt: new Date().toISOString()
  };

  db.orders.push(order);
  writeDB(db);
  res.json({ success: true, order });
});

// GET /api/orders  (my orders)
app.get('/api/orders', authMiddleware, (req, res) => {
  const db = readDB();
  const orders = db.orders.filter(o => o.userId === req.user.id).reverse();
  res.json(orders);
});

// GET /api/admin/orders  (all orders - admin)
app.get('/api/admin/orders', adminMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.orders.reverse());
});

// PATCH /api/admin/orders/:id  (update order status - admin)
app.patch('/api/admin/orders/:id', adminMiddleware, (req, res) => {
  const { status } = req.body;
  const db = readDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  order.status = status;
  writeDB(db);
  res.json({ success: true, order });
});

// ══════════════════════════════════════════════════════════════
// RESERVATION ROUTES
// ══════════════════════════════════════════════════════════════

// POST /api/reservations
app.post('/api/reservations', authMiddleware, (req, res) => {
  const { date, time, guests, occasion, name, phone } = req.body;
  if (!date || !time || !guests) return res.status(400).json({ error: 'Date, time, guests required' });

  const db = readDB();
  const reservation = {
    id: 'RES-' + Date.now(),
    userId: req.user.id,
    name: name || req.user.name,
    phone: phone || '',
    date,
    time,
    guests,
    occasion: occasion || 'None',
    status: 'Confirmed',
    createdAt: new Date().toISOString()
  };

  db.reservations.push(reservation);
  writeDB(db);
  res.json({ success: true, reservation });
});

// GET /api/reservations  (my reservations)
app.get('/api/reservations', authMiddleware, (req, res) => {
  const db = readDB();
  const reservations = db.reservations.filter(r => r.userId === req.user.id).reverse();
  res.json(reservations);
});

// GET /api/admin/reservations  (all - admin)
app.get('/api/admin/reservations', adminMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.reservations.reverse());
});

// ══════════════════════════════════════════════════════════════
// ADMIN UTILITY
// ══════════════════════════════════════════════════════════════

// POST /api/admin/create  (create first admin - run once!)
app.post('/api/admin/create', async (req, res) => {
  const { secret, name, email, password } = req.body;
  if (secret !== 'ADMIN_SETUP_2024') return res.status(403).json({ error: 'Wrong secret' });

  const db = readDB();
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = { id: Date.now().toString(), name, email, password: hashedPassword, role: 'admin', phone: '', createdAt: new Date().toISOString() };
  db.users.push(admin);
  writeDB(db);
  res.json({ success: true, message: 'Admin created!' });
});

// GET /api/admin/users  (all users)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const db = readDB();
  const users = db.users.map(({ password, ...u }) => u);
  res.json(users);
});

// ── Start Server ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🍛 Spice & Soul Restaurant Server`);
  console.log(`✅ Running at: http://localhost:${PORT}`);
  console.log(`📋 API Docs: http://localhost:${PORT}/api-docs.html\n`);
});