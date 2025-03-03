const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Test database connection
pool.connect((err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to PostgreSQL');
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Signup endpoint
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
      [email, hashedPassword]
    );
    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.status(201).json({ token });
  } catch (error) {
    if (error.code === '23505') { // Duplicate email
      res.status(400).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Save weight log
app.post('/weights', authenticateToken, async (req, res) => {
  const { date, am_weight, pm_weight, note } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO weight_logs (user_id, date, am_weight, pm_weight, note) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, date, am_weight || null, pm_weight || null, note || '']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Weight save error:', error);
    res.status(500).json({ error: 'Failed to save weight' });
  }
});

// Get weight logs
app.get('/weights', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM weight_logs WHERE user_id = $1 ORDER BY date DESC', [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Weight fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch weights' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));