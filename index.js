const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

const nodemailer = require('nodemailer');

// Email setup
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Store OTPs temporarily (in-memory, use Redis in production)
const otps = new Map();

// Middleware to check device
const checkDevice = async (req, res, next) => {
  const deviceId = req.headers['x-device-id'];
  if (!deviceId) return res.status(400).json({ error: 'Device ID required' });

  try {
    const deviceResult = await pool.query(
      'SELECT * FROM devices WHERE user_id = $1 AND device_id = $2',
      [req.user.id, deviceId]
    );

    if (deviceResult.rows.length === 0) {
      // New device - send OTP
      const otp = generateOTP();
      otps.set(`${req.user.id}-${deviceId}`, otp);

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: req.user.email,
        subject: 'WeightTracker - Verify Your Device',
        text: `Your OTP is: ${otp}`,
      });

      return res.status(403).json({ error: 'New device detected', needsOtp: true });
    }

    // Update last_used
    await pool.query(
      'UPDATE devices SET last_used = CURRENT_TIMESTAMP WHERE user_id = $1 AND device_id = $2',
      [req.user.id, deviceId]
    );

    next();
  } catch (error) {
    console.error('Device check error:', error);
    res.status(500).json({ error: 'Device verification failed' });
  }
};

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
  const deviceId = req.headers['x-device-id'];
  if (!deviceId) return res.status(400).json({ error: 'Device ID required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
      [email, hashedPassword]
    );
    const userId = result.rows[0].id;
    const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Add device
    await pool.query(
      'INSERT INTO devices (user_id, device_id) VALUES ($1, $2)',
      [userId, deviceId]
    );

    res.status(201).json({ token });
  } catch (error) {
    if (error.code === '23505') {
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
    const token = jwt.sign({ id: user.id, email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    // Attach user to request for checkDevice
    req.user = { id: user.id, email };
    await checkDevice(req, res, async () => {
      res.json({ token });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP endpoint
app.post('/verify-otp', authenticateToken, async (req, res) => {
  const { otp, deviceId } = req.body;
  if (!deviceId || !otp) return res.status(400).json({ error: 'OTP and device ID required' });

  const key = `${req.user.id}-${deviceId}`;
  const storedOtp = otps.get(key);

  if (storedOtp && storedOtp === otp) {
    // OTP correct - add device
    await pool.query(
      'INSERT INTO devices (user_id, device_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, deviceId]
    );
    otps.delete(key);
    res.json({ message: 'Device verified' });
  } else {
    res.status(400).json({ error: 'Invalid OTP' });
  }
});

// GET latest weight
app.get('/latest-weight', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT am_weight, pm_weight 
       FROM weight_logs 
       WHERE user_id = $1 
       AND (am_weight IS NOT NULL OR pm_weight IS NOT NULL) 
       ORDER BY date DESC, created_at DESC 
       LIMIT 1`,
      [req.user.id]
    );
    if (result.rows.length > 0) {
      const { am_weight, pm_weight } = result.rows[0];
      res.json({ latest: am_weight || pm_weight });
    } else {
      res.json({ latest: null });
    }
  } catch (error) {
    console.error('Latest weight fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch latest weight' });
  }
});

// GET weight log
app.get('/weights', authenticateToken, async (req, res) => {
  const { date } = req.query; // Optional date param (YYYY-MM-DD)
  try {
    if (date) {
      const result = await pool.query(
        'SELECT * FROM weight_logs WHERE user_id = $1 AND date = $2',
        [req.user.id, date]
      );
      res.json(result.rows[0] || null);
    } else {
      const result = await pool.query(
        'SELECT * FROM weight_logs WHERE user_id = $1 ORDER BY date DESC',
        [req.user.id]
      );
      res.json(result.rows);
    }
  } catch (error) {
    console.error('Weight fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch weights' });
  }
});

// Save or update weight log for a specific date
app.post('/weights', authenticateToken, async (req, res) => {
  const { date, am_weight, pm_weight, note } = req.body;
  try {
    const existing = await pool.query(
      'SELECT * FROM weight_logs WHERE user_id = $1 AND date = $2',
      [req.user.id, date]
    );
    if (existing.rows.length > 0) {
      // Update existing entry
      const result = await pool.query(
        `UPDATE weight_logs 
         SET am_weight = COALESCE($1, am_weight), 
             pm_weight = COALESCE($2, pm_weight), 
             note = COALESCE($3, note), 
             created_at = CURRENT_TIMESTAMP 
         WHERE user_id = $4 AND date = $5 
         RETURNING *`,
        [am_weight, pm_weight, note, req.user.id, date]
      );
      res.json(result.rows[0]);
    } else {
      // Insert new entry
      const result = await pool.query(
        'INSERT INTO weight_logs (user_id, date, am_weight, pm_weight, note) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [req.user.id, date, am_weight || null, pm_weight || null, note || '']
      );
      res.json(result.rows[0]);
    }
  } catch (error) {
    console.error('Weight save error:', error);
    res.status(500).json({ error: 'Failed to save weight' });
  }
});

// Calculate averages
app.get('/averages', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(new Date().setDate(new Date().getDate() - 1)).toISOString().split('T')[0];
    const sevenDaysAgo = new Date(new Date().setDate(new Date().getDate() - 8)).toISOString().split('T')[0];

    // Daily averages query
    const getDailyAverageQuery = `
      SELECT 
        date,
        CASE 
          WHEN am_weight IS NOT NULL AND pm_weight IS NOT NULL THEN (am_weight + pm_weight) / 2
          WHEN am_weight IS NOT NULL THEN am_weight
          WHEN pm_weight IS NOT NULL THEN pm_weight
          ELSE NULL
        END as daily_avg
      FROM weight_logs
      WHERE user_id = $1 AND date <= $2
      ORDER BY date DESC
    `;

    const dailyResults = await pool.query(getDailyAverageQuery, [userId, today]);
    const dailyAverages = dailyResults.rows.filter(row => row.daily_avg !== null);

    // Yesterday's average
    const yesterdayEntry = dailyAverages.find(row => row.date === yesterday);
    const yesterdayAvg = yesterdayEntry ? parseFloat(yesterdayEntry.daily_avg.toFixed(2)) : null;

    // Previous week's average (7 days, excluding today)
    const previousWeek = dailyAverages.filter(row => row.date > sevenDaysAgo && row.date < today);
    const previousWeekAvg = previousWeek.length === 7
      ? parseFloat((previousWeek.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / 7).toFixed(2))
      : null;

    // Existing averages
    const oneDayAvg = dailyAverages.find(row => row.date === today) ? parseFloat(dailyAverages.find(row => row.date === today).daily_avg.toFixed(2)) : null;
    const multiDayAverages = {};
    for (let days = 2; days <= 6; days++) {
      const recentDays = dailyAverages.slice(0, days);
      if (recentDays.length === days) {
        const sum = recentDays.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0);
        multiDayAverages[`${days}DayAvg`] = parseFloat((sum / days).toFixed(2));
      } else {
        multiDayAverages[`${days}DayAvg`] = null;
      }
    }
    const oneWeek = dailyAverages.slice(0, 7);
    const oneWeekAvg = oneWeek.length === 7 ? parseFloat((oneWeek.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / 7).toFixed(2)) : null;
    const oneMonth = dailyAverages.slice(0, 28);
    const oneMonthAvg = oneMonth.length === 28 ? parseFloat((oneMonth.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / 28).toFixed(2)) : null;
    const threeMonths = dailyAverages.slice(0, 90);
    const threeMonthAvg = threeMonths.length >= 90 ? parseFloat((threeMonths.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / threeMonths.length).toFixed(2)) : null;
    const oneYear = dailyAverages.slice(0, 365);
    const oneYearAvg = oneYear.length >= 365 ? parseFloat((oneYear.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / oneYear.length).toFixed(2)) : null;

    res.json({
      yesterdayAvg,
      previousWeekAvg,
      oneDayAvg,
      twoDayAvg: multiDayAverages['2DayAvg'],
      threeDayAvg: multiDayAverages['3DayAvg'],
      fourDayAvg: multiDayAverages['4DayAvg'],
      fiveDayAvg: multiDayAverages['5DayAvg'],
      sixDayAvg: multiDayAverages['6DayAvg'],
      oneWeekAvg,
      oneMonthAvg,
      threeMonthAvg,
      oneYearAvg,
    });
  } catch (error) {
    console.error('Averages error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to calculate averages' });
  }
});

// Set or update goal
app.post('/goals', authenticateToken, async (req, res) => {
  const { target_weight, goal_type } = req.body;
  if (!target_weight || !['gain', 'lose'].includes(goal_type)) {
    return res.status(400).json({ error: 'Invalid target weight or goal type' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO goals (user_id, target_weight, goal_type) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (user_id) 
       DO UPDATE SET target_weight = $2, goal_type = $3, created_at = CURRENT_TIMESTAMP 
       RETURNING *`,
      [req.user.id, target_weight, goal_type]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Goal set error:', error);
    res.status(500).json({ error: 'Failed to set goal' });
  }
});

// Get goal
app.get('/goals', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM goals WHERE user_id = $1', [req.user.id]);
    res.json(result.rows[0] || null);
  } catch (error) {
    console.error('Goal fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch goal' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));