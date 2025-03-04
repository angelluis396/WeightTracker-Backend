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

// Calculate averages
app.get('/averages', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];

    // Helper: Get daily averages (simplified)
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

    // Fetch daily averages
    const dailyResults = await pool.query(getDailyAverageQuery, [userId, today]);
    const dailyAverages = dailyResults.rows.filter(row => row.daily_avg !== null);

    // Debug: Log raw daily averages
    console.log('Daily Averages:', dailyAverages);

    // 1-Day Average (today)
    const todayEntry = dailyAverages.find(row => row.date === today);
    const oneDayAvg = todayEntry ? parseFloat(todayEntry.daily_avg.toFixed(2)) : null;

    // 2-to-6 Day Averages
    const multiDayAverages = {};
    for (let days = 2; days <= 6; days++) {
      const recentDays = dailyAverages.slice(0, days);
      if (recentDays.length === days) {
        const dailyValues = recentDays.map(row => parseFloat(row.daily_avg));
        console.log(`Calculating ${days}-day average. Values:`, dailyValues);
        const sum = dailyValues.reduce((acc, val) => acc + val, 0);
        console.log(`${days}-day sum:`, sum);
        const avg = sum / days;
        multiDayAverages[`${days}DayAvg`] = parseFloat(avg.toFixed(2));
        console.log(`${days}-day avg:`, multiDayAverages[`${days}DayAvg`]);
      } else {
        multiDayAverages[`${days}DayAvg`] = null;
      }
    }

    // 1-Week Average (7 days)
    const oneWeek = dailyAverages.slice(0, 7);
    const oneWeekAvg = oneWeek.length === 7 ? parseFloat((oneWeek.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / 7).toFixed(2)) : null;

    // 1-Month Average (28 days)
    const oneMonth = dailyAverages.slice(0, 28);
    const oneMonthAvg = oneMonth.length === 28 ? parseFloat((oneMonth.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / 28).toFixed(2)) : null;

    // 3-Month Average (90 days)
    const threeMonths = dailyAverages.slice(0, 90);
    const threeMonthAvg = threeMonths.length >= 90 ? parseFloat((threeMonths.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / threeMonths.length).toFixed(2)) : null;

    // 1-Year Average (365 days)
    const oneYear = dailyAverages.slice(0, 365);
    const oneYearAvg = oneYear.length >= 365 ? parseFloat((oneYear.reduce((acc, row) => acc + parseFloat(row.daily_avg), 0) / oneYear.length).toFixed(2)) : null;

    res.json({
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
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));