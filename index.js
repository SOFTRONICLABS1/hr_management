import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import { initDb, get, all, run } from './db.js'

const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173'

const app = express()

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true })
})

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {}
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' })
    }

    const user = await get(
      'SELECT id, username, password_hash, role, employee_id FROM users WHERE username = ?',
      [username],
    )
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const token = jwt.sign(
      { sub: user.id, username: user.username, role: user.role, employee_id: user.employee_id || null },
      JWT_SECRET,
      { expiresIn: '2h' },
    )

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, employee_id: user.employee_id || null },
    })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if (!token) return res.status(401).json({ message: 'Missing token' })

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    return next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' })
  }
}

app.get('/auth/me', authMiddleware, (req, res) => {
  res.json({
    user: {
      id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      employee_id: req.user.employee_id || null,
    },
  })
})

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ message: 'Forbidden' })
    return next()
  }
}

// Employees CRUD
app.get('/employees', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all('SELECT * FROM employees ORDER BY id DESC')
  res.json(rows)
})

app.post('/employees', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, email, role, department, status } = req.body || {}
  if (!name || !email || !role || !department || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO employees (name, email, role, department, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [name, email, role, department, status, now],
  )

  const employee = await get('SELECT * FROM employees WHERE id = ?', [result.lastID])
  res.json(employee)
})

app.put('/employees/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { name, email, role, department, status } = req.body || {}
  if (!name || !email || !role || !department || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  await run(
    'UPDATE employees SET name = ?, email = ?, role = ?, department = ?, status = ? WHERE id = ?',
    [name, email, role, department, status, id],
  )

  const employee = await get('SELECT * FROM employees WHERE id = ?', [id])
  res.json(employee)
})

app.delete('/employees/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  await run('DELETE FROM employees WHERE id = ?', [id])
  res.json({ ok: true })
})

// Attendance CRUD
app.get('/attendance', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all(
    `SELECT attendance.*, employees.name as employee_name
     FROM attendance
     JOIN employees ON attendance.employee_id = employees.id
     ORDER BY attendance.id DESC`,
  )
  res.json(rows)
})

app.post('/attendance', authMiddleware, requireRole('admin'), async (req, res) => {
  const { employee_id, date, status } = req.body || {}
  if (!employee_id || !date || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO attendance (employee_id, date, status, created_at) VALUES (?, ?, ?, ?)',
    [employee_id, date, status, now],
  )

  const entry = await get('SELECT * FROM attendance WHERE id = ?', [result.lastID])
  res.json(entry)
})

app.put('/attendance/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { employee_id, date, status } = req.body || {}
  if (!employee_id || !date || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  await run(
    'UPDATE attendance SET employee_id = ?, date = ?, status = ? WHERE id = ?',
    [employee_id, date, status, id],
  )

  const entry = await get('SELECT * FROM attendance WHERE id = ?', [id])
  res.json(entry)
})

app.delete('/attendance/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  await run('DELETE FROM attendance WHERE id = ?', [id])
  res.json({ ok: true })
})

// Leave Requests CRUD
app.get('/leave', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all(
    `SELECT leave_requests.*, employees.name as employee_name
     FROM leave_requests
     JOIN employees ON leave_requests.employee_id = employees.id
     ORDER BY leave_requests.id DESC`,
  )
  res.json(rows)
})

app.post('/leave', authMiddleware, requireRole('admin'), async (req, res) => {
  const { employee_id, start_date, end_date, reason, status } = req.body || {}
  if (!employee_id || !start_date || !end_date || !reason || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO leave_requests (employee_id, start_date, end_date, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [employee_id, start_date, end_date, reason, status, now],
  )

  const entry = await get('SELECT * FROM leave_requests WHERE id = ?', [result.lastID])
  res.json(entry)
})

app.put('/leave/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { employee_id, start_date, end_date, reason, status } = req.body || {}
  if (!employee_id || !start_date || !end_date || !reason || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  await run(
    'UPDATE leave_requests SET employee_id = ?, start_date = ?, end_date = ?, reason = ?, status = ? WHERE id = ?',
    [employee_id, start_date, end_date, reason, status, id],
  )

  const entry = await get('SELECT * FROM leave_requests WHERE id = ?', [id])
  res.json(entry)
})

app.delete('/leave/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  await run('DELETE FROM leave_requests WHERE id = ?', [id])
  res.json({ ok: true })
})

// Settings
app.get('/settings', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all('SELECT key, value FROM settings')
  const settings = rows.reduce((acc, row) => {
    acc[row.key] = row.value
    return acc
  }, {})
  res.json(settings)
})

app.put('/settings', authMiddleware, requireRole('admin'), async (req, res) => {
  const settings = req.body || {}
  const entries = Object.entries(settings)
  for (const [key, value] of entries) {
    await run(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      [key, String(value)],
    )
  }
  res.json({ ok: true })
})

// Employee self-service
app.get('/employee/me', authMiddleware, requireRole('employee'), async (req, res) => {
  const employee = await get('SELECT * FROM employees WHERE id = ?', [req.user.employee_id])
  if (!employee) return res.status(404).json({ message: 'Employee not found' })
  res.json(employee)
})

app.get('/employee/attendance', authMiddleware, requireRole('employee'), async (req, res) => {
  const rows = await all(
    'SELECT * FROM attendance WHERE employee_id = ? ORDER BY date DESC',
    [req.user.employee_id],
  )
  res.json(rows)
})

app.get('/employee/leave', authMiddleware, requireRole('employee'), async (req, res) => {
  const rows = await all(
    'SELECT * FROM leave_requests WHERE employee_id = ? ORDER BY id DESC',
    [req.user.employee_id],
  )
  res.json(rows)
})

app.post('/employee/leave', authMiddleware, requireRole('employee'), async (req, res) => {
  const { start_date, end_date, reason } = req.body || {}
  if (!start_date || !end_date || !reason) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO leave_requests (employee_id, start_date, end_date, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.employee_id, start_date, end_date, reason, 'Pending', now],
  )

  const entry = await get('SELECT * FROM leave_requests WHERE id = ?', [result.lastID])
  res.json(entry)
})

app.delete('/employee/leave/:id', authMiddleware, requireRole('employee'), async (req, res) => {
  const { id } = req.params
  await run(
    'DELETE FROM leave_requests WHERE id = ? AND employee_id = ? AND status = ?',
    [id, req.user.employee_id, 'Pending'],
  )
  res.json({ ok: true })
})

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on http://localhost:${PORT}`)
    })
  })
  .catch((err) => {
    console.error('Failed to init db', err)
    process.exit(1)
  })
