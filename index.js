import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { PDFDocument, rgb } from 'pdf-lib'
import fontkit from '@pdf-lib/fontkit'
import { initDb, get, all, run } from './db.js'

const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const PAYSLIP_BG_PATH = path.join(__dirname, 'assets', 'payslip-bg.jpg')
const PAYSLIP_FONT_PATH = path.join(__dirname, 'assets', 'arial.ttf')
const PAYSLIP_BG_BYTES = fs.readFileSync(PAYSLIP_BG_PATH)
const PAYSLIP_FONT_BYTES = fs.readFileSync(PAYSLIP_FONT_PATH)

const app = express()

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }))
app.use(express.json())

function formatNumber(value) {
  if (value === null || value === undefined || value === '') return '0'
  const num = Number(value)
  if (Number.isNaN(num)) return String(value)
  return Math.round(num).toLocaleString('en-US')
}

function formatInt(value) {
  if (value === null || value === undefined || value === '') return '0'
  const num = Number.parseInt(value, 10)
  if (Number.isNaN(num)) return '0'
  return String(num)
}

function sanitizeDigits(value) {
  if (value === null || value === undefined) return ''
  return String(value).replace(/[^0-9]/g, '')
}

async function buildPayslipPdf(payslip) {
  const pdfDoc = await PDFDocument.create()
  pdfDoc.registerFontkit(fontkit)
  const bgImage = await pdfDoc.embedJpg(PAYSLIP_BG_BYTES)
  const font = await pdfDoc.embedFont(PAYSLIP_FONT_BYTES)
  const page = pdfDoc.addPage([bgImage.width, bgImage.height])

  page.drawImage(bgImage, {
    x: 0,
    y: 0,
    width: bgImage.width,
    height: bgImage.height,
  })

  const fontSize = 21
  const textColor = rgb(0, 0, 0)
  const height = bgImage.height

  const drawText = (text, x, y) => {
    if (text === null || text === undefined || text === '') return
    page.drawText(String(text), {
      x,
      y: height - y - fontSize,
      size: fontSize,
      font,
      color: textColor,
    })
  }

  drawText(payslip.month, 690, 365)
  drawText(payslip.name, 695, 425)
  drawText(payslip.employee_no, 446, 455)
  drawText(formatInt(payslip.no_of_days_pay), 1000, 455)
  drawText(formatInt(payslip.no_of_days_in_month), 1000, 485)
  drawText(payslip.location, 449, 485)
  drawText(payslip.bank, 447, 515)
  drawText(formatInt(payslip.location_india_days), 1000, 515)
  drawText(payslip.bank_ac_no, 448, 542)
  drawText(formatInt(payslip.lop), 1000, 545)
  drawText(payslip.employee_pan, 448, 570)
  drawText(payslip.employer_pan, 448, 600)
  drawText(payslip.employer_tan, 448, 630)
  drawText(formatInt(payslip.leaves), 1000, 570)
  drawText(payslip.role, 445, 695)
  drawText(payslip.role_designation, 445, 725)
  drawText(formatNumber(payslip.basic_salary), 670, 815)
  drawText(formatNumber(payslip.house_rent_allowance), 680, 845)
  drawText(formatNumber(payslip.conveyance_allowance), 680, 873)
  drawText(formatNumber(payslip.medical_allowance), 680, 900)
  drawText(formatNumber(payslip.special_allowance), 670, 930)
  drawText(formatNumber(payslip.total_income), 670, 960)
  drawText(formatNumber(payslip.income_tax), 1060, 815)
  drawText(formatNumber(payslip.professional_tax), 1045, 845)
  drawText(formatNumber(payslip.total_deductions), 1045, 960)
  drawText(formatNumber(payslip.net_pay), 1006, 1017)
  drawText(payslip.information, 165, 1105)
  drawText(payslip.generated_on, 278, 1223)

  return pdfDoc.save()
}

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

app.post('/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {}
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Missing fields' })
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'New password must be at least 6 characters.' })
  }

  const user = await get('SELECT id, password_hash FROM users WHERE id = ?', [req.user.sub])
  if (!user) return res.status(404).json({ message: 'User not found' })

  const ok = await bcrypt.compare(currentPassword, user.password_hash)
  if (!ok) {
    return res.status(401).json({ message: 'Current password is incorrect' })
  }

  const passwordHash = await bcrypt.hash(newPassword, 10)
  await run('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, user.id])
  res.json({ ok: true })
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
  const { name, email, role, department, status, username, password } = req.body || {}
  if (!name || !email || !role || !department || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  if (username && !password) {
    return res.status(400).json({ message: 'Password is required for the user account' })
  }

  if (username) {
    const existingUser = await get('SELECT id FROM users WHERE username = ?', [username])
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' })
    }
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO employees (name, email, role, department, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [name, email, role, department, status, now],
  )

  if (username && password) {
    const passwordHash = await bcrypt.hash(password, 10)
    await run(
      'INSERT INTO users (username, password_hash, role, employee_id, created_at) VALUES (?, ?, ?, ?, ?)',
      [username, passwordHash, 'employee', result.lastID, now],
    )
  }

  const employee = await get('SELECT * FROM employees WHERE id = ?', [result.lastID])
  res.json(employee)
})

app.put('/employees/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { name, email, role, department, status, reset_password } = req.body || {}
  if (!name || !email || !role || !department || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  await run(
    'UPDATE employees SET name = ?, email = ?, role = ?, department = ?, status = ? WHERE id = ?',
    [name, email, role, department, status, id],
  )

  if (reset_password) {
    const user = await get('SELECT id FROM users WHERE employee_id = ?', [id])
    if (!user) {
      return res.status(404).json({ message: 'Employee user account not found' })
    }
    const passwordHash = await bcrypt.hash(reset_password, 10)
    await run('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, user.id])
  }

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
  const { employee_id, start_date, end_date, subject, description, reason, status } = req.body || {}
  const finalReason = description || reason
  if (!employee_id || !start_date || !end_date || !finalReason || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO leave_requests (employee_id, start_date, end_date, subject, description, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [employee_id, start_date, end_date, subject || '', description || '', finalReason, status, now],
  )

  const entry = await get('SELECT * FROM leave_requests WHERE id = ?', [result.lastID])
  res.json(entry)
})

app.put('/leave/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { employee_id, start_date, end_date, subject, description, reason, status } = req.body || {}
  const finalReason = description || reason
  if (!employee_id || !start_date || !end_date || !finalReason || !status) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  await run(
    'UPDATE leave_requests SET employee_id = ?, start_date = ?, end_date = ?, subject = ?, description = ?, reason = ?, status = ? WHERE id = ?',
    [employee_id, start_date, end_date, subject || '', description || '', finalReason, status, id],
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

// Payslips CRUD + PDF
app.get('/payslips', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all(
    `SELECT payslips.*, employees.name as employee_name
     FROM payslips
     JOIN employees ON payslips.employee_id = employees.id
     ORDER BY payslips.id DESC`,
  )
  res.json(rows)
})

app.post('/payslips', authMiddleware, requireRole('admin'), async (req, res) => {
  const payload = req.body || {}
  const { employee_id, month, request_id } = payload
  if (!employee_id || !month) {
    return res.status(400).json({ message: 'Employee and month are required.' })
  }

  const employee = await get('SELECT name, role, department FROM employees WHERE id = ?', [employee_id])
  if (!employee) {
    return res.status(404).json({ message: 'Employee not found.' })
  }

  const now = new Date().toISOString()
  const generatedOn = payload.generated_on || now

  const result = await run(
    `INSERT INTO payslips (
      employee_id, month, name, employee_no, no_of_days_pay, location, no_of_days_in_month,
      bank, location_india_days, bank_ac_no, lop, employee_pan, employer_pan, employer_tan, leaves,
      role, role_designation, basic_salary, income_tax, house_rent_allowance, professional_tax,
      conveyance_allowance, medical_allowance, special_allowance, total_income, total_deductions,
      net_pay, information, generated_on, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      employee_id,
      month,
      payload.name || employee.name,
      payload.employee_no || '',
      sanitizeDigits(payload.no_of_days_pay),
      payload.location || '',
      sanitizeDigits(payload.no_of_days_in_month),
      payload.bank || '',
      sanitizeDigits(payload.location_india_days),
      sanitizeDigits(payload.bank_ac_no),
      sanitizeDigits(payload.lop),
      payload.employee_pan || '',
      payload.employer_pan || '',
      payload.employer_tan || '',
      sanitizeDigits(payload.leaves),
      payload.role || employee.role || '',
      payload.role_designation || employee.department || '',
      payload.basic_salary ?? null,
      payload.income_tax ?? null,
      payload.house_rent_allowance ?? null,
      payload.professional_tax ?? null,
      payload.conveyance_allowance ?? null,
      payload.medical_allowance ?? null,
      payload.special_allowance ?? null,
      payload.total_income ?? null,
      payload.total_deductions ?? null,
      payload.net_pay ?? null,
      payload.information || '',
      generatedOn,
      now,
    ],
  )

  const payslip = await get('SELECT * FROM payslips WHERE id = ?', [result.lastID])

  if (request_id) {
    const nowUpdate = new Date().toISOString()
    await run(
      'UPDATE payslip_requests SET status = ?, payslip_id = ?, updated_at = ? WHERE id = ?',
      ['Generated', payslip.id, nowUpdate, request_id],
    )
  }

  res.json(payslip)
})

app.put('/payslips/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const payload = req.body || {}
  const { employee_id, month } = payload
  if (!employee_id || !month) {
    return res.status(400).json({ message: 'Employee and month are required.' })
  }

  await run(
    `UPDATE payslips SET
      employee_id = ?, month = ?, name = ?, employee_no = ?, no_of_days_pay = ?, location = ?,
      no_of_days_in_month = ?, bank = ?, location_india_days = ?, bank_ac_no = ?, lop = ?,
      employee_pan = ?, employer_pan = ?, employer_tan = ?, leaves = ?, role = ?, role_designation = ?,
      basic_salary = ?, income_tax = ?, house_rent_allowance = ?, professional_tax = ?,
      conveyance_allowance = ?, medical_allowance = ?, special_allowance = ?, total_income = ?,
      total_deductions = ?, net_pay = ?, information = ?, generated_on = ?
     WHERE id = ?`,
    [
      employee_id,
      month,
      payload.name || '',
      payload.employee_no || '',
      sanitizeDigits(payload.no_of_days_pay),
      payload.location || '',
      sanitizeDigits(payload.no_of_days_in_month),
      payload.bank || '',
      sanitizeDigits(payload.location_india_days),
      sanitizeDigits(payload.bank_ac_no),
      sanitizeDigits(payload.lop),
      payload.employee_pan || '',
      payload.employer_pan || '',
      payload.employer_tan || '',
      sanitizeDigits(payload.leaves),
      payload.role || '',
      payload.role_designation || '',
      payload.basic_salary ?? null,
      payload.income_tax ?? null,
      payload.house_rent_allowance ?? null,
      payload.professional_tax ?? null,
      payload.conveyance_allowance ?? null,
      payload.medical_allowance ?? null,
      payload.special_allowance ?? null,
      payload.total_income ?? null,
      payload.total_deductions ?? null,
      payload.net_pay ?? null,
      payload.information || '',
      payload.generated_on || '',
      id,
    ],
  )

  const payslip = await get('SELECT * FROM payslips WHERE id = ?', [id])
  res.json(payslip)
})

app.delete('/payslips/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  await run('DELETE FROM payslips WHERE id = ?', [id])
  res.json({ ok: true })
})

app.get('/payslips/:id/pdf', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const payslip = await get('SELECT * FROM payslips WHERE id = ?', [id])
  if (!payslip) {
    return res.status(404).json({ message: 'Payslip not found.' })
  }

  const pdfBytes = await buildPayslipPdf(payslip)
  const safeName = (payslip.name || 'Employee').replace(/[^a-z0-9-_]/gi, '_')
  const safeMonth = (payslip.month || 'Payslip').replace(/[^a-z0-9-_]/gi, '_')
  res.setHeader('Content-Type', 'application/pdf')
  res.setHeader('Content-Disposition', `inline; filename="Payslip-${safeName}-${safeMonth}.pdf"`)
  res.send(Buffer.from(pdfBytes))
})

// Payslip Requests (Admin)
app.get('/payslip-requests', authMiddleware, requireRole('admin'), async (_req, res) => {
  const rows = await all(
    `SELECT payslip_requests.*, employees.name as employee_name
     FROM payslip_requests
     JOIN employees ON payslip_requests.employee_id = employees.id
     ORDER BY payslip_requests.id DESC`,
  )
  res.json(rows)
})

app.put('/payslip-requests/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { id } = req.params
  const { status, payslip_id } = req.body || {}
  if (!status) {
    return res.status(400).json({ message: 'Missing status' })
  }
  const now = new Date().toISOString()
  await run('UPDATE payslip_requests SET status = ?, payslip_id = ?, updated_at = ? WHERE id = ?', [
    status,
    payslip_id || null,
    now,
    id,
  ])
  const entry = await get('SELECT * FROM payslip_requests WHERE id = ?', [id])
  res.json(entry)
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
  const { start_date, end_date, subject, description, reason } = req.body || {}
  const finalReason = description || reason
  if (!start_date || !end_date || !finalReason) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO leave_requests (employee_id, start_date, end_date, subject, description, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [
      req.user.employee_id,
      start_date,
      end_date,
      subject || '',
      description || '',
      finalReason,
      'Pending',
      now,
    ],
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

// Employee Payslip Requests + Downloads
app.get('/employee/payslip-requests', authMiddleware, requireRole('employee'), async (req, res) => {
  const rows = await all(
    'SELECT * FROM payslip_requests WHERE employee_id = ? ORDER BY id DESC',
    [req.user.employee_id],
  )
  res.json(rows)
})

app.post('/employee/payslip-requests', authMiddleware, requireRole('employee'), async (req, res) => {
  const { month } = req.body || {}
  if (!month) {
    return res.status(400).json({ message: 'Month is required' })
  }
  const now = new Date().toISOString()
  const result = await run(
    'INSERT INTO payslip_requests (employee_id, month, status, created_at) VALUES (?, ?, ?, ?)',
    [req.user.employee_id, month, 'Pending', now],
  )
  const entry = await get('SELECT * FROM payslip_requests WHERE id = ?', [result.lastID])
  res.json(entry)
})

app.get('/employee/payslips', authMiddleware, requireRole('employee'), async (req, res) => {
  const rows = await all(
    'SELECT * FROM payslips WHERE employee_id = ? ORDER BY id DESC',
    [req.user.employee_id],
  )
  res.json(rows)
})

app.get('/employee/payslips/:id/pdf', authMiddleware, requireRole('employee'), async (req, res) => {
  const { id } = req.params
  const payslip = await get('SELECT * FROM payslips WHERE id = ?', [id])
  if (!payslip || String(payslip.employee_id) !== String(req.user.employee_id)) {
    return res.status(404).json({ message: 'Payslip not found.' })
  }

  const pdfBytes = await buildPayslipPdf(payslip)
  const safeName = (payslip.name || 'Employee').replace(/[^a-z0-9-_]/gi, '_')
  const safeMonth = (payslip.month || 'Payslip').replace(/[^a-z0-9-_]/gi, '_')
  res.setHeader('Content-Type', 'application/pdf')
  res.setHeader('Content-Disposition', `inline; filename="Payslip-${safeName}-${safeMonth}.pdf"`)
  res.send(Buffer.from(pdfBytes))
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
