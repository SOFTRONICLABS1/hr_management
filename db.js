import sqlite3 from 'sqlite3'
import bcrypt from 'bcryptjs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const DB_PATH = path.join(__dirname, 'data', 'app.db')

const db = new sqlite3.Database(DB_PATH)

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err)
      resolve(this)
    })
  })
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err)
      resolve(row)
    })
  })
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err)
      resolve(rows)
    })
  })
}

async function initDb() {
  await run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      employee_id INTEGER,
      created_at TEXT NOT NULL
    )`,
  )

  await run(
    `CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL,
      department TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  )

  await run(
    `CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(employee_id) REFERENCES employees(id)
    )`,
  )

  await run(
    `CREATE TABLE IF NOT EXISTS leave_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(employee_id) REFERENCES employees(id)
    )`,
  )

  await run(
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`,
  )

  try {
    await run('ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT \\'admin\\'')
  } catch {}
  try {
    await run('ALTER TABLE users ADD COLUMN employee_id INTEGER')
  } catch {}

  const now = new Date().toISOString()

  const existingAdmin = await get('SELECT id FROM users WHERE username = ?', ['admin'])
  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash('admin', 10)
    await run(
      'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
      ['admin', passwordHash, 'admin', now],
    )
  } else {
    await run('UPDATE users SET role = ? WHERE username = ?', ['admin', 'admin'])
  }

  const existingEmployeeUser = await get('SELECT id FROM users WHERE username = ?', ['employee1'])
  if (!existingEmployeeUser) {
    const employee = await get('SELECT id FROM employees WHERE email = ?', ['employee1@company.com'])
    let employeeId = employee?.id
    if (!employeeId) {
      const result = await run(
        'INSERT INTO employees (name, email, role, department, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        ['Employee One', 'employee1@company.com', 'Staff', 'General', 'Active', now],
      )
      employeeId = result.lastID
    }

    const passwordHash = await bcrypt.hash('employee1', 10)
    await run(
      'INSERT INTO users (username, password_hash, role, employee_id, created_at) VALUES (?, ?, ?, ?, ?)',
      ['employee1', passwordHash, 'employee', employeeId, now],
    )
  }
}

export { db, run, get, all, initDb }
