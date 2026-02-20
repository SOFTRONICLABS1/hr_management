import bcrypt from 'bcryptjs'
import { getFirestore } from './_firebase.js'
import { applyCors, handleOptions } from './_cors.js'
import { requireRole } from './_auth.js'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  let user
  try {
    user = requireRole('admin')(req)
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
    return
  }

  const db = getFirestore()

  if (req.method === 'GET') {
    const snapshot = await db.collection('employees').orderBy('created_at', 'desc').get()
    const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
    res.json(rows)
    return
  }

  if (req.method === 'POST') {
    const { name, email, role, department, status, username, password } = req.body || {}
    if (!name || !email || !role || !department || !status || !username || !password) {
      res.status(400).json({ message: 'Missing fields' })
      return
    }

    const existing = await db.collection('users').where('username', '==', username).limit(1).get()
    if (!existing.empty) {
      res.status(409).json({ message: 'Username already exists' })
      return
    }

    const employeePayload = {
      name,
      email,
      role,
      department,
      status,
      created_at: new Date().toISOString(),
    }

    const employeeRef = await db.collection('employees').add(employeePayload)

    const password_hash = await bcrypt.hash(password, 10)
    await db.collection('users').doc(employeeRef.id).set({
      username,
      role: 'employee',
      employee_id: employeeRef.id,
      password_hash,
      created_at: new Date().toISOString(),
    })

    res.json({ id: employeeRef.id, ...employeePayload })
    return
  }

  if (req.method === 'PUT') {
    const id = req.query.id
    const { name, email, role, department, status } = req.body || {}
    if (!id || !name || !email || !role || !department || !status) {
      res.status(400).json({ message: 'Missing fields' })
      return
    }

    const payload = { name, email, role, department, status }
    await db.collection('employees').doc(id).update(payload)

    res.json({ id, ...payload })
    return
  }

  if (req.method === 'DELETE') {
    const id = req.query.id
    if (!id) {
      res.status(400).json({ message: 'Missing id' })
      return
    }

    await db.collection('employees').doc(id).delete()

    const userSnap = await db.collection('users').where('employee_id', '==', id).get()
    await Promise.all(userSnap.docs.map((doc) => doc.ref.delete()))

    res.json({ ok: true })
    return
  }

  res.status(405).json({ message: 'Method not allowed' })
}
