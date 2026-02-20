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

    const usersSnap = await db.collection('users').get()
    const permissionsByEmployee = new Map()
    usersSnap.docs.forEach((doc) => {
      const data = doc.data()
      if (data.employee_id) {
        permissionsByEmployee.set(data.employee_id, data.permissions || {})
      }
    })

    const enriched = rows.map((row) => ({
      ...row,
      permissions: permissionsByEmployee.get(row.id) || {},
    }))

    res.json(enriched)
    return
  }

  if (req.method === 'POST') {
    const { name, email, role, department, status, username, password, permissions } = req.body || {}
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
      permissions: permissions || {},
      created_at: new Date().toISOString(),
    })

    res.json({ id: employeeRef.id, ...employeePayload, permissions: permissions || {} })
    return
  }

  if (req.method === 'PUT') {
    const id = req.query.id
    const { name, email, role, department, status, permissions } = req.body || {}
    if (!id || !name || !email || !role || !department || !status) {
      res.status(400).json({ message: 'Missing fields' })
      return
    }

    const payload = { name, email, role, department, status }
    await db.collection('employees').doc(id).update(payload)

    if (permissions) {
      const userSnap = await db.collection('users').where('employee_id', '==', id).limit(1).get()
      if (!userSnap.empty) {
        await userSnap.docs[0].ref.update({ permissions })
      }
    }

    res.json({ id, ...payload, permissions: permissions || {} })
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
