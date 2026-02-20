import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { getFirestore } from './_firebase.js'
import { applyCors, handleOptions } from './_cors.js'
import { verifyToken, requireRole, requirePermission } from './_auth.js'

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(req, res)

  const path = Array.isArray(req.query.path) ? req.query.path.join('/') : ''

  try {
    if (path === 'health' && req.method === 'GET') {
      res.json({ ok: true })
      return
    }

    if (path === 'auth/login' && req.method === 'POST') {
      const { username, password } = req.body || {}
      if (!username || !password) {
        res.status(400).json({ message: 'Username and password required' })
        return
      }

      const db = getFirestore()
      const snapshot = await db.collection('users').where('username', '==', username).limit(1).get()
      if (snapshot.empty) {
        res.status(401).json({ message: 'Invalid credentials' })
        return
      }

      const doc = snapshot.docs[0]
      const user = { id: doc.id, ...doc.data() }

      const ok = await bcrypt.compare(password, user.password_hash || '')
      if (!ok) {
        res.status(401).json({ message: 'Invalid credentials' })
        return
      }

      const defaultPermissions = {
        attendance_view: true,
        leave_apply: true,
        profile_view: true,
      }
      const permissions =
        user.role === 'employee'
          ? { ...defaultPermissions, ...(user.permissions || {}) }
          : user.permissions || {}

      if (user.role === 'employee' && !user.permissions) {
        await doc.ref.update({ permissions })
      }

      const token = jwt.sign(
        {
          sub: user.id,
          username: user.username,
          role: user.role,
          employee_id: user.employee_id || null,
          permissions,
        },
        JWT_SECRET,
        { expiresIn: '2h' },
      )

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          employee_id: user.employee_id || null,
          permissions,
        },
      })
      return
    }

    if (path === 'auth/me' && req.method === 'GET') {
      const user = verifyToken(req)
      res.json({
        user: {
          id: user.sub,
          username: user.username,
          role: user.role,
          employee_id: user.employee_id || null,
          permissions: user.permissions || {},
        },
      })
      return
    }

    if (path === 'auth/change-password' && req.method === 'POST') {
      const user = requireRole('admin')(req)
      const { currentPassword, newPassword } = req.body || {}
      if (!currentPassword || !newPassword) {
        res.status(400).json({ message: 'Missing fields' })
        return
      }

      if (newPassword.length < 6) {
        res.status(400).json({ message: 'Password must be at least 6 characters' })
        return
      }

      const db = getFirestore()
      const docRef = db.collection('users').doc(user.sub)
      const docSnap = await docRef.get()
      if (!docSnap.exists) {
        res.status(404).json({ message: 'User not found' })
        return
      }

      const data = docSnap.data()
      const ok = await bcrypt.compare(currentPassword, data.password_hash || '')
      if (!ok) {
        res.status(401).json({ message: 'Invalid current password' })
        return
      }

      const password_hash = await bcrypt.hash(newPassword, 10)
      await docRef.update({ password_hash })
      res.json({ ok: true })
      return
    }

    if (path === 'employees') {
      requireRole('admin')(req)
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
    }

    if (path === 'attendance') {
      requireRole('admin')(req)
      const db = getFirestore()

      if (req.method === 'GET') {
        const snapshot = await db.collection('attendance').orderBy('created_at', 'desc').get()
        const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
        res.json(rows)
        return
      }

      if (req.method === 'POST') {
        const { employee_id, date, status, employee_name } = req.body || {}
        if (!employee_id || !date || !status) {
          res.status(400).json({ message: 'Missing fields' })
          return
        }

        const payload = {
          employee_id,
          employee_name: employee_name || '',
          date,
          status,
          created_at: new Date().toISOString(),
        }

        const ref = await db.collection('attendance').add(payload)
        res.json({ id: ref.id, ...payload })
        return
      }

      if (req.method === 'PUT') {
        const id = req.query.id
        const { employee_id, date, status, employee_name } = req.body || {}
        if (!id || !employee_id || !date || !status) {
          res.status(400).json({ message: 'Missing fields' })
          return
        }

        const payload = {
          employee_id,
          employee_name: employee_name || '',
          date,
          status,
        }

        await db.collection('attendance').doc(id).update(payload)
        res.json({ id, ...payload })
        return
      }

      if (req.method === 'DELETE') {
        const id = req.query.id
        if (!id) {
          res.status(400).json({ message: 'Missing id' })
          return
        }

        await db.collection('attendance').doc(id).delete()
        res.json({ ok: true })
        return
      }
    }

    if (path === 'leave') {
      requireRole('admin')(req)
      const db = getFirestore()

      if (req.method === 'GET') {
        const snapshot = await db.collection('leave_requests').orderBy('created_at', 'desc').get()
        const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
        res.json(rows)
        return
      }

      if (req.method === 'POST') {
        const { employee_id, start_date, end_date, reason, status, employee_name } = req.body || {}
        if (!employee_id || !start_date || !end_date || !reason || !status) {
          res.status(400).json({ message: 'Missing fields' })
          return
        }

        const payload = {
          employee_id,
          employee_name: employee_name || '',
          start_date,
          end_date,
          reason,
          status,
          created_at: new Date().toISOString(),
        }

        const ref = await db.collection('leave_requests').add(payload)
        res.json({ id: ref.id, ...payload })
        return
      }

      if (req.method === 'PUT') {
        const id = req.query.id
        const { employee_id, start_date, end_date, reason, status, employee_name } = req.body || {}
        if (!id || !employee_id || !start_date || !end_date || !reason || !status) {
          res.status(400).json({ message: 'Missing fields' })
          return
        }

        const payload = {
          employee_id,
          employee_name: employee_name || '',
          start_date,
          end_date,
          reason,
          status,
        }

        await db.collection('leave_requests').doc(id).update(payload)
        res.json({ id, ...payload })
        return
      }

      if (req.method === 'DELETE') {
        const id = req.query.id
        if (!id) {
          res.status(400).json({ message: 'Missing id' })
          return
        }

        await db.collection('leave_requests').doc(id).delete()
        res.json({ ok: true })
        return
      }
    }

    if (path === 'settings') {
      requireRole('admin')(req)
      const db = getFirestore()

      if (req.method === 'GET') {
        const doc = await db.collection('settings').doc('company').get()
        res.json(doc.exists ? doc.data() : {})
        return
      }

      if (req.method === 'PUT') {
        const payload = req.body || {}
        await db.collection('settings').doc('company').set(payload, { merge: true })
        res.json({ ok: true })
        return
      }
    }

    if (path === 'employee/me' && req.method === 'GET') {
      const user = requirePermission('profile_view')(req)
      const db = getFirestore()
      const doc = await db.collection('employees').doc(user.employee_id).get()
      if (!doc.exists) {
        res.status(404).json({ message: 'Employee not found' })
        return
      }
      res.json({ id: doc.id, ...doc.data() })
      return
    }

    if (path === 'employee/attendance' && req.method === 'GET') {
      const user = requirePermission('attendance_view')(req)
      const db = getFirestore()
      const snapshot = await db
        .collection('attendance')
        .where('employee_id', '==', user.employee_id)
        .orderBy('date', 'desc')
        .get()

      const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
      res.json(rows)
      return
    }

    if (path === 'employee/leave') {
      const user = requirePermission('leave_apply')(req)
      const db = getFirestore()

      if (req.method === 'GET') {
        const snapshot = await db
          .collection('leave_requests')
          .where('employee_id', '==', user.employee_id)
          .orderBy('created_at', 'desc')
          .get()
        const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
        res.json(rows)
        return
      }

      if (req.method === 'POST') {
        const { start_date, end_date, reason } = req.body || {}
        if (!start_date || !end_date || !reason) {
          res.status(400).json({ message: 'Missing fields' })
          return
        }

        const payload = {
          employee_id: user.employee_id,
          start_date,
          end_date,
          reason,
          status: 'Pending',
          created_at: new Date().toISOString(),
        }

        const ref = await db.collection('leave_requests').add(payload)
        res.json({ id: ref.id, ...payload })
        return
      }

      if (req.method === 'DELETE') {
        const id = req.query.id
        if (!id) {
          res.status(400).json({ message: 'Missing id' })
          return
        }

        const docRef = db.collection('leave_requests').doc(id)
        const docSnap = await docRef.get()
        if (!docSnap.exists) {
          res.status(404).json({ message: 'Not found' })
          return
        }

        const data = docSnap.data()
        if (data.employee_id !== user.employee_id || data.status !== 'Pending') {
          res.status(403).json({ message: 'Forbidden' })
          return
        }

        await docRef.delete()
        res.json({ ok: true })
        return
      }
    }

    res.status(404).json({ message: 'Not found' })
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
  }
}
