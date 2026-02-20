import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { getFirestore } from '../_firebase.js'
import { applyCors, handleOptions } from '../_cors.js'

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  if (req.method !== 'POST') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  try {
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

    const permissions = user.permissions || {}
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
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' })
  }
}
