import bcrypt from 'bcryptjs'
import { getFirestore } from '../_firebase.js'
import { applyCors, handleOptions } from '../_cors.js'
import { requireRole } from '../_auth.js'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  if (req.method !== 'POST') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  let user
  try {
    user = requireRole('admin')(req)
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
    return
  }

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
}
