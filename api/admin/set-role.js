import { getAuth, getFirestore } from '../_firebase.js'
import { requireAdmin } from '../_auth.js'

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  try {
    await requireAdmin(req)

    const { uid, role } = req.body || {}
    if (!uid || !role) {
      res.status(400).json({ message: 'Missing fields' })
      return
    }

    const auth = getAuth()
    await auth.setCustomUserClaims(uid, { role })

    const db = getFirestore()
    await db.collection('users').doc(uid).set({ role }, { merge: true })

    res.json({ ok: true })
  } catch (err) {
    const status = err.status || 500
    res.status(status).json({ message: err.message || 'Server error' })
  }
}
