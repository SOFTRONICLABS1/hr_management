import { getFirestore } from '../_firebase.js'
import { applyCors, handleOptions } from '../_cors.js'
import { requireRole } from '../_auth.js'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  let user
  try {
    user = requireRole('employee')(req)
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
    return
  }

  if (req.method !== 'GET') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  const db = getFirestore()
  const snapshot = await db
    .collection('attendance')
    .where('employee_id', '==', user.employee_id)
    .orderBy('date', 'desc')
    .get()

  const rows = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))
  res.json(rows)
}
