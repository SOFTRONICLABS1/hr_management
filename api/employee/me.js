import { getFirestore } from '../_firebase.js'
import { applyCors, handleOptions } from '../_cors.js'
import { requirePermission } from '../_auth.js'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  let user
  try {
    user = requirePermission('profile_view')(req)
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
    return
  }

  if (req.method !== 'GET') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  const db = getFirestore()
  const doc = await db.collection('employees').doc(user.employee_id).get()
  if (!doc.exists) {
    res.status(404).json({ message: 'Employee not found' })
    return
  }

  res.json({ id: doc.id, ...doc.data() })
}
