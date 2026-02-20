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

  res.status(405).json({ message: 'Method not allowed' })
}
