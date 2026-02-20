import { getFirestore } from './_firebase.js'
import { applyCors, handleOptions } from './_cors.js'
import { requireRole } from './_auth.js'

export default async function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  try {
    requireRole('admin')(req)
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
    return
  }

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

  res.status(405).json({ message: 'Method not allowed' })
}
