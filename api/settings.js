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

  res.status(405).json({ message: 'Method not allowed' })
}
