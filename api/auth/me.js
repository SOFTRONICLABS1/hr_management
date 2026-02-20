import { verifyToken } from '../_auth.js'
import { applyCors, handleOptions } from '../_cors.js'

export default function handler(req, res) {
  if (handleOptions(req, res)) return
  applyCors(res)

  if (req.method !== 'GET') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  try {
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
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message || 'Server error' })
  }
}
