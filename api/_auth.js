import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

function getBearerToken(req) {
  const header = req.headers.authorization || ''
  if (!header.startsWith('Bearer ')) return null
  return header.slice(7)
}

function verifyToken(req) {
  const token = getBearerToken(req)
  if (!token) {
    const error = new Error('Missing token')
    error.status = 401
    throw error
  }

  try {
    return jwt.verify(token, JWT_SECRET)
  } catch {
    const error = new Error('Invalid token')
    error.status = 401
    throw error
  }
}

function requireRole(role) {
  return (req) => {
    const payload = verifyToken(req)
    if (payload.role !== role) {
      const error = new Error('Forbidden')
      error.status = 403
      throw error
    }
    return payload
  }
}

export { verifyToken, requireRole }
