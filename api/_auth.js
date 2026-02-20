import { getAuth } from './_firebase.js'

function getBearerToken(req) {
  const header = req.headers.authorization || ''
  if (!header.startsWith('Bearer ')) return null
  return header.slice(7)
}

async function verifyToken(req) {
  const token = getBearerToken(req)
  if (!token) throw new Error('Missing token')
  const auth = getAuth()
  return auth.verifyIdToken(token)
}

function isBootstrapAdmin(email) {
  const list = (process.env.BOOTSTRAP_ADMIN_EMAILS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
  return list.includes(email)
}

async function requireAdmin(req) {
  const decoded = await verifyToken(req)
  if (decoded.role === 'admin' || isBootstrapAdmin(decoded.email)) {
    return decoded
  }
  const error = new Error('Forbidden')
  error.status = 403
  throw error
}

export { verifyToken, requireAdmin }
