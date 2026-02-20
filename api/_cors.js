function resolveOrigin(req) {
  const allowed = process.env.CLIENT_ORIGIN
  if (allowed) return allowed
  return req.headers.origin || '*'
}

function applyCors(req, res) {
  const origin = resolveOrigin(req)
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Vary', 'Origin')
}

function handleOptions(req, res) {
  if (req.method === 'OPTIONS') {
    applyCors(req, res)
    res.status(200).end()
    return true
  }
  return false
}

export { applyCors, handleOptions }
