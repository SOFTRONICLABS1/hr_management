function applyCors(res) {
  const origin = process.env.CLIENT_ORIGIN || '*'
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
}

function handleOptions(req, res) {
  if (req.method === 'OPTIONS') {
    applyCors(res)
    res.status(204).end()
    return true
  }
  return false
}

export { applyCors, handleOptions }
