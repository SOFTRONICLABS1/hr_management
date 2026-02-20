import { getAuth, getFirestore } from '../_firebase.js'
import { requireAdmin } from '../_auth.js'

const USER_EMAIL_DOMAIN = 'hr-management.local'

function toEmail(username) {
  if (!username) return ''
  return username.includes('@') ? username : `${username}@${USER_EMAIL_DOMAIN}`
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ message: 'Method not allowed' })
    return
  }

  try {
    await requireAdmin(req)

    const { username, password, employee } = req.body || {}
    if (!username || !password || !employee?.name || !employee?.email) {
      res.status(400).json({ message: 'Missing fields' })
      return
    }

    const auth = getAuth()
    const db = getFirestore()

    const email = toEmail(username)
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: employee.name,
    })

    await auth.setCustomUserClaims(userRecord.uid, { role: 'employee' })

    const employeeRef = await db.collection('employees').add({
      name: employee.name,
      email: employee.email,
      role: employee.role || 'Staff',
      department: employee.department || 'General',
      status: employee.status || 'Active',
      created_at: new Date().toISOString(),
    })

    await db.collection('users').doc(userRecord.uid).set({
      username,
      role: 'employee',
      employee_id: employeeRef.id,
      created_at: new Date().toISOString(),
    })

    res.json({ ok: true, uid: userRecord.uid, employee_id: employeeRef.id })
  } catch (err) {
    const status = err.status || 500
    res.status(status).json({ message: err.message || 'Server error' })
  }
}
