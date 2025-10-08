// Aplicación de ejemplo con vulnerabilidades intencionales para testing
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Vulnerabilidad: Hardcoded credentials
const ADMIN_PASSWORD = 'admin123';
const SECRET_KEY = 'super-secret-key-123';
const DATABASE_URL = 'postgresql://admin:password123@localhost:5432/mydb';

// Vulnerabilidad: SQL Injection potential
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  // Simulated SQL query - vulnerable to injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  console.log('Executing query:', query);
  res.json({ message: 'User data', query });
});

// Vulnerabilidad: SQL Injection en búsqueda
app.get('/search-users', (req, res) => {
  const searchTerm = req.query.term;
  // Vulnerable a SQL injection
  const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;
  res.json({ query, message: 'Search executed' });
});

// Vulnerabilidad: XSS potential
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // No sanitization of user input
  res.send(`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${searchTerm}</p>
        <script>alert('XSS vulnerability found!');</script>
      </body>
    </html>
  `);
});

// Vulnerabilidad: XSS en comentarios
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  // Directamente renderiza sin sanitización
  res.send(`<div class="comment">${comment}</div>`);
});

// Vulnerabilidad: Path traversal
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;
  // No validation of filename - allows ../../../etc/passwd
  const filePath = path.join(__dirname, 'uploads', filename);
  res.download(filePath);
});

// Vulnerabilidad: Path traversal en lectura de archivos
app.get('/read-file', (req, res) => {
  const filepath = req.query.file;
  // Permite leer cualquier archivo del sistema
  const content = fs.readFileSync(filepath, 'utf8');
  res.send(content);
});

// Vulnerabilidad: Weak encryption
function encryptPassword(password) {
  // Very weak encryption - just base64
  return Buffer.from(password).toString('base64');
}

// Vulnerabilidad: MD5 hash (vulnerable)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Vulnerabilidad: Insecure random number generation
function generateSessionId() {
  return Math.random().toString(36).substring(2);
}

// Vulnerabilidad: Predictable token generation
function generateToken() {
  return Date.now().toString();
}

// Vulnerabilidad: Information disclosure
app.get('/debug', (req, res) => {
  res.json({
    environment: process.env,
    version: process.version,
    platform: process.platform,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    // Exponiendo información sensible
    adminPassword: ADMIN_PASSWORD,
    secretKey: SECRET_KEY,
    databaseUrl: DATABASE_URL
  });
});

// Vulnerabilidad: CSRF - No protection
app.post('/transfer-money', (req, res) => {
  const { amount, to } = req.body;
  // No CSRF protection
  res.json({ 
    message: `Transferred $${amount} to ${to}`,
    status: 'success'
  });
});

// Vulnerabilidad: Missing authentication
app.get('/admin/users', (req, res) => {
  // No authentication check
  res.json([
    { id: 1, name: 'John Doe', email: 'john@example.com' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
  ]);
});

// Vulnerabilidad: Weak session management
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    // Weak session token
    const sessionToken = generateToken();
    res.cookie('session', sessionToken, { 
      httpOnly: false, // Should be true
      secure: false,   // Should be true in production
      sameSite: 'none' // Should be 'strict'
    });
    res.json({ success: true, token: sessionToken });
  } else {
    res.status(401).json({ success: false });
  }
});

// Vulnerabilidad: Directory listing enabled
app.get('/files', (req, res) => {
  const dir = req.query.dir || __dirname;
  const files = fs.readdirSync(dir);
  res.json({ directory: dir, files });
});

// Vulnerabilidad: Command injection
app.post('/ping', (req, res) => {
  const host = req.body.host;
  // Vulnerable a command injection
  const { exec } = require('child_process');
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.json({ output: stdout, error: stderr });
  });
});

// Vulnerabilidad: Server-Side Request Forgery (SSRF)
app.get('/fetch-url', (req, res) => {
  const url = req.query.url;
  // No validation of URL - allows internal network access
  const https = require('https');
  https.get(url, (response) => {
    let data = '';
    response.on('data', (chunk) => data += chunk);
    response.on('end', () => res.send(data));
  });
});

// Vulnerabilidad: Insecure deserialization
app.post('/process-data', (req, res) => {
  const data = req.body.data;
  // Insecure - could lead to RCE
  try {
    const parsed = JSON.parse(data);
    res.json({ processed: parsed });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Vulnerabilidad: Weak password policy
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  
  // No password complexity requirements
  if (password.length < 3) {
    return res.status(400).json({ error: 'Password too short' });
  }
  
  // Store with weak hash
  const hashedPassword = hashPassword(password);
  res.json({ 
    message: 'User registered', 
    username,
    hashedPassword // Exposing hash in response
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Test app listening on port ${PORT}`);
  console.log('Available vulnerable endpoints:');
  console.log('- GET /users/:id (SQL Injection)');
  console.log('- GET /search?q=term (XSS)');
  console.log('- GET /download/:filename (Path Traversal)');
  console.log('- GET /debug (Information Disclosure)');
  console.log('- POST /transfer-money (CSRF)');
  console.log('- GET /admin/users (Missing Auth)');
  console.log('- POST /login (Weak Session)');
  console.log('- GET /files?dir=path (Directory Listing)');
  console.log('- POST /ping (Command Injection)');
  console.log('- GET /fetch-url?url=... (SSRF)');
});
