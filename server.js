const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const ExcelJS = require('exceljs');
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
const PORT = 3000;

const ENCRYPTION_KEY = crypto.randomBytes(32);

app.use(bodyParser.json());
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.static('public'));

app.use(session({
    secret: 'your_super_secret_key_change_in_prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 3600000,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

const DBSOURCE = 'expenses.db';

const db = new sqlite3.Database(DBSOURCE, (err) => {
    if (err) {
        console.error('Failed to connect to DB:', err.message);
        process.exit(1);
    } else {
        console.log('Connected to SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            category TEXT,
            date TEXT NOT NULL,
            description TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    }
});

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch {
        return '';
    }
}

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized, please login.' });
    }
    next();
}

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ error: 'Username and password (min 6!) required.' });
    }
    
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Internal error' });
        
        const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
        db.run(sql, [username, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(409).json({ error: 'Username already taken.' });
                }
                return res.status(400).json({ error: err.message });
            }
            req.session.userId = this.lastID;
            req.session.username = username;
            res.json({ message: 'Registered and logged in', username });
        });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required.' });
    }
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) return res.status(500).json({ error: 'Internal error' });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        bcrypt.compare(password, user.password_hash, (err, result) => {
            if (err) return res.status(500).json({ error: 'Internal error' });
            if (!result) return res.status(401).json({ error: 'Invalid credentials.' });

            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ message: 'Logged in', username: user.username });
        });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Failed to logout' });
        res.json({ message: 'Logged out' });
    });
});

app.get('/api/current_user', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }
    res.json({ id: req.session.userId, username: req.session.username });
});

app.post('/api/expenses', requireLogin, (req, res) => {
    const { amount, category, date, description } = req.body;
    if (!amount || !date || !description) {
        return res.status(400).json({ error: 'Amount, date and description are required' });
    }
    const encryptedDescription = encrypt(description);
    const sql = 'INSERT INTO expenses (user_id, amount, category, date, description) VALUES (?, ?, ?, ?, ?)';
    const params = [req.session.userId, amount, category || '', date, encryptedDescription];
    db.run(sql, params, function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
        } else {
            res.json({ id: this.lastID });
        }
    });
});

app.get('/api/expenses', requireLogin, (req, res) => {
    let sql = 'SELECT * FROM expenses WHERE user_id = ?';
    let params = [req.session.userId];

    if (req.query.category) {
        sql += ' AND category = ?';
        params.push(req.query.category);
    }

    if (req.query.fromDate) {
        sql += ' AND date >= ?';
        params.push(req.query.fromDate);
    }

    if (req.query.toDate) {
        sql += ' AND date <= ?';
        params.push(req.query.toDate);
    }

    db.all(sql, params, (err, rows) => {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        const expenses = rows.map(r => ({
            id: r.id,
            amount: r.amount,
            category: r.category,
            date: r.date,
            description: r.description ? decrypt(r.description) : ''
        }));
        res.json(expenses);
    });
});

app.put('/api/expenses/:id', requireLogin, (req, res) => {
    const { amount, category, date, description } = req.body;
    const { id } = req.params;
    const encryptedDescription = encrypt(description || '');
    const sql = `UPDATE expenses SET amount = ?, category = ?, date = ?, description = ? WHERE id = ? AND user_id = ?`;
    const params = [amount, category || '', date, encryptedDescription, id, req.session.userId];
    db.run(sql, params, function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Expense not found or unauthorized' });
            return;
        }
        res.json({ updated: true });
    });
});

app.delete('/api/expenses/:id', requireLogin, (req, res) => {
    const { id } = req.params;
    const sql = `DELETE FROM expenses WHERE id = ? AND user_id = ?`;
    db.run(sql, [id, req.session.userId], function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Expense not found or unauthorized' });
            return;
        }
        res.json({ deleted: true });
    });
});

app.get('/api/backup', requireLogin, (req, res) => {
    const backupDir = path.join(__dirname, 'backup');
    if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir);
    }
    const backupFile = path.join(backupDir, `expenses_backup_${req.session.userId}_${Date.now()}.db`);
    const readStream = fs.createReadStream(DBSOURCE);
    const writeStream = fs.createWriteStream(backupFile);
    readStream.pipe(writeStream);
    writeStream.on('finish', () => {
        res.json({ backupFile, message: 'Backup successful' });
    });
    writeStream.on('error', (err) => {
        res.status(500).json({ error: 'Backup failed', details: err.message });
    });
});

app.get('/api/expenses/summary/monthly', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { fromDate, toDate, category } = req.query;

  let sql = `
    SELECT strftime('%Y-%m', date) as month, SUM(amount) as total
    FROM expenses WHERE user_id = ?
  `;
  const params = [userId];

  if (category) {
    sql += ' AND category = ?';
    params.push(category);
  }
  if (fromDate) {
    sql += ' AND date >= ?';
    params.push(fromDate);
  }
  if (toDate) {
    sql += ' AND date <= ?';
    params.push(toDate);
  }
  sql += ' GROUP BY month ORDER BY month';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/expenses/summary/weekly', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { fromDate, toDate, category } = req.query;

  let sql = `
    SELECT strftime('%Y', date) as year,
           strftime('%W', date) as week,
           SUM(amount) as total
    FROM expenses WHERE user_id = ?
  `;
  const params = [userId];

  if (category) {
    sql += ' AND category = ?';
    params.push(category);
  }
  if (fromDate) {
    sql += ' AND date >= ?';
    params.push(fromDate);
  }
  if (toDate) {
    sql += ' AND date <= ?';
    params.push(toDate);
  }
  sql += ' GROUP BY year, week ORDER BY year, week';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const formatted = rows.map(r => ({
      week: `${r.year}-W${('0' + r.week).slice(-2)}`,
      total: r.total
    }));

    res.json(formatted);
  });
});

app.put('/api/user/profile', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { username } = req.body;

  if (!username || username.trim().length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }

  const trimmedUsername = username.trim();

  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [trimmedUsername, userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) return res.status(409).json({ error: 'Username already taken.' });

    db.run('UPDATE users SET username = ? WHERE id = ?', [trimmedUsername, userId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update username.' });
      req.session.username = trimmedUsername; // update session username
      res.json({ message: 'Username updated successfully.', username: trimmedUsername });
    });
  });
});

app.put('/api/user/password', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Current password and new password (min 6 chars) required.' });
  }

  db.get('SELECT password_hash FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found.' });

    bcrypt.compare(currentPassword, user.password_hash, (err, isMatch) => {
      if (err) return res.status(500).json({ error: 'Error during password verification.' });
      if (!isMatch) return res.status(401).json({ error: 'Current password is incorrect.' });

      bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Error hashing new password.' });

        db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, userId], function(err) {
          if (err) return res.status(500).json({ error: 'Failed to update password.' });
          res.json({ message: 'Password updated successfully.' });
        });
      });
    });
  });
});

app.get('/api/expenses/export', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  db.all('SELECT * FROM expenses WHERE user_id = ?', [userId], async (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Expenses');
    sheet.columns = [
      { header: 'Amount', key: 'amount', width: 15 },
      { header: 'Category', key: 'category', width: 25 },
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Description', key: 'description', width: 50 },
    ];

    rows.forEach(row => {
      // decrypt description
      let description = '';
      try {
        description = decrypt(row.description);
      } catch { }
      sheet.addRow({
        amount: row.amount,
        category: row.category,
        date: row.date,
        description: description,
      });
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=expenses.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  });
});

app.post('/api/expenses/import', requireLogin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(req.file.buffer);
    const sheet = workbook.getWorksheet('Expenses') || workbook.worksheets[0];
    const userId = req.session.userId;

    const insertStmt = db.prepare('INSERT INTO expenses (user_id, amount, category, date, description) VALUES (?, ?, ?, ?, ?)');

    for (let i = 2; i <= sheet.rowCount; i++) { // Skip header row
      const row = sheet.getRow(i);
      const amount = parseFloat(row.getCell('A').value);
      const category = (row.getCell('B').value || '').toString();
      const date = (row.getCell('C').value || '').toString();
      const description = (row.getCell('D').value || '').toString();

      if (isNaN(amount) || !date || !description) continue;

      const encryptedDesc = encrypt(description);
      insertStmt.run(userId, amount, category, date, encryptedDesc);
    }

    insertStmt.finalize();
    res.json({ message: 'Expenses imported successfully' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to import expenses: ' + e.message });
  }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

