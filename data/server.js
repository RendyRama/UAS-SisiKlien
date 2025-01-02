const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;
const SECRET_KEY = 'admin123';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Koneksi ke Database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', 
    password: '', 
    database: 'bencana', 
    port: 3306,
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');
});

// **API Endpoints**

// GET semua data bencana
app.get('/api/bencana', (req, res) => {
    const sql = 'SELECT * FROM bencana_gunung';
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// GET satu data bencana berdasarkan ID
app.get('/api/bencana/:id', (req, res) => {
    const sql = 'SELECT * FROM bencana_gunung WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length === 0) return res.status(404).json({ message: 'Data not found' });
        res.json(result[0]);
    });
});

// POST buat data bencana baru dengan validasi
app.post(
    '/api/bencana',
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'INSERT INTO bencana_gunung (nama_gunung, status_aktivitas, rekomendasi, laporan) VALUES (?, ?, ?, ?)';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: result.insertId, nama_gunung, status_aktivitas, rekomendasi, laporan });
        });
    }
);

// PUT update data bencana dengan validasi
app.put(
    '/api/bencana/:id',
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'UPDATE bencana_gunung SET nama_gunung = ?, status_aktivitas = ?, rekomendasi = ?, laporan = ? WHERE id = ?';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan, req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: req.params.id, nama_gunung, status_aktivitas, rekomendasi, laporan });
        });
    }
);

// DELETE hapus data bencana
app.delete(
    '/api/bencana/:id',
    [check('id').isInt().withMessage('ID must be an integer')],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const sql = 'DELETE FROM bencana_gunung WHERE id = ?';
        db.query(sql, [req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Data deleted successfully' });
        });
    }
);

// **API Register**
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
        db.query(checkEmailSql, [email], async (err, results) => {
            if (err) return res.status(500).json({ error: err.message });

            if (results.length > 0) {
                return res.status(409).json({ message: 'Email already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const insertSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
            db.query(insertSql, [name, email, hashedPassword], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// **API Login**
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
});

// Middleware untuk Auth
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access denied' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Endpoint Terproteksi
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

// Jalankan server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});




// // Endpoint Statistik Bencana
// app.get('/api/bencana/stats', (req, res) => {
//     const sql = `
//         SELECT 
//             COUNT(*) AS total,
//             SUM(CASE WHEN status_aktivitas = 'Normal' THEN 1 ELSE 0 END) AS normal,
//             SUM(CASE WHEN status_aktivitas = 'Waspada' THEN 1 ELSE 0 END) AS waspada,
//             SUM(CASE WHEN status_aktivitas = 'Siaga' THEN 1 ELSE 0 END) AS siaga,
//             SUM(CASE WHEN status_aktivitas = 'Awas' THEN 1 ELSE 0 END) AS awas
//         FROM bencana_gunung;
//     `;
//     db.query(sql, (err, result) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(result[0]);
//     });
// });

/*const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const { check, validationResult } = require('express-validator');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Koneksi ke Database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Ganti jika username MySQL Anda berbeda
    password: '', // Ganti jika password MySQL Anda ada
    database: 'bencana', // Ganti dengan nama database
    port: 3306 // Pastikan ini sesuai dengan port MySQL Anda
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');
});

// API Endpoints

// GET semua data bencana
app.get('/api/bencana', (req, res) => {
    const sql = 'SELECT * FROM bencana_gunung';
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// GET satu data bencana berdasarkan ID
app.get('/api/bencana/:id', (req, res) => {
    const sql = 'SELECT * FROM bencana_gunung WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length === 0) return res.status(404).json({ message: 'Data not found' });
        res.json(result[0]);
    });
});

// POST buat data bencana baru dengan validasi
app.post(
    '/api/bencana',
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'INSERT INTO bencana_gunung (nama_gunung, status_aktivitas, rekomendasi, laporan) VALUES (?, ?, ?, ?)';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: result.insertId, nama_gunung, status_aktivitas, rekomendasi, laporan });
        });
    }
);

// PUT update data bencana dengan validasi
app.put(
    '/api/bencana/:id',
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'UPDATE bencana_gunung SET nama_gunung = ?, status_aktivitas = ?, rekomendasi = ?, laporan = ? WHERE id = ?';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan, req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Data updated successfully' });
        });
    }
);

// DELETE hapus data bencana
app.delete(
    '/api/bencana/:id',
    [check('id').isInt().withMessage('ID must be an integer')],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const sql = 'DELETE FROM bencana_gunung WHERE id = ?';
        db.query(sql, [req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Data deleted successfully' });
        });
    }
);

// Jalankan server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
*/

/* TOKEN
// Import modules
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

const app = express();
const PORT = 5000;
const SECRET_KEY = 'your_secret_key'; // Ganti dengan kunci rahasia Anda

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(morgan('combined'));

// Koneksi ke Database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'bencana',
    port: 3306,
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');
});

// Middleware untuk autentikasi token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        req.user = user;
        next();
    });
};

// API Endpoints

// GET semua data bencana dengan pagination
app.get('/api/bencana', authenticateToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const sql = 'SELECT * FROM bencana_gunung LIMIT ? OFFSET ?';
    db.query(sql, [limit, offset], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

// GET satu data bencana berdasarkan ID
app.get('/api/bencana/:id', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM bencana_gunung WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.length === 0) return res.status(404).json({ message: 'Data not found' });
        res.json(result[0]);
    });
});

// POST buat data bencana baru dengan validasi
app.post(
    '/api/bencana',
    authenticateToken,
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'INSERT INTO bencana_gunung (nama_gunung, status_aktivitas, rekomendasi, laporan) VALUES (?, ?, ?, ?)';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: result.insertId, nama_gunung, status_aktivitas, rekomendasi, laporan });
        });
    }
);

// PUT update data bencana dengan validasi
app.put(
    '/api/bencana/:id',
    authenticateToken,
    [
        check('nama_gunung').notEmpty().withMessage('Nama Gunung is required'),
        check('status_aktivitas')
            .isIn(['Normal', 'Waspada', 'Siaga', 'Awas'])
            .withMessage('Invalid status aktivitas'),
        check('rekomendasi').notEmpty().withMessage('Rekomendasi is required'),
        check('laporan').notEmpty().withMessage('Laporan is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }

        const { nama_gunung, status_aktivitas, rekomendasi, laporan } = req.body;
        const sql = 'UPDATE bencana_gunung SET nama_gunung = ?, status_aktivitas = ?, rekomendasi = ?, laporan = ? WHERE id = ?';
        db.query(sql, [nama_gunung, status_aktivitas, rekomendasi, laporan, req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Data updated successfully' });
        });
    }
);

// DELETE hapus data bencana
app.delete('/api/bencana/:id', authenticateToken, (req, res) => {
    const sql = 'DELETE FROM bencana_gunung WHERE id = ?';
    db.query(sql, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Data deleted successfully' });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Jalankan server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

*/
