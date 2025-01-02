const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Ambil token dari header
    if (!token) return res.status(401).json({ message: 'Token is missing' });

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Token is invalid' });
        req.user = user; // Simpan data user dari token
        next();
    });
};

module.exports = authenticateToken;
