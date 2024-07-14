// app.js
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static('public'));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'NIs@0509',
    database: 'ctf'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database');
});

const admins = [
    { username: 'admin', password: bcrypt.hashSync('admin', 8), role: 'admin' },
    { username: 'superadmin', password: bcrypt.hashSync('superadmin', 8), role: 'superadmin' }
];
const jwtSecret = 'your_jwt_secret';

app.get('/login', (req, res) => {
    res.render('login', { user: req.user });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const admin = admins.find(user => user.username === username);
    if (!admin || !bcrypt.compareSync(password, admin.password)) {
        return res.status(401).send('Unauthorized');
    }

    const token = jwt.sign({ username: admin.username, role: admin.role }, jwtSecret, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/highscore');
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) return res.status(401).send('Unauthorized');

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).send('Forbidden');
        res.locals.user = user;
        req.user = user;
        next();
    });
}

function isSuperAdmin(req, res, next) {
    if (req.user.role !== 'superadmin') {
        return res.status(403).send('Forbidden');
    }
    next();
}

app.get('/highscore', authenticateToken, (req, res) => {
    db.query('SELECT username, first_name, last_name, total_points FROM players ORDER BY total_points ASC', (err, results) => {
        if (err) throw err;
        res.render('highscore', { players: results });
    });
});

app.get('/manage-players', authenticateToken, isSuperAdmin, (req, res) => {
    db.query('SELECT * FROM players', (err, results) => {
        if (err) throw err;
        res.render('manage-players', { players: results });
    });
});

app.post('/manage-players/add', authenticateToken, isSuperAdmin, (req, res) => {
    const { username, password, first_name, last_name } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    db.query('INSERT INTO players (username, password, first_name, last_name) VALUES (?, ?, ?, ?)', [username, hashedPassword, first_name, last_name], (err) => {
        if (err) throw err;
        res.redirect('/manage-players');
    });
});

app.post('/manage-players/delete', authenticateToken, isSuperAdmin, (req, res) => {
    const { username } = req.body;
    db.query('DELETE FROM players WHERE username = ?', [username], (err) => {
        if (err) throw err;
        res.redirect('/manage-players');
    });
});




app.get('/manage-flags', authenticateToken, isSuperAdmin, (req, res) => {
    db.query('SELECT * FROM flags', (err, results) => {
        if (err) throw err;
        res.render('manage-flags', { flags: results });
    });
});

app.post('/manage-flags/add', authenticateToken, isSuperAdmin, (req, res) => {
    const { flag, points } = req.body;
    db.query('INSERT INTO flags (flag, points) VALUES (?, ?)', [flag, points], (err) => {
        if (err) throw err;
        res.redirect('/manage-flags');
    });
});

app.post('/manage-flags/delete', authenticateToken, isSuperAdmin, (req, res) => {
    const { flag } = req.body;
    db.query('DELETE FROM flags WHERE flag = ?', [flag], (err) => {
        if (err) throw err;
        res.redirect('/manage-flags');
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
