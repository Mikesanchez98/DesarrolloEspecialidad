const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');

dotenv.config();

const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'secret';

const users = [
    { username: 'admin', password: 'admin' }
];

const sessions = {};

const secureCookieOptions = () => ({
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}));

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/csrf-token', (req, res) => {
    const csrfToken = new csrf().create(SECRET_KEY);
    res.json({ csrfToken });
});

app.post('/login', (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({error: 'Invalid CSRF token'});
    }

    if (!username || !password) {
        return res.status(400).json({error: 'Usuario y contraseña son requeridos.'});
    }

    const user = users.find(user => user.username.toLowerCase() == username.toLowerCase());
    if (!user || user.password !== password) {
        return res.status(401).json({error: 'Usuario o contraseña incorrectos.'})
    }

    const sessionId = crypto.randomBytes(16).toString('base64url');
    sessions[sessionId] = { username };
    res.cookie('sessionId', sessionId, secureCookieOptions());
    res.status(200).json({ message: 'Login succesful' });
});

app.listen(port, () => {
    console.log(`Server listening at http:/localhost:${port}`);
});