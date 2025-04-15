const express = require('express');
const pool = require('./db/db');
const cors = require('cors');
const helmet = require('helmet');
const protectedRoutes = require('./middleware/protectedRoutes');
const registerRoutes = require('./routes/register');
const loginRoutes = require('./routes/login');
const app = express();
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || "yourSuperSecretKey";

const corsOptions = {
    origin: ['http://localhost:5000', 'http://localhost:5173'], 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors(corsOptions));
app.use(helmet());


app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    next();
});

app.use('/api/register', registerRoutes);
app.use('/api/login', loginRoutes);

app.get('/protected', protectedRoutes, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

app.get('/', (req, res) => {
    res.send({ message: 'Test' });
});

app.listen(5000, () => {
    console.log(`Server is running on http://localhost:${5000}`);
});