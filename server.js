const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const multer = require('multer'); 
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('Database connected!');
});

// Helper functions
const createToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
        expiresIn: '1h'
    });
};


const storage = multer.memoryStorage();
const upload = multer({ storage });
// Registration for astrologers
app.post('/register/astrologer', upload.single('profile_photo'), async (req, res) => {
    const {
        first_name, last_name, mobile_number, aadhar_number, dob, gender,
        experience_years, languages_known, skills, email, district,
        pin_code, rate_per_min, password
    } = req.body;

    const profile_photo = req.file ? req.file.buffer : null;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
        INSERT INTO astrologers (first_name, last_name, mobile_number, aadhar_number, dob, gender,
        experience_years, languages_known, skills, email, profile_photo, district, country, pin_code,
        rate_per_min, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'India', ?, ?, ?)
    `;

    db.query(query, [
        first_name, last_name, mobile_number, aadhar_number, dob, gender,
        experience_years, languages_known, skills, email, profile_photo, district,
        pin_code, rate_per_min, hashedPassword 
    ], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('An error occurred while registering the astrologer.');
        }
        res.status(201).send('Astrologer registered successfully!');
    });
});

// Registration for users
app.post('/register/user', async (req, res) => {
    const {
        first_name, last_name, dob, city, birthplace, mobile_number, birth_time, gender,
        email, district, pin_code,  password
    } = req.body;

    const profile_photo = req.file ? req.file.buffer : null;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
        INSERT INTO users (first_name, last_name, dob, city, birthplace, mobile_number, birth_time,
        gender, email, state, country, district, pin_code, profile_photo, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Maharashtra', 'India', ?, ?, ?, ?)
    `;

    db.query(query, [
        first_name, last_name, dob, city, birthplace, mobile_number, birth_time, gender,
        email, district, pin_code, profile_photo, hashedPassword
    ], (err, results) => {
        if (err) return res.status(500).send(err);
        res.status(201).send('User registered successfully!');
    });
});

// Login for astrologers
app.post('/login/astrologer', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM astrologers WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(400).send('No astrologer found with this email.');

        const astrologer = results[0];
        const isPasswordValid = await bcrypt.compare(password, astrologer.password);

        if (!isPasswordValid) return res.status(400).send('Invalid password.');

        const token = createToken(astrologer);
        res.status(200).json({ token });
    });
});

// Login for users
app.post('/login/user', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(400).send('No user found with this email.');

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) return res.status(400).send('Invalid password.');

        const token = createToken(user);
        res.status(200).json({ token });
    });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
