const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/db');
const Joi = require('joi');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const registerSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required().messages({
        'string.alphanum': 'Username must contain only letters and numbers',
        'string.min': 'Username must be at least 3 characters',
        'string.max': 'Username cannot exceed 30 characters',
        'string.empty': 'Username is required'
    }),
    email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'string.empty': 'Email is required'
    }),
    password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])')).required().messages({
        'string.min': 'Password must be at least 8 characters',
        'string.pattern.base': 'Password must contain at least one lowercase, uppercase, number, and special character',
        'string.empty': 'Password is required'
    }),
    role: Joi.string().valid('user', 'admin').default('user')
});

router.post('/', [
    body('username').trim().notEmpty().isAlphanumeric().isLength({ min: 3, max: 30 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    })
], async (req, res) => {
    try {
        const schemaValidation = registerSchema.validate(req.body, { abortEarly: false });
        if (schemaValidation.error) {
            return res.status(400).json({
                errors: schemaValidation.error.details.map(detail => ({
                    field: detail.path[0],
                    message: detail.message
                }))
            });
        }

        const expressValidatorErrors = validationResult(req);
        if (!expressValidatorErrors.isEmpty()) {
            return res.status(400).json({ errors: expressValidatorErrors.array() });
        }

        const { username, email, password, role = 'user' } = req.body;

        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(409).json({ error: 'Email already in use' });
        }

        const usernameCheck = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (usernameCheck.rows.length > 0) {
            return res.status(409).json({ error: 'Username already taken' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role',
            [username, email, hashedPassword, role]
        );

        const user = result.rows[0];
        const token = jwt.sign(
            { 
                id: user.id,
                role: user.role 
            },
            process.env.JWT_SECRET,
            { 
                expiresIn: '1h'
            }
        );

        res.status(201).json({ 
            message: 'User registered successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            token 
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ 
            error: 'Registration failed',
            ...(process.env.NODE_ENV !== 'production' && { details: err.message })
        });
    }
});

module.exports = router;