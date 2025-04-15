const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/db');
const Joi = require('joi');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const loginSchema = Joi.object({
    email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'string.empty': 'Email is required'
    }),
    password: Joi.string().min(8).required().messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.empty': 'Password is required'
    })
});

router.post('/', [
    body('email')
        .isEmail()
        .withMessage('Please provide a valid email')
        .normalizeEmail(),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
], async (req, res) => {
    try {
        const schemaValidation = loginSchema.validate(req.body, { abortEarly: false });
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

        const { email, password } = req.body;

        const result = await pool.query('SELECT id, email, password_hash, role FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

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

        res.status(200).json({ 
            message: 'Login successful', 
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ 
            error: 'Authentication failed',
            ...(process.env.NODE_ENV !== 'production' && { details: err.message })
        });
    }
});

module.exports = router;