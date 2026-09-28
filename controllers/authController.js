const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userModel = require("../models/userModel");

async function login(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const normalizedEmail = email.trim();

        const user = await userModel.findUserByEmail(
            normalizedEmail
        );

        if (!user) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const passwordValid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordValid) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "2h"
            }
        );

        res.json({
            message: "Login successful.",
            token,
            user: {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            error: "Unable to login."
        });
    }
}

async function register(req, res) {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "Name, email and password are required."
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                error: "Passwords do not match."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        // Check whether user already exists
        const existingUser = await userModel.findUserByEmail(
            normalizedEmail
        );

        if (existingUser) {
            return res.status(409).json({
                error: "Email is already registered."
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create user
        const user = await userModel.createUser({
            name: name.trim(),
            email: normalizedEmail,
            password_hash: passwordHash
        });

        res.status(201).json({
            message: "Registration successful.",
            user: {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            error: "Unable to register."
        });
    }
}

module.exports = {
    login,
    register
};