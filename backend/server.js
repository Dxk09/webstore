require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require('path');

// ===== App Configuration =====
const app = express();
app.use(express.json());
app.use(cors());

// ===== Environment Variables =====
const PORT = process.env.PORT || 5001;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://khandxk:gZg3hupQwPIJANuY@bookbyte.5a0f0.mongodb.net/?retryWrites=true&w=majority&appName=BookByte";
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_here";

// ===== Database Connection =====
mongoose.connect(MONGODB_URI)
    .then(() => console.log("MongoDB Connected"))
    .then(() => console.log("Please direct to http://localhost:5001"))
    .catch(err => console.error("MongoDB Connection Error:", err));

// ===== Models =====
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// ===== Middleware =====
const auth = (req, res, next) => {
    const token = req.header("x-auth-token");

    if (!token) {
        return res.status(401).json({ msg: "No token, authorization denied" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        return res.status(401).json({ msg: "Token is not valid" });
    }//b
};

// ===== Helper Functions =====
const generateToken = (userId) => {
    const payload = {
        user: { id: userId }
    };

    return new Promise((resolve, reject) => {
        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: "1h" },
            (err, token) => {
                if (err) reject(err);
                resolve(token);
            }
        );
    });
};

// ===== API Routes =====
// Test route
app.get('/api/test', (req, res) => {
    res.json({ msg: 'API is working' });
});

// Auth Routes
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ msg: "All fields are required" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ msg: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        const token = await generateToken(user.id);

        res.status(201).json({
            token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (err) {
        console.error("Registration error:", err.message);
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ msg: "All fields are required" });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: "Invalid credentials" });
        }

        const token = await generateToken(user.id);

        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (err) {
        console.error("Login error:", err.message);
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});

app.get("/api/user", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        if (!user) {
            return res.status(404).json({ msg: "User not found" });
        }
        res.json(user);
    } catch (err) {
        console.error("User fetch error:", err.message);
        res.status(500).json({ msg: "Server Error", error: err.message });
    }
});

// ===== Static File Serving =====
// This must come AFTER the API routes to avoid blocking them
app.use(express.static(path.join(__dirname, 'public')));

// Catch-all route - send index.html for any route not matched by the API
app.get('*', (req, res) => {
    console.log("Serving index.html for path:", req.path);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== Server Initialization =====
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Public directory path: ${path.join(__dirname, 'public')}`);
    console.log(`Index file path: ${path.join(__dirname, 'public', 'index.html')}`);
});