require('dotenv').config()
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const User = require('./model/user');
const mongoose = require('mongoose');
const app = express();
app.use(express.json());

// Secret key for JWT
const secretKey = process.env.SECRET_KEY;

// Database connection
const dbUrl = process.env.MONGO_URI;
mongoose.connect(dbUrl, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to the database');
    })
    .catch((error) => {
        console.error('Database connection error:', error);
    });


// Home Route 
app.get('/', (req, res) => {
    return res.send("Welcome to the Home Route ")
})

// Signup route
app.post('/signup', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        // Check if the email is already registered
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ name, email, password: hashedPassword, phone });
        await newUser.save();

        return res.status(200).json({
            message: 'User created successfully',
            name: name,
            email: email,
            phonenumber: phone
        });
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    try {
        // Destructuring of Request Body data 
        const { email, password } = req.body;

        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare the entered password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

        return res.status(200).json({ token });
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});
// Protected route
app.get('/protected', (req, res) => {
    const token = req.headers.authorization;
    console.log(token)
    if (!token) {
        return res.status(401).json({ error: 'Missing token' });
    }

    try {
        const decoded = jwt.verify(token, secretKey);
        console.log("hiiii decoded")
        const userId = decoded.userId;
        console.log("userid : ", userId)
        // Access the protected resource with the userId
        // Example: Fetch user data from the database
        User.findById(userId, (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Return the protected resource
            return res.json({ message: 'Wohoo Access to Protected resource', user });
        });
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
});


const port = process.env.PORT || 8000
app.listen(port, () => {
    console.log(`Server Started at ${port}`)
})