const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');//npm i  jsonwebtoken
const cors = require('cors');
const cookieParser = require('cookie-parser'); //npm i cookie-parser

const app = express();
const port = process.env.PORT || 5000;

mongoose.connect('mongodb://localhost:27017/signup')
.then(() => {
  console.log('Connected to database');
  seedAdminUser(); // Seed admin user if not exists
})
.catch((err) => {
  console.error('Database connection error:', err);
});

const SignupSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  roles: [{ type: String, enum: ['reader', 'creator', 'admin'], required: true }]
});

const SignupCollection = mongoose.model('signupcollection', SignupSchema);

app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000', 
  credentials: true,
}));
app.use(cookieParser());

const secret = 'your_jwt_secret';

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.sendStatus(401);

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.sendStatus(403);
    }
    req.user = decoded;
    next();
  });
};

const authorizeRole = (roles) => (req, res, next) => {
  if (!roles.some(role => req.user.roles.includes(role))) {
    return res.sendStatus(403);
  }
  next();
};

app.post('/signup', async (req, res) => {
  const { username, email, password, roles } = req.body;

  try {
    const existingUser = await SignupCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const newUser = new SignupCollection({ username, email, password, roles });
    const savedUser = await newUser.save();
    const userToReturn = savedUser.toObject();
    delete userToReturn.password;

    res.status(201).json(userToReturn);
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ message: 'Something went wrong while saving data' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await SignupCollection.findOne({ email });
    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id, roles: user.roles }, secret, { expiresIn: '15m' });
    res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 15 * 60 * 1000 }); // Set cookie with token
    res.status(200).json({ user: { username: user.username, email: user.email, roles: user.roles } });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Something went wrong while logging in' });
  }
});

app.get('/dashboard', authenticateToken, authorizeRole(['reader', 'creator', 'admin']), (req, res) => {
  res.status(200).json({ role: req.user.roles });
});

async function seedAdminUser() {
  try {
    const adminUsers = [
      { username: 'Admin1', email: 'admin1@example.com', password: 'Admin1234', roles: ['admin'] },
      { username: 'Admin2', email: 'admin2@example.com', password: 'Admin5678', roles: ['admin'] },
      // Add more admin users as needed
    ];

    for (const userData of adminUsers) {
      const { email } = userData;
      const existingAdmin = await SignupCollection.findOne({ email });
      if (!existingAdmin) {
        const adminUser = new SignupCollection(userData);
        await adminUser.save();
        console.log(`Admin user created: ${email}`);
      }
    }
  } catch (error) {
    console.error('Error seeding admin users:', error);
  }
}

app.listen(port, () => {
  console.log(`App is listening on port ${port}`);
});
