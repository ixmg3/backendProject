const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const Joi = require('joi');
const methodOverride = require('method-override');

const router = express.Router();

router.use(methodOverride('_method'));

// Joi Validation Schemas
// Registration schema
const registerSchema = Joi.object({
  name: Joi.string().min(3).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  confirm_password: Joi.any()
    .valid(Joi.ref('password'))
    .required()
    .messages({ 'any.only': 'Passwords must match' }),
  role: Joi.string().optional(),
  address: Joi.object({
    street: Joi.string().optional(),
    city: Joi.string().optional(),
    zipcode: Joi.string().optional()
  }).optional()
});

// Login schema
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

// Profile update schema
const profileSchema = Joi.object({
  name: Joi.string().min(3).max(50).required(),
  email: Joi.string().email().required(),
  street: Joi.string().optional(),
  city: Joi.string().optional(),
  zipcode: Joi.string().optional()
});


// redner login
router.get('/login', (req, res) => {
  res.render('login');
});

// render registration
router.get('/register', (req, res) => {
  res.render('register');
});

// register functionality
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirm_password, role, address } = req.body;
    
    // passwords match
    if (password !== confirm_password) {
      return res.send(`<script>alert("Passwords do not match"); window.location.href="/users/register";</script>`);
    }

    // duplicate check
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.send(`<script>alert("User already exists with that email"); window.location.href="/users/register";</script>`);
    }

    const newUser = new User({
      name,
      email,
      password,
      role: role || 'user', // its always user cuz you cant make yourself admin
      address
    });

    await newUser.save();

    return res.send(`<script>alert("User registered successfully!"); window.location.href="/users/login";</script>`);
  } catch (error) {
    return res.send(`<script>alert("Error: ${error.message}"); window.location.href="/users/register";</script>`);
  }
});



// login functionality
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // search by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.send(`<script>alert("User not found"); window.location.href="/users/login";</script>`);
    }
    
    // match passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.send(`<script>alert("Invalid credentials"); window.location.href="/users/login";</script>`);
    }
    
    // store session info
    req.session.user = { id: user._id, role: user.role, name: user.name };

    return res.send(`<script>alert("Logged in successfully!"); window.location.href="/";</script>`);
    } catch (error) {
    return res.send(`<script>alert("Error: ${error.message}"); window.location.href="/users/login";</script>`);
  }
});

// logout
router.get('/logout', (req, res) => {
  res.redirect('/users/login');
});


// profile (user info) edit
router.put('/profile', async (req, res) => {
  try {
    console.log('PUT /profile request body:', req.body);

    if (!req.session.user) {
      return res.send(`<script>alert("Unauthorized"); window.location.href="/users/login";</script>`);
    }

    const { name, email, street, city, zipcode } = req.body;
    const userId = req.session.user.id;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        name, 
        email, 
        address: { street, city, zipcode } 
      },
      { new: true, runValidators: true }
    );

    console.log('Updated user:', updatedUser);

    // Update session info if needed
    req.session.user.name = updatedUser.name;
    req.session.user.email = updatedUser.email;

    return res.send(`<script>alert("Profile updated successfully!"); window.location.href="/";</script>`);
  } catch (error) {
    console.error('Error updating profile:', error);
    return res.send(`<script>alert("Error: ${error.message}"); window.location.href="/";</script>`);
  }
});

module.exports = router;
