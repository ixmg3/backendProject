require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const path = require('path');
const methodOverride = require('method-override');
const User = require('./models/User');
const Product = require('./models/Product');
const Order = require('./models/Order');

const app = express();
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per windowMs
});
app.use(limiter);

// connect to atlas
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected...'))
  .catch((err) => console.error(err));

// middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(methodOverride('_method'));

// ejs setup 
app.set('view engine', 'ejs');

// more middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'supersecretkey',
    resave: false,
    saveUninitialized: false,
  })
);

// route imports
const userRoutes = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');
const orderRoutes = require('./routes/orderRoutes');
const adminRoutes = require('./routes/adminRoutes');

// use the routes
app.use('/users', userRoutes);
app.use('/products', productRoutes);
app.use('/orders', orderRoutes);
app.use('/admin', adminRoutes);

// home route
app.get('/', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/users/login');
  }
  const user = await User.findById(req.session.user.id);
  const orders = await Order.find({ user_id: req.session.user.id });
  const allProducts = await Product.find({}, 'product_name');
  res.render('index', { user, orders, allProducts });
});

// data manager for admins
app.get('/admin/data-manager', (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access Denied: Admins Only");
  }
  res.render('dataManager', { user: req.session.user });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Global error-handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // Set default status code to 500 if not already set
  const status = err.status || 500;
  
  // Respond with JSON if API, or render an error page if needed
  res.status(status).json({ error: err.message });
});