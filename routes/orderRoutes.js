const express = require('express');
const Order = require('../models/Order');
const User = require('../models/User');
const router = express.Router();

// render new order page
router.get('/new', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/users/login');
  }
  res.render('createOrder', { user: req.session.user });
});

router.post('/', async (req, res) => {
  try {
    const { products } = req.body;
    // calculate total price
    const total_amount = products.reduce((sum, product) => {
      const qty = product.quantity || 1;
      return sum + Number(product.price) * qty;
    }, 0);

    // create new order
    const newOrder = new Order({
      user_id: req.session.user.id,
      products, // array with product_id, product_name, quantity, and price
      total_amount,
      status: 'pending'
    });
    await newOrder.save();
    await User.findByIdAndUpdate(req.session.user.id, { $push: { order_history: newOrder._id } });
    res.status(201).json({ message: 'Order created successfully!' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Retrieve a specific order by its ID
router.get('/:id', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.redirect('/users/login');
    }
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).send('Order not found');
    }
    res.render('orderDetails', { order, user: req.session.user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// delete order
router.delete('/:id', async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.redirect('/');
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
