const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Product = require('../models/Product');
const Order = require('../models/Order');


// admin only restriction
router.use((req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send("Access Denied: Admins Only");
  }
  next();
});

// render new product
router.get('/new-product', (req, res) => {
    res.render('newProduct');
});

// new product func
router.post('/new-product', async (req, res) => {
    try {
      const { productName, brandDesc, sellPrice, category } = req.body;
      const newProduct = new Product({
        "Product Name": productName,
        "Brand Desc": brandDesc,
        SellPrice: sellPrice,
        Category: category
      });
      await newProduct.save();
      res.redirect('/admin/data-manager');
    } catch (error) {
      res.status(500).send(error.message);
    }
  });

// render edit product
router.get('/edit-product/:id', async (req, res) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product) {
        return res.status(404).send("Product not found");
      }
      res.render('editProduct', { product });
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
  
// edit product
router.post('/edit-product/:id', async (req, res) => {
    try {
        const { productName, brandDesc, sellPrice, category } = req.body;
        
        const updatedProduct = await Product.findByIdAndUpdate(
        req.params.id,
        {
            "Product Name": productName,
            "Brand Desc": brandDesc,
            SellPrice: sellPrice,
            Category: category
        },
        { new: true }
        );
        
        if (!updatedProduct) {
        return res.status(404).send("Product not found");
        }
        res.redirect('/admin/data-manager');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// montly sales report
router.get('/reports/monthly-sales', async (req, res) => {
    try {
      const monthlySales = await Order.aggregate([
        // Only consider completed orders
        { $match: { status: "completed" } },
        // Group orders by year and month (using order_date)
        { $group: {
            _id: { year: { $year: "$order_date" }, month: { $month: "$order_date" } },
            totalSales: { $sum: "$total_amount" },
            orderCount: { $sum: 1 }
        } },
        // Sort by year then month ascending
        { $sort: { "_id.year": 1, "_id.month": 1 } }
      ]);
      res.json(monthlySales);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  });
  
// stats by category
router.get('/reports/product-stats', async (req, res) => {
    try {
        const productStats = await Product.aggregate([
        { $group: {
            _id: "$Category",   // Assuming your product field for category is "Category"
            avgPrice: { $avg: "$SellPrice" },
            minPrice: { $min: "$SellPrice" },
            maxPrice: { $max: "$SellPrice" },
            count: { $sum: 1 }
        } },
        { $sort: { avgPrice: 1 } }
        ]);
        res.json(productStats);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// seearch for users by email
router.get('/search-users', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.json([]);
    const users = await User.find({ email: new RegExp(email, 'i') });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// get all products
router.get('/all-products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// get all products by a criteria
router.get('/search-products', async (req, res) => {
  try {
    const { criteria, query } = req.query;
    if (!criteria || !query) return res.json([]);
    let filter = {};
    if (criteria === "SellPrice") {
      filter[criteria] = Number(query);
    } else {
      filter[criteria] = new RegExp(query, 'i');
    }
    const products = await Product.find(filter);
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// search product by the given field
router.get('/sort-products', async (req, res) => {
  try {
    const { field, order } = req.query;
    const sortOrder = order === 'asc' ? 1 : -1;
    const products = await Product.find({}).sort({ [field]: sortOrder });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// render edit form
router.get('/edit-user/:id', async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      // Find orders for this user
      const orders = await Order.find({ user_id: req.params.id });
      if (!user) return res.status(404).send("User not found");
      res.render('editUser', { user, orders });
    } catch (error) {
      res.status(500).send(error.message);
    }
  });

// update user info
router.post('/edit-user/:id', async (req, res) => {
    try {
      const { name, email, role, address } = req.body;
      await User.findByIdAndUpdate(req.params.id, { name, email, role, address }, { new: true });
      res.redirect('/admin/edit-user/' + req.params.id);
    } catch (error) {
      res.status(500).send(error.message);
    }
  });
  
// update order info
router.post('/edit-order/:id', async (req, res) => {
    try {
      const { order_date, total_amount, status, products } = req.body;
      const updatedOrder = await Order.findByIdAndUpdate(req.params.id, {
        order_date: new Date(order_date),
        total_amount: Number(total_amount),
        status,
        products: products.map(prod => ({
          product_id: prod.product_id,
          product_name: prod.product_name,
          quantity: Number(prod.quantity),
          price: Number(prod.price)
        }))
      }, { new: true });
      res.redirect('/admin/edit-user/' + updatedOrder.user_id);
    } catch (error) {
      res.status(500).send(error.message);
    }
  });

router.get('/data-manager', (req, res) => {
  res.render('dataManager', { user: req.session.user });
});

module.exports = router;
