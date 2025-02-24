const express = require('express');
const Product = require('../models/Product');
const router = express.Router();

router.get('/search', async (req, res) => {
  try {
    const { query } = req.query;

    // search by words, regardless of word order
    if (!query) return res.json([]);
    const words = query.trim().split(/\s+/);
    const regexConditions = words.map(word => ({
      "Brand Desc": { $regex: word, $options: 'i' }
    }));
    
    const products = await Product.find({ $and: regexConditions });
    if (!req.session.user) {
      return res.redirect('/users/login');
    }
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
