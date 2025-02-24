const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  "Product Name": { type: String, required: true },
  "Brand Desc": { type: String },
  "SellPrice": { type: Number, required: true },
  "Category": { type: String }
});

module.exports = mongoose.model('Product', productSchema);
