const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  order_date: { type: Date, default: Date.now },
  products: [
    {
      product_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      product_name: { type: String, required: true },
      quantity: { type: Number, default: 1 },
      price: { type: Number, required: true } // Price at time of order
    }
  ],
  total_amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' }
});

module.exports = mongoose.model('Order', orderSchema);
