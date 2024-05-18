const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [
    {
      name: {
        type: String,
        required: true
      },
      price: {
        type: Number,
        required: true
      },
      quantity: {
        type: Number,
        required: true,  // Ensure quantity is required
        default: 1  // Default quantity is 1
      }
    }
  ],
  total: {
    type: Number,
    required: true
  }
});

const Order = mongoose.model('Order', OrderSchema);

module.exports = Order;
