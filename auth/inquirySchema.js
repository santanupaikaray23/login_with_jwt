var mongoose = require("mongoose");

var ExpressionSchema = new mongoose.Schema({
   sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "Seller", required: true },
  buyer_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  listing_id: { type: String, required: true },
  vehicle_name: { type: String, required: false },
  vehicle_price: { type: Number, required: false },
  message: { type: String, required: true },
  contact_phone: { type: String, match: /^[0-9]{10}$/, required: true },
  preferred_contact_time: { type: String },
  status: {
    type: String,
    enum: ["new", "contacted", "closed"],
    default: "new",
  },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Expression", ExpressionSchema);
