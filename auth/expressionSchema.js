var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var ExpressionSchema = new Schema(
  {
    vehicle_id: Number,
    buyer_id: Number,
    message:String,
    contact_phone: Number,
    preferred_contact_time: String, 
     createdAt: String, 
     updatedAt: String,
    status: { 
      type: String, 
      enum: ['new','contacted','closed'], 
      default: 'new' 
    }
  },
  
     
  
);

const Expression = mongoose.model('expression', ExpressionSchema);

module.exports = Expression;