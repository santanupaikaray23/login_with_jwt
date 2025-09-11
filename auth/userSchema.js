var mongoose = require ('mongoose');

var UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    role:String,
    phone:Number,
    city:String,
    is_blocked: { type: Boolean, default: false }
  
})

mongoose.model('User',UserSchema);

module.exports = mongoose.model('User')