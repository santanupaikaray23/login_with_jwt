var mongoose = require ('mongoose');

var UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    role:String,
    phone:Number,
    city:String,
    is_blocked: { type: Boolean, default: false },
    created_at:String,
    updated_at:String

  
})

mongoose.model('User',UserSchema);

module.exports = mongoose.model('User')