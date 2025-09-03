var mongoose = require ('mongoose');

var UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    role:String,
    phone:Number,
    city:String
})
mongoose.model('users',UserSchema);
module.exports = mongoose.model('users')