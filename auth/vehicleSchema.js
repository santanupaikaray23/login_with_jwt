var mongoose = require ('mongoose');

var VehicleSchema = new mongoose.Schema({
    id:Number,
    sellerid:Number,
    title:String,
    make:String,
    model:String,
    variant:String,
    year:Number,
    fueltype:String,
    transmission:String,
    ownercount:Number,
    registrationstate:String,
    price:Number,
    description:String,
    locationcity:String,
    localpincode:Number,
    status:String,
    statushistory:String,
    mileage:Number,
    isActive:Boolean,
     images: [
    {
      filename: String,
      mimetype: String,
      data: String, // base64 string
    },
  ],


})

const Vehicledetail = mongoose.model('vehicledetail',VehicleSchema);

module.exports = Vehicledetail;