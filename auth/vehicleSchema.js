var mongoose = require ('mongoose');

var VehicleSchema = new mongoose.Schema({
    vehicle_id:Number,
    seller_id:Number,
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
    mileage_km:Number,
    isActive:Boolean,
     created_at:String,
    updated_at:String,
    
status: { type: String, enum: ["approved", "rejected", "sold","draft"], default: "draft" },
     images: [
    {
      filename: String,
      mimetype: String,
      data: String, 
    },
  ],


})

const Vehicledetail = mongoose.model('vehicledetail',VehicleSchema);

module.exports = Vehicledetail;