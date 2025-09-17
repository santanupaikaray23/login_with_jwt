const express = require ('express');
const router = express.Router();
const bodyParser = require ('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require ('bcryptjs');
const config = require('../config');
const User = require('./userSchema');
const Vehicledetail = require('./vehicleSchema');
const adminAuditSchema = require('./adminAuditSchema')

const multer = require("multer");

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json())

let tokenBlacklist = [];
router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err;
        res.send(data)
    })
})
router.post('/signup',(req,res)=>{
    var hashpassword = bcrypt.hashSync(req.body.password,8)
    User.create({
        name:req.body.name,
        password:hashpassword,
        email:req.body.email,
        role:req.body.role?req.body.role:'Admin',
        phone:req.body.phone,
        city:req.body.city,
        is_blocked: false,
        created_at:req.body.created_at,
        updated_at:req.body.updated_at


    },(err) => {
        if(err) return res.status(500).send({message:'Signup failed. Please try again'})
        res.status(200).json({ message:'Signup Success'});
    })
})
router.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) return res.status(500).send({ auth: false, message: 'Error While Login' });
    if (!user) return res.status(404).send({ auth: false, message: 'No User Found! Register First' });
    const passIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passIsValid) return res.status(401).send({ auth: false, message: 'Invalid password' });
    const token = jwt.sign(
      { id: user._id, role: user.role }, 
      config.secert,
      { expiresIn: 86400 }
    );
    res.status(200).send({
      auth: true,
      token: token,
      user: {
        // id: user._id,
        // email: user.email,
        role: user.role
      }
    });
  });
});
router.get('/userInfo',(req,res) => {
    var token = req.headers ['x-access-token'];
    if(!token) return res.send({auth:false,token:'No Token Provided'});
    jwt.verify(token,config.secert,(err,user)=>{
        if(err) return res.send({auth:false,token:'Invalid Token'});
        User.findById(user.id,(err,result)=>{
            res.send(result)
        })
    })
})
router.post('/logout', (req, res) => {
    const token = req.headers['x-access-token'] || req.body.token;
    if (token) {
        tokenBlacklist.push(token);
    }
    res.status(200).send({ auth: false, token: 'Logged out' });
});
function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send({ auth: false, token: 'No token provided.' });

    if (tokenBlacklist.includes(token)) {
        return res.status(401).send({ auth: false, token: 'Token is blacklisted. Please login again.' });
    }
jwt.verify(token, config.secret, (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, token: 'Failed to authenticate token.' });
        req.userId = decoded.id;
        next();
    });
}
// Read
router.get('/vehicledetails', async (req, res) => {
  var query = {}
  query = {isActive:true}
  try {
    let { 
      page = 1, 
      limit = 10,
      search,
      fueltype,
      transmissions,
      locationcity,
      minPrice,
      maxPrice,
      minYear,
      maxYear,
      minMileage,
      maxMileage,
      sort 
    } = req.query;

    page = parseInt(page);
    limit = parseInt(limit);

    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1) limit = 10;

const skip = (page - 1) * limit;

    let query = { isActive: true }; 

if (search) {
  query.$or = [
    { make: new RegExp(search, 'i') },
    { model: new RegExp(search, 'i') },
    { title: new RegExp(search, 'i') },
    { description: new RegExp(search, 'i') }
  ];
}
if (fueltype) query.fueltype = fueltype;
if (transmissions) query.transmission = transmissions;
if (locationcity) query.locationcity = locationcity;
if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
if (minMileage) query.mileage = { ...query.mileage, $gte: Number(minMileage) };
if (maxMileage) query.mileage = { ...query.mileage, $lte: Number(maxMileage) };

    let sortOption = {};
    switch (sort) {
      case "newest":
        sortOption = { createdAt: -1 }; 
        break;
      case "price_low":
        sortOption = { price: 1 };
        break;
      case "price_high":
        sortOption = { price: -1 };
        break;
      case "year":
        sortOption = { year: -1 };
        break;
      default:
        sortOption = {}; 
    }

    const [data, total] = await Promise.all([
      Vehicledetail.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit),
      Vehicledetail.countDocuments(query) 
    ]);

    res.json({
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// router.get('/vehicledetails', async (req, res) => {
//   try {
//     let { 
//       page = 1, 
//       limit = 10,
//       search,
//       fueltype,
//       transmissions,
//       locationcity,
//       minPrice,
//       maxPrice,
//       minYear,
//       maxYear,
//       minMileage,
//       maxMileage,
//       sort 
//     } = req.query;

//     page = parseInt(page);
//     limit = parseInt(limit);

//     if (isNaN(page) || page < 1) page = 1;
//     if (isNaN(limit) || limit < 1) limit = 10;

//     const skip = (page - 1) * limit;

//     // Always enforce isActive = true
//     const query = { isActive: true };

//     if (search) {
//       query.$or = [
//         { make: new RegExp(search, 'i') },
//         { model: new RegExp(search, 'i') },
//         { title: new RegExp(search, 'i') },
//         { description: new RegExp(search, 'i') }
//       ];
//     }
//     if (fueltype) query.fueltype = fueltype;
//     if (transmissions) query.transmission = transmissions;
//     if (locationcity) query.locationcity = locationcity;
//     if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
//     if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
//     if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
//     if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
//     if (minMileage) query.mileage = { ...query.mileage, $gte: Number(minMileage) };
//     if (maxMileage) query.mileage = { ...query.mileage, $lte: Number(maxMileage) };

//     let sortOption = {};
//     switch (sort) {
//       case "newest":
//         sortOption = { createdAt: -1 }; 
//         break;
//       case "price_low":
//         sortOption = { price: 1 };
//         break;
//       case "price_high":
//         sortOption = { price: -1 };
//         break;
//       case "year":
//         sortOption = { year: -1 };
//         break;
//       default:
//         sortOption = {}; 
//     }

//     const [data, total] = await Promise.all([
//       Vehicledetail.find(query)
//         .sort(sortOption)
//         .skip(skip)
//         .limit(limit),
//       Vehicledetail.countDocuments(query) 
//     ]);

//     res.json({
//       data,
//       total,
//       page,
//       limit,
//       totalPages: Math.ceil(total / limit)
//     });

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

router.get('/vehicledetails/total', async (req, res) => {
  try {
    let { 
      search,
      fueltype,
      transmissions,
      locationcity,
      minPrice,
      maxPrice,
      minYear,
      maxYear,
      minMileage,
      maxMileage
    } = req.query;
    const query = {};
    if (search) {
      query.$or = [
        { make: new RegExp(search, 'i') },
        { model: new RegExp(search, 'i') },
        { title: new RegExp(search, 'i') },
        { description: new RegExp(search, 'i') }
      ];
    }
    if (fueltype) query.fueltype = fueltype;
    if (transmissions) query.transmission = transmissions;
    if (locationcity) query.locationcity = locationcity;
    if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
    if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
    if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
    if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
    if (minMileage) query.mileage = { ...query.mileage, $gte: Number(minMileage) };
    if (maxMileage) query.mileage = { ...query.mileage, $lte: Number(maxMileage) };

    const total = await Vehicledetail.countDocuments(query);

    res.json({ total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// Inserts
// router.post('/addvehicledetail', async (req, res) => {
//   try {
//     console.log("Request body:", req.body);
//     const vehicle = new Vehicledetail(req.body);
//     await vehicle.save();
//  res.status(201).send('Data Added');
//   } catch (err) {
//     console.error('Error adding vehicle:', err);
//     res.status(500).json({ error: err.message, details: err });
//   }
// });

// router.put('/updatevehicledetail', async (req, res) => {
//   try {
//     const id = req.body._id;
//     const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
//       id,
//       {
//         $set: {
//           sellerid: req.body.sellerid,
//           title: req.body.title,
//           make: req.body.make,
//           model: req.body.model,
//           variant: req.body.variant,
//           year: req.body.year,
//           fueltype: req.body.fueltype,
//           transmission: req.body.transmission,
//           ownercount: req.body.ownercount,
//           registrationstate: req.body.registrationstate,
//           price: req.body.price,
//           description: req.body.description,
//           locationcity: req.body.locationcity,
//           localpincode: req.body.localpincode,
//           images: req.body.images,
//           mileage: req.body.mileage,
//           isActive: true,
//         },
//       },
//       { new: true } 
//     );
//     if (!updatedVehicle) {
//       return res.status(404).send('No vehicle found with that ID');
//     }
//   res.send('Data Updated');
//   } catch (err) {
//     console.error('Error updating vehicle:', err);
//     res.status(500).send(err.message);
//   }
// });

router.post(
  "/addvehicledetail",
  upload.array("images", 5),
  async (req, res) => {
    try {
      console.log("Body fields:", req.body);
      console.log("Files:", req.files);

      const requiredFields = [
        "title",
        "make",
        "model",
        "variant",
        "year",
        "fueltype",
        "transmission",
        "ownercount",
        "registrationstate",
        "price",
        "description",
        "locationcity",
        "localpincode",
        "status",
        "statushistory",
        "isActive"
      ];

      for (const field of requiredFields) {
        if (!req.body[field] || req.body[field].toString().trim() === "") {
          return res
            .status(400)
            .json({ success: false, error: `${field} is required.` });
        }
      }

      const year = parseInt(req.body.year, 10);
      if (isNaN(year) || year < 1900 || year > new Date().getFullYear()) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid year provided." });
      }

      const price = parseFloat(req.body.price);
      if (isNaN(price) || price <= 0) {
        return res
          .status(400)
          .json({ success: false, error: "Price must be a positive number." });
      }

      const ownercount = parseInt(req.body.ownercount, 10);
      if (isNaN(ownercount) || ownercount <= 0) {
        return res
          .status(400)
          .json({ success: false, error: "Owner count must be greater than 0." });
      }


      const pincodePattern = /^[0-9]{6}$/;
      if (!pincodePattern.test(req.body.localpincode)) {
        return res
          .status(400)
          .json({ success: false, error: "Pincode must be exactly 6 digits." });
      }

      // Validate fuel type
      const validFuelTypes = ["Petrol", "Diesel", "Electric"];
      if (!validFuelTypes.includes(req.body.fueltype)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid fuel type." });
      }

      // Validate transmission
      const validTransmissions = ["Automatic", "Manual", "Electric"];
      if (!validTransmissions.includes(req.body.transmission)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid transmission type." });
      }

      // Build the object for MongoDB
      const vehicleData = {
        title: req.body.title.trim(),
        make: req.body.make.trim(),
        model: req.body.model.trim(),
        variant: req.body.variant,
        year,
        fueltype: req.body.fueltype,
        transmission: req.body.transmission,
        ownercount,
        registrationstate: req.body.registrationstate,
        price,
        description: req.body.description,
        locationcity: req.body.locationcity,
        localpincode: req.body.localpincode,
        status: req.body.status,
        statushistory: req.body.statushistory,
        isActive: req.body.isActive,
        images: req.files.map(f => ({
          filename: f.originalname,
          mimetype: f.mimetype,
          data: f.buffer.toString("base64"),
        })),
      };

      // Save to DB using mongoose
      const vehicle = new Vehicledetail(vehicleData);
      await vehicle.save();

      res.status(201).json({ success: true, vehicle });
    } catch (err) {
      console.error("Error saving vehicle:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  }
);

router.put(
  "/updatevehicledetail/:id",
  upload.array("images", 5),
  async (req, res) => {
    try {
      const id = req.params.id;
      const existingVehicle = await Vehicledetail.findById(id);
      if (!existingVehicle) {
        return res.status(404).send("No vehicle found with that ID");
      }

      // Build update object (excluding images first)
      const vehicleData = {
        title: req.body.title,
        make: req.body.make,
        model: req.body.model,
        variant: req.body.variant,
        year: req.body.year,
        fueltype: req.body.fueltype,
        transmission: req.body.transmission,
        ownercount: req.body.ownercount,
        registrationstate: req.body.registrationstate,
        price: req.body.price,
        description: req.body.description,
        locationcity: req.body.locationcity,
        localpincode: req.body.localpincode,
        status: req.body.status,
        statushistory: req.body.statushistory,
        isActive: true
      };

      let updatedImages = existingVehicle.images || [];

      if (req.files && req.files.length > 0) {
        // frontend will send imageIndexes[] aligned with files[]
        const indexes = req.body.imageIndexes
          ? JSON.parse(req.body.imageIndexes)
          : [];

        req.files.forEach((file, i) => {
          const slotIndex = indexes[i]; // which slot to replace
          const newImage = {
            data: file.buffer.toString("base64"),
            mimetype: file.mimetype,
            filename: file.originalname,
          };
          if (typeof slotIndex === "number") {
            updatedImages[slotIndex] = newImage;
          }
        });

        vehicleData.images = updatedImages;
      }

      const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
        id,
        { $set: vehicleData },
        { new: true }
      );

      res.json(updatedVehicle);
    } catch (err) {
      console.error("Error updating vehicle:", err);
      res.status(500).send(err.message);
    }
  }
);

router.put(
  "/deactivatevehicledetail/:id",
  upload.array("images", 5),
  async (req, res) => {
    try {
      const id = req.params.id;
      const existingVehicle = await Vehicledetail.findById(id);

      if (!existingVehicle) {
        return res.status(404).send("No vehicle found with that ID");
      }

      // Always set isActive to false
      const vehicleData = {  
        isActive: false,
        images: existingVehicle.images || []  // initialize with existing images
      };

      // If new files are uploaded, add them
      if (req.files && req.files.length > 0) {
        const newImages = req.files.map((file) => ({
          data: file.buffer.toString("base64"),
          mimetype: file.mimetype,
          filename: file.originalname,
        }));
        vehicleData.images = [...vehicleData.images, ...newImages];
      }

      // Update vehicle details
      const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
        id,
        { $set: vehicleData },
        { new: true }
      );

      res.json(updatedVehicle);
    } catch (err) {
      console.error("Error updating vehicle:", err);
      res.status(500).send(err.message);
    }
  }
);

router.put(
  "/activatevehicledetail/:id",
  upload.array("images", 5),
  async (req, res) => {
    try {
      const id = req.params.id;
      const existingVehicle = await Vehicledetail.findById(id);

      if (!existingVehicle) {
        return res.status(404).send("No vehicle found with that ID");
      }

      // Always set isActive to true
      const vehicleData = {  
        isActive: true,
        images: existingVehicle.images || [] // keep old images
      };

      // If new files are uploaded, add them
      if (req.files && req.files.length > 0) {
        const newImages = req.files.map((file) => ({
          data: file.buffer.toString("base64"),
          mimetype: file.mimetype,
          filename: file.originalname,
        }));
        vehicleData.images = [...vehicleData.images, ...newImages];
      }

      // Update vehicle details
      const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
        id,
        { $set: vehicleData },
        { new: true }
      );

      res.json(updatedVehicle);
    } catch (err) {
      console.error("Error updating vehicle:", err);
      res.status(500).send(err.message);
    }
  }
);

router.delete('/deletevehicledetail', async (req, res) => {
  try {
    const id = req.body._id;
    const deletedVehicle = await Vehicledetail.findByIdAndDelete(id);
    if (!deletedVehicle) {
      return res.status(404).send('No vehicle found with that ID');
    }
    res.send('Data Deleted');
  } catch (err) {
    console.error('Error deleting vehicle:', err);
    res.status(500).send(err.message);
  }
});

router.delete('/deletevehicledetail/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const deletedVehicle = await Vehicledetail.findByIdAndDelete(id);

    if (!deletedVehicle) {
      return res.status(404).send('No vehicle found with that ID');
    }

    res.send('Data Deleted');
  } catch (err) {
    console.error('Error deleting vehicle:', err);
    res.status(500).send(err.message);
  }
});

module.exports = router
