const express = require ('express');
const router = express.Router();
const bodyParser = require ('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require ('bcryptjs');
const config = require('../config');
const User = require('./userSchema');
const Vehicledetail = require('./vehicleSchema')


router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json())

let tokenBlacklist = [];
//get all users
router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err;
        res.send(data)
    })
})
//register User
router.post('/signup',(req,res)=>{
    var hashpassword = bcrypt.hashSync(req.body.password,8)
    User.create({
        name:req.body.name,
        password:hashpassword,
        email:req.body.email,
        role:req.body.role?req.body.role:'User',
        phone:req.body.phone,
        city:req.body.city
    },(err,user) => {
        if(err) return res.status(500).send({message:'Signup failed. Please try again'})
        res.status(200).json({ message:'Signup Success'});
    })
})
//login user
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
//profile
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
router.get('/vehicledetails',(req,res)=>{
    Vehicledetail.find({},(err,data)=>{
        if(err) throw err;
        res.send(data)
    })
})
// Insert
router.post('/addvehicledetail', async (req, res) => {
  try {
    console.log("Request body:", req.body);

    const vehicle = new Vehicledetail(req.body);
    await vehicle.save();

    res.status(201).send('Data Added');
  } catch (err) {
    console.error('Error adding vehicle:', err);
    res.status(500).json({ error: err.message, details: err });
  }
});

router.put('/updatevehicledetail', async (req, res) => {
  try {
    const id = req.body._id;

    const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
      id,
      {
        $set: {
          sellerid: req.body.sellerid,
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
          images: req.body.images,
          isActive: true,
        },
      },
      { new: true } 
    );

    if (!updatedVehicle) {
      return res.status(404).send('No vehicle found with that ID');
    }

    res.send('Data Updated');
  } catch (err) {
    console.error('Error updating vehicle:', err);
    res.status(500).send(err.message);
  }
});
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

module.exports = router
