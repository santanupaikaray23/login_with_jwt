const express = require("express");
const router = express.Router();
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const config = require("../config");
const User = require("./userSchema");
const Vehicledetail = require("./vehicleSchema");
const AdminAudit = require("./adminAuditSchema");
const authMiddleware = require("../middleware/authMiddleware");
const Expression = require("./expressionSchema");

const multer = require("multer");

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

router.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json({
      success: true,
      count: users.length,
      data: users,
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: err.message });
  }
});

router.put("/blockUser/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const existingUser = await User.findById(id);

    if (!existingUser) {
      return res.status(404).json({ message: "No user found with that ID" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { $set: { is_blocked: true, status: "blocked" } },
      { new: true }
    );

    res.json({ success: true, data: updatedUser });
  } catch (err) {
    console.error("Error deactivating user:", err);
    res.status(500).json({ error: err.message });
  }
});

router.put("/unblockUser/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const existingUser = await User.findById(id);

    if (!existingUser) {
      return res.status(404).json({ message: "No user found with that ID" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { $set: { is_blocked: false, status: "unblock" } },
      { new: true }
    );

    res.json({ success: true, data: updatedUser });
  } catch (err) {
    console.error("Error activating user:", err);
    res.status(500).json({ error: err.message });
  }
});

// Read
router.get("/adminAudit", async (req, res) => {
  try {
    const audits = await AdminAudit.find().populate("actor_id");
    res.json(audits);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error while fetching audits" });
  }
});

router.get("/expressions", async (req, res) => {
  try {
    const expressions = await Expression.find()
      .populate("listing_id")
      .populate("buyer_id");

    res.json(expressions);
  } catch (err) {
    console.error("Error fetching expressions:", err);
    res.status(500).json({ error: "Server error while fetching expressions" });
  }
});

router.post("/addExpressions", authMiddleware, async (req, res) => {
  try {
    const buyer_id = req.user?._id;
    const {
      listing_id,
      vehicle_name,
      vehicle_price,
      message,
      contact_phone,
      preferred_contact_time,
      status,
    } = req.body;
    if (!buyer_id || !listing_id || !message || !contact_phone) {
      return res.status(400).json({
        error: "buyer_id, listing_id, message, and contact_phone are required.",
      });
    }
    const expression = new Expression({
      buyer_id,
      listing_id,
      vehicle_name,
      vehicle_price,
      message,
      contact_phone,
      preferred_contact_time,
      status,
    });

    const savedExpression = await expression.save();

    res.status(201).json(savedExpression);
  } catch (err) {
    console.error("Error creating expression:", err);
    res.status(500).json({ error: "Server error while creating expression" });
  }
});

router.get("/expressions/:id", async (req, res) => {
  try {
    const expression = await Expression.findById(req.params.id)
      .populate("buyer_id")
      .populate("listing_id");

    if (!expression) {
      return res.status(404).json({ error: "Expression not found" });
    }

    res.json(expression);
  } catch (err) {
    console.error("Error fetching expression by ID:", err);
    res.status(500).json({ error: "Server error while fetching expression" });
  }
});

router.get("/vehicledetails/:id", async (req, res) => {
  try {
    const vehicle = await Vehicledetail.findById(req.params.id);
    res.json(vehicle);
  } catch (err) {
    res.status(500).send(err);
  }
});
// router.put(
//   "/expressions/:id",
//   authMiddleware,
//   async (req, res) => {
//     try {
//       const id = req.params.id;
//       const existingExpression = await Expression.findById(id);

//       if (!existingExpression) {
//         return res.status(404).json({ message: "No expression found with that ID" });
//       }

//       const updatedExpression = await Expression.findByIdAndUpdate(
//         id,
//         {
//      $set: {
//   message: req.body.message,
//   contact_phone: req.body.contact_phone,
//   preferred_contact_time: req.body.preferred_contact_time,
//   status: req.body.status || existingExpression.status,
//   updated_at: new Date()
// }
//         },
//         { new: true }
//       );

//       if (!updatedExpression) {
//         return res.status(500).json({ message: "Failed to update expression" });
//       }
//       res.json({ success: true, data: updatedExpression });
//     } catch (err) {
//       console.error("Error updating expression:", err);
//       res.status(500).json({ error: err.message });
//     }
//   }
// );

router.post("/signup", (req, res) => {
  var hashpassword = bcrypt.hashSync(req.body.password, 8);
  User.create(
    {
      name: req.body.name,
      password: hashpassword,
      email: req.body.email,
      role: req.body.role ? req.body.role : "Admin",
      phone: req.body.phone,
      city: req.body.city,
      is_blocked: false,
      created_at: req.body.created_at,
      updated_at: req.body.updated_at,
    },
    (err) => {
      if (err)
        return res
          .status(500)
          .send({ message: "Signup failed. Please try again" });
      res.status(200).json({ message: "Signup Success" });
    }
  );
});
router.post("/login", (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (user && user.is_blocked == "true") {
      return res
        .status(400)
        .send({ auth: false, message: "This user is blocked by admin" });
    }
    if (err)
      return res
        .status(500)
        .send({ auth: false, message: "Error While Login" });
    if (!user)
      return res
        .status(404)
        .send({ auth: false, message: "No User Found! Register First" });
    const passIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passIsValid)
      return res.status(401).send({ auth: false, message: "Invalid password" });
    const token = jwt.sign({ id: user._id, role: user.role }, config.secert, {
      expiresIn: 86400,
    });
    res.status(200).send({
      auth: true,
      token: token,
      user: {
        role: user.role,
      },
    });
  });
});
router.get("/userInfo", (req, res) => {
  var token = req.headers["x-access-token"];
  if (!token) return res.send({ auth: false, token: "No Token Provided" });
  jwt.verify(token, config.secert, (err, user) => {
    if (err) return res.send({ auth: false, token: "Invalid Token" });
    User.findById(user.id, (err, result) => {
      res.send(result);
    });
  });
});
router.post("/logout", (req, res) => {
  const token = req.headers["x-access-token"] || req.body.token;
  if (token) {
    tokenBlacklist.push(token);
  }
  res.status(200).send({ auth: false, token: "Logged out" });
});
function verifyToken(req, res, next) {
  const token = req.headers["x-access-token"];
  if (!token)
    return res.status(403).send({ auth: false, token: "No token provided." });

  if (tokenBlacklist.includes(token)) {
    return res
      .status(401)
      .send({
        auth: false,
        token: "Token is blacklisted. Please login again.",
      });
  }
  jwt.verify(token, config.secret, (err, decoded) => {
    if (err)
      return res
        .status(500)
        .send({ auth: false, token: "Failed to authenticate token." });
    req.userId = decoded.id;
    next();
  });
}

router.get("/vehicledetailsbuyer", async (req, res) => {
  var query = {};
  query = { isActive: true };
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
      sort,
    } = req.query;

    page = parseInt(page);
    limit = parseInt(limit);

    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1) limit = 10;

    const skip = (page - 1) * limit;

    let query = { isActive: true };

    if (search) {
      query.$or = [
        { make: new RegExp(search, "i") },
        { model: new RegExp(search, "i") },
        { title: new RegExp(search, "i") },
        { description: new RegExp(search, "i") },
      ];
    }
    if (fueltype) query.fueltype = fueltype;
    if (transmissions) query.transmission = transmissions;
    if (locationcity) query.locationcity = locationcity;
    if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
    if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
    if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
    if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
    if (minMileage)
      query.mileage = { ...query.mileage, $gte: Number(minMileage) };
    if (maxMileage)
      query.mileage = { ...query.mileage, $lte: Number(maxMileage) };

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
      Vehicledetail.find(query).sort(sortOption).skip(skip).limit(limit),
      Vehicledetail.countDocuments(query),
    ]);

    res.json({
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// Read
router.get("/vehicledetails", async (req, res) => {
  var query = {};
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
      sort,
    } = req.query;
    page = parseInt(page);
    limit = parseInt(limit);
    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1) limit = 10;
    const skip = (page - 1) * limit;
    if (search) {
      query.$or = [
        { make: new RegExp(search, "i") },
        { model: new RegExp(search, "i") },
        { title: new RegExp(search, "i") },
        { description: new RegExp(search, "i") },
      ];
    }
    if (fueltype) query.fueltype = fueltype;
    if (transmissions) query.transmission = transmissions;
    if (locationcity) query.locationcity = locationcity;
    if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
    if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
    if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
    if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
    if (minMileage)
      query.mileage = { ...query.mileage, $gte: Number(minMileage) };
    if (maxMileage)
      query.mileage = { ...query.mileage, $lte: Number(maxMileage) };
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
      Vehicledetail.find(query).sort(sortOption).skip(skip).limit(limit),
      Vehicledetail.countDocuments(query),
    ]);

    res.json({
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/vehicledetails/:id", async (req, res) => {
  try {
    const vehicle = await Vehicledetail.findById(req.params.id);
    res.json(vehicle);
  } catch (err) {
    res.status(500).send(err);
  }
});

router.get("/vehicledetails/total", async (req, res) => {
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
      maxMileage,
    } = req.query;
    const query = {};
    if (search) {
      query.$or = [
        { make: new RegExp(search, "i") },
        { model: new RegExp(search, "i") },
        { title: new RegExp(search, "i") },
        { description: new RegExp(search, "i") },
      ];
    }
    if (fueltype) query.fueltype = fueltype;
    if (transmissions) query.transmission = transmissions;
    if (locationcity) query.locationcity = locationcity;
    if (minPrice) query.price = { ...query.price, $gte: Number(minPrice) };
    if (maxPrice) query.price = { ...query.price, $lte: Number(maxPrice) };
    if (minYear) query.year = { ...query.year, $gte: Number(minYear) };
    if (maxYear) query.year = { ...query.year, $lte: Number(maxYear) };
    if (minMileage)
      query.mileage = { ...query.mileage, $gte: Number(minMileage) };
    if (maxMileage)
      query.mileage = { ...query.mileage, $lte: Number(maxMileage) };
    const total = await Vehicledetail.countDocuments(query);
    res.json({ total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

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
        "mileage_km",
        "created_at",
        "updated_at",
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
          .json({
            success: false,
            error: "Owner count must be greater than 0.",
          });
      }
      const pincodePattern = /^[0-9]{6}$/;
      if (!pincodePattern.test(req.body.localpincode)) {
        return res
          .status(400)
          .json({ success: false, error: "Pincode must be exactly 6 digits." });
      }
      const validFuelTypes = ["Petrol", "Diesel", "Electric"];
      if (!validFuelTypes.includes(req.body.fueltype)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid fuel type." });
      }
      const validTransmissions = ["Automatic", "Manual", "Electric"];
      if (!validTransmissions.includes(req.body.transmission)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid transmission type." });
      }
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
        mileage_km: req.body.mileage_km,
        created_at: req.body.created_at,
        updated_at: req.body.updated_at,
        status: req.body.status || "draft",
        images: req.files.map((f) => ({
          filename: f.originalname,
          mimetype: f.mimetype,
          data: f.buffer.toString("base64"),
        })),
      };

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
        mileage_km: req.body.mileage_km,
        created_at: req.body.created_at,
      };

      let updatedImages = existingVehicle.images || [];

      if (req.files && req.files.length > 0) {
        const indexes = req.body.imageIndexes
          ? JSON.parse(req.body.imageIndexes)
          : [];

        req.files.forEach((file, i) => {
          const slotIndex = indexes[i];
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
  authMiddleware,
  upload.array("images", 5),
  async (req, res) => {
    try {
      const id = req.params.id;
      const existingVehicle = await Vehicledetail.findById(id);

      if (!existingVehicle) {
        return res
          .status(404)
          .json({ message: "No vehicle found with that ID" });
      }

      const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
        id,
        { $set: { isActive: false, status: "rejected" } },
        { new: true }
      );

      await AdminAudit.create({
        actor_id: req.user?._id,
        action: "deactivate_listing",
        target_type: "listing",
        target_id: updatedVehicle._id,
        from_status: existingVehicle.status || "approved",
        to_status: "deactivated",
        status: "deactivated",
        reason: req.body.reason || null,
      });

      res.json({ success: true, data: updatedVehicle });
    } catch (err) {
      console.error("Error deactivating vehicle:", err);
      res.status(500).json({ error: err.message });
    }
  }
);

router.put(
  "/activatevehicledetail/:id",
  authMiddleware,
  upload.array("images", 5),
  async (req, res) => {
    try {
      const id = req.params.id;
      const existingVehicle = await Vehicledetail.findById(id);

      if (!existingVehicle) {
        return res
          .status(404)
          .json({ message: "No vehicle found with that ID" });
      }

      const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
        id,
        { $set: { isActive: true, status: "approved" } },
        { new: true }
      );

      if (!updatedVehicle) {
        return res.status(500).json({ message: "Failed to update vehicle" });
      }

      await AdminAudit.create({
        actor_id: req.user?._id,
        action: "approve_listing",
        target_type: "listing",
        target_id: updatedVehicle._id,
        from_status: existingVehicle.status || "pending",
        to_status: "approved",
        status: "approved",
        reason: req.body.reason || null,
      });

      res.json({ success: true, data: updatedVehicle });
    } catch (err) {
      console.error("Error activating vehicle:", err);
      res.status(500).json({ error: err.message });
    }
  }
);

router.delete("/deletevehicledetail", async (req, res) => {
  try {
    const id = req.body._id;
    const deletedVehicle = await Vehicledetail.findByIdAndDelete(id);
    if (!deletedVehicle) {
      return res.status(404).send("No vehicle found with that ID");
    }
    res.send("Data Deleted");
  } catch (err) {
    console.error("Error deleting vehicle:", err);
    res.status(500).send(err.message);
  }
});

router.delete("/deletevehicledetail/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const deletedVehicle = await Vehicledetail.findByIdAndDelete(id);

    if (!deletedVehicle) {
      return res.status(404).send("No vehicle found with that ID");
    }

    res.send("Data Deleted");
  } catch (err) {
    console.error("Error deleting vehicle:", err);
    res.status(500).send(err.message);
  }
});

module.exports = router;
