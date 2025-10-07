require('dotenv').config();
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
const Expression = require("./inquirySchema");
const nodemailer = require("nodemailer");

const multer = require("multer");

const storage = multer.memoryStorage();


const fileFilter = (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png"];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        const error = new Error("Only .jpg and .png formats are allowed!");
        error.status = 400; // optional
        cb(error, false);
    }
};

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
});

router.use(bodyParser.json({ limit: '10mb' })); // for JSON bodies
router.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

router.get("/users", async(req, res) => {
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

router.put("/blockUser/:id", async(req, res) => {
    try {
        const id = req.params.id;
        const existingUser = await User.findById(id);

        if (!existingUser) {
            return res.status(404).json({ message: "No user found with that ID" });
        }

        const updatedUser = await User.findByIdAndUpdate(
            id, { $set: { is_blocked: true, status: "blocked" } }, { new: true }
        );

        res.json({ success: true, data: updatedUser });
    } catch (err) {
        console.error("Error deactivating user:", err);
        res.status(500).json({ error: err.message });
    }
});

router.put("/unblockUser/:id", async(req, res) => {
    try {
        const id = req.params.id;
        const existingUser = await User.findById(id);

        if (!existingUser) {
            return res.status(404).json({ message: "No user found with that ID" });
        }

        const updatedUser = await User.findByIdAndUpdate(
            id, { $set: { is_blocked: false, status: "unblock" } }, { new: true }
        );

        res.json({ success: true, data: updatedUser });
    } catch (err) {
        console.error("Error activating user:", err);
        res.status(500).json({ error: err.message });
    }
});

router.get("/adminAudit", async(req, res) => {
    try {
        const audits = await AdminAudit.find().populate("actor_id");
        res.json(audits);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error while fetching audits" });
    }
});

router.get("/adminAudit/:id", async (req, res) => {
    try {
        const audits = await AdminAudit.find({target_id: req.params.id})

        if (audits.length === 0) {
            return res.status(404).json({ error: "No audits found for this target" });
        }

        res.json(audits);
    } catch (err) {
        console.error("Error fetching audit:", err);
        res.status(500).json({ error: "Server error while fetching audit" });
    }
});

router.get("/expressions", async(req, res) => {
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
    const buyer_id = req.user._id;
    const {
      listing_id,
      vehicle_name,
      vehicle_price,
      message,
      contact_phone,
      preferred_contact_time,
      status,
    } = req.body;

    // Validate required fields
    if (!buyer_id || !listing_id || !message || !contact_phone) {
      return res.status(400).json({
        error: "buyer_id, listing_id, message, and contact_phone are required.",
      });
    }

    // Update if exists, else create new
    const updatedExpression = await Expression.findOneAndUpdate(
      { buyer_id, listing_id }, // search condition
      {
        $set: {
          vehicle_name,
          vehicle_price,
          message,
          contact_phone,
          preferred_contact_time,
          status,
        },
      },
      { new: true, upsert: true } // return updated doc, create if not found
    );

    res.status(200).json(updatedExpression);
  } catch (err) {
    console.error("Error creating/updating expression:", err);
    res.status(500).json({ error: "Server error while creating/updating expression" });
  }
});

router.put("/expressions/:id", authMiddleware, async (req, res) => {
  try {
    const vehicleId = req.params.id;
    const {
      status,
    } = req.body;

    console.log('vehicleId:', vehicleId, status);
      const existingExpression = await Expression.findOne({
      listing_id: vehicleId,
      });

    if (!existingExpression) {
      return res.status(404).json({ message: "No expression found with that ID for this buyer" });
    }

    console.log("Existing Expression:", existingExpression);

    const updatedExpression = await Expression.findByIdAndUpdate(
     existingExpression._id,
      {
        $set: {
            
          status
          
        },
      },
      { new: true }
    );

    if (!updatedExpression) {
      return res.status(500).json({ message: "Failed to update expression" });
    }

    res.json({ success: true, data: updatedExpression });
  } catch (err) {
    console.error("Error updating expression:", err);
    res.status(500).json({ error: err.message });
  }
});

router.get("/expressions/:id", async(req, res) => {
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

router.get("/vehicledetails/:id", async(req, res) => {
    try {
        const vehicle = await Vehicledetail.findById(req.params.id);
        res.json(vehicle);
    } catch (err) {
        res.status(500).send(err);
    }
});

router.post("/signup", async (req, res) => {
  try {
    const { username, email, password, phone,name, city, avatar_url, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already registered with this email" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username, 
      email,
      password: hashedPassword,
      role, 
      name, 
      phone,
      city,
      avatar_url: avatar_url || "",
      is_blocked: false,
      created_at: new Date(),
      updated_at: new Date()
    });

    await newUser.save();

    res.status(200).json({ message: "Signup Success" });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ message: "Signup failed. Please try again" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).send({
        auth: false,
        message: "No User Found! Register First",
      });
    }

    if (user.is_blocked === "true") {
      return res.status(400).send({
        auth: false,
        message: "This user is blocked by admin",
      });
    }

    const passIsValid = bcrypt.compareSync(req.body.password, user.password);

    if (!passIsValid) {
      return res.status(401).send({
        auth: false,
        message: "Invalid password",
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      config.secret, 
      { expiresIn: 86400 }
    );

    return res.status(200).send({
      auth: true,
      token,
      user: {
        role: user.role,
        email: user.email,
        id: user._id,
      },
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).send({
      auth: false,
      message: "Error While Login",
    });
  }
});

router.get("/userInfo", (req, res) => {
    var token = req.headers["x-access-token"];
    if (!token) return res.send({ auth: false, token: "No Token Provided" });
    jwt.verify(token, config.secret, (err, user) => {
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

router.get("/vehicledetailsbuyer", async(req, res) => {
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
        if (minPrice) query.price = {...query.price, $gte: Number(minPrice) };
        if (maxPrice) query.price = {...query.price, $lte: Number(maxPrice) };
        if (minYear) query.year = {...query.year, $gte: Number(minYear) };
        if (maxYear) query.year = {...query.year, $lte: Number(maxYear) };
        if (minMileage)
            query.mileage = {...query.mileage, $gte: Number(minMileage) };
        if (maxMileage)
            query.mileage = {...query.mileage, $lte: Number(maxMileage) };

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

router.get("/vehicledetails", async(req, res) => {
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
        if (minPrice) query.price = {...query.price, $gte: Number(minPrice) };
        if (maxPrice) query.price = {...query.price, $lte: Number(maxPrice) };
        if (minYear) query.year = {...query.year, $gte: Number(minYear) };
        if (maxYear) query.year = {...query.year, $lte: Number(maxYear) };
        if (minMileage)
            query.mileage = {...query.mileage, $gte: Number(minMileage) };
        if (maxMileage)
            query.mileage = {...query.mileage, $lte: Number(maxMileage) };
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

router.get("/vehicledetails/:id", async(req, res) => {
    try {
        const vehicle = await Vehicledetail.findById(req.params.id);
        res.json(vehicle);
    } catch (err) {
        res.status(500).send(err);
    }
});

router.get("/vehicledetails/total", async(req, res) => {
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
        if (minPrice) query.price = {...query.price, $gte: Number(minPrice) };
        if (maxPrice) query.price = {...query.price, $lte: Number(maxPrice) };
        if (minYear) query.year = {...query.year, $gte: Number(minYear) };
        if (maxYear) query.year = {...query.year, $lte: Number(maxYear) };
        if (minMileage)
            query.mileage = {...query.mileage, $gte: Number(minMileage) };
        if (maxMileage)
            query.mileage = {...query.mileage, $lte: Number(maxMileage) };
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
    async(req, res) => {
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
                "status"
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
  })

router.put(
    "/deactivatevehicledetail/:id",
    authMiddleware,
    upload.array("images", 5),
    async(req, res) => {
        try {
            const id = req.params.id;
            const existingVehicle = await Vehicledetail.findById(id);

            if (!existingVehicle) {
                return res
                    .status(404)
                    .json({ message: "No vehicle found with that ID" });
            }

            const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
                id, {
                    $set: { isActive: false, status: "rejected" },
                }, { new: true }
            );

            if (!updatedVehicle) {
                return res.status(500).json({ message: "Failed to update vehicle" });
            }

            const auditQuery = { target_id: updatedVehicle._id, target_type: "listing" };
            const auditData = {
                actor_id: req.user._id,
                action: "deactivate_listing",
                target_type: "listing",
                target_id: updatedVehicle._id,
                from_status: existingVehicle.status || "approved",
                to_status: "rejected",
                status: "rejected",
                reason: req.body.reason || null,
            };

            const existingAudit = await AdminAudit.findOne(auditQuery);
            if (existingAudit) {
                await AdminAudit.findByIdAndUpdate(existingAudit._id, { $set: auditData });
            } else {
                await AdminAudit.create(auditData);
            }

            res.json({ success: true, data: updatedVehicle });
        } catch (err) {
            console.error("Error deactivating vehicle:", err);
            res.status(500).json({ error: err.message });
        }
    }
);

router.put(
    "/sold/:id",
    authMiddleware,
    // upload.array("images", 5),
    async(req, res) => {
        try {
            const id = req.params.id;
            const existingVehicle = await Vehicledetail.findById(id);
            if (!existingVehicle) {
                return res
                    .status(404)
                    .json({ message: "No vehicle found with that ID" });
            }

            const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
                id, { $set: { isActive: false, status: "sold" } }, { new: true }
            );

            if (!updatedVehicle) {
                return res.status(500).json({ message: "Failed to update vehicle" });
            }

            const auditQuery = {
                target_id: updatedVehicle._id,
                target_type: "listing"
            };

            const auditData = {
                actor_id: req.user._id,
                action: "approve_listing",
                target_type: "listing",
                target_id: updatedVehicle._id,
                from_status: existingVehicle.status || "pending",
                to_status: "sold",
                status: "sold",
                reason: req.body.reason || null,
            };

            const existingAudit = await AdminAudit.findOne(auditQuery);

            if (existingAudit) {
                await AdminAudit.findByIdAndUpdate(existingAudit._id, { $set: auditData });
            } else {
                await AdminAudit.create(auditData);
            }

            res.json({ success: true, data: updatedVehicle });
        } catch (err) {
            console.error("Error activating vehicle:", err);
            res.status(500).json({ error: err.message });
        }
    }
);

router.put(
    "/activatevehicledetail/:id",
    authMiddleware,
    upload.array("images", 5),
    async(req, res) => {
        try {
            const id = req.params.id;
            const existingVehicle = await Vehicledetail.findById(id);

            if (!existingVehicle) {
                return res
                    .status(404)
                    .json({ message: "No vehicle found with that ID" });
            }

            const updatedVehicle = await Vehicledetail.findByIdAndUpdate(
                id, { $set: { isActive: true, status: "approved" } }, { new: true }
            );

            if (!updatedVehicle) {
                return res.status(500).json({ message: "Failed to update vehicle" });
            }

            const auditQuery = {
                target_id: updatedVehicle._id,
                target_type: "listing"
            };

            const auditData = {
                actor_id: req.user._id,
                action: "approve_listing",
                target_type: "listing",
                target_id: updatedVehicle._id,
                from_status: existingVehicle.status || "pending",
                to_status: "approved",
                status: "approved",
                reason: req.body.reason || null,
            };

            const existingAudit = await AdminAudit.findOne(auditQuery);

            if (existingAudit) {
                await AdminAudit.findByIdAndUpdate(existingAudit._id, { $set: auditData });
            } else {
                await AdminAudit.create(auditData);
            }

            res.json({ success: true, data: updatedVehicle });
        } catch (err) {
            console.error("Error activating vehicle:", err);
            res.status(500).json({ error: err.message });
        }
    }
);

router.delete("/deletevehicledetail/:id", async(req, res) => {
    try {
        const id = req.params.id;
        const deletedVehicle = await Vehicledetail.findByIdAndDelete(id);

        if (!deletedVehicle) {
            return res.status(404).res.json({data:"No vehicle found with that ID"});
        }

        return res.json({data:"Data Deleted"});
    } catch (err) {
        console.error("Error deleting vehicle:", err);
        res.status(500).json({"error":err.message});
    }
});

router.get("/buyerStatus", async (req, res) => {
  try {
    const expressions = await Expression.find()
      .populate("buyer_id"); 

    res.json(expressions);
  } catch (err) {
    console.error("Error fetching buyer statuses:", err);
    res.status(500).json({ error: "Server error while fetching buyer statuses" });
  }
});

router.get("/buyerStatus/:id", async (req, res) => {
  try {
    const expression = await Expression.find({listing_id: req.params.id}).populate("buyer_id");

    if (!expression) {
      return res.status(404).json({ error: "Buyer status not found" });
    }

    res.json(expression);
  } catch (err) {
    console.error("Error fetching buyer status by ID:", err);
    res.status(500).json({ error: "Server error while fetching buyer status" });
  }
});

router.post('/forgotpassword', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).send('User not found');
        const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const transporter = nodemailer.createTransport({
            service: 'gmail', 
            auth: {
                user: 'santanupaikaray1996@gmail.com',
                pass: 'ofeo xnql hagr fpzk', 
            },
        });
        const resetLink = `http://localhost:4200/resetpassword?token=${resetToken}`;
        const mailOptions = {
            from: 'santanupaikaray1996@gmail.com',
            to: email,
            subject: 'Password Reset',
            text: `Click on this link to reset your password: ${resetLink}`,
        };
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message:'Password reset email sent successfully'});
    } catch (err) {
        console.error(err);
        res.status(500).json({message:'Internal Server Error'});
    }
});

router.post('/resetpassword', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.RESET_PASSWORD_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.password = bcrypt.hashSync(newPassword, 8);
    await user.save();
    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    }
    res.status(400).json({ message: 'Invalid token' });
  }
});

router.get('/resetpassword', async (req, res) => {
  const { token } = req.query;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ message: 'Token is valid', id: decoded.id });
  } catch (err) {
    console.error(err);
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Reset token has expired' });
    }
    res.status(400).json({ message: 'Invalid token' });
  }
});

module.exports = router;