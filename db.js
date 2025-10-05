const User = require("./auth/userSchema");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");

async function seedAdmin() {
  try {
    const adminEmail = "admin@example.com";
    let existingAdmin = await User.findOne({ email: adminEmail });

    const hashedPassword = await bcrypt.hash("admin123", 10);

    if (!existingAdmin) {
      const adminUser = new User({
        name: "Admin Name",
        email: adminEmail,
        password: hashedPassword,
        role: "admin",
        phone: "9999999999",
        avatar_url: "",
        city: "khordha",
        is_blocked: false,   
        created_at: new Date(),
        updated_at: new Date()
      });

      await adminUser.save();
      console.log("Admin user seeded successfully");
    } else {
      existingAdmin.username = "Admin";
      existingAdmin.password = hashedPassword;
      existingAdmin.role = "admin";
      existingAdmin.phone = "9999999999";
      existingAdmin.city = "khordha";
      existingAdmin.is_blocked = false;
      existingAdmin.updated_at = new Date();

      await existingAdmin.save();
      console.log("Admin user updated successfully");
    }
  } catch (err) {
    console.error("Error seeding admin:", err);
  }
}

async function connectDB() {
  await mongoose.connect("mongodb://127.0.0.1:27017/usedvehicles", {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });
  console.log("MongoDB connected");

  await seedAdmin();
}

module.exports = connectDB;