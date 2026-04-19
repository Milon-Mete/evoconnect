require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors()); 
app.use(express.json()); 

const JWT_SECRET = process.env.JWT_SECRET;

// ==========================================
// 1. DATABASE CONNECTION & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Atlas Connected Successfully"))
  .catch(err => console.error("MongoDB Connection Error:", err));

// This trick ensures MongoDB sends 'id' instead of '_id' so your frontend doesn't break
const toJSONConfig = {
  virtuals: true,
  transform: (doc, ret) => {
    delete ret._id;
    delete ret.__v;
  }
};

// USER SCHEMA
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  hasPaid: { type: Boolean, default: false },
  profile: {
    guestName: String,
    guestImage: String,
    guestDescription: String,
    youtubeUrl: String,
    businessCategory: String,
    location: String,
    phone: String,
    website: String
  }
}, { timestamps: true, toJSON: toJSONConfig });

// SERVICE SCHEMA
const serviceSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  serviceName: String,
  serviceDescription: String,
  redirectUrl: String,
  thumbnailUrl: String,
  category: { type: String, default: 'General' },
  subCategory: String,
  price: String
}, { timestamps: true, toJSON: toJSONConfig });

const User = mongoose.model('Usere', userSchema);
const Service = mongoose.model('Servicee', serviceSchema);

// ==========================================
// 2. MIDDLEWARE (SECURITY BOUNCER)
// ==========================================
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: "No token provided, please log in." });

  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Unauthorized token" });
    req.userId = decoded.id; 
    next();
  });
}

// ==========================================
// 3. AUTHENTICATION ROUTES
// ==========================================
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists in DB
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    // Encrypt the password and save
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, hasPaid: false });
    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    // Generate token using the MongoDB _id
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, message: "Logged in successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// 4. USER STATE & PAYMENT ROUTES
// ==========================================
app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ email: user.email, hasPaid: user.hasPaid, profile: user.profile });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/api/pay-access', verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.userId, { hasPaid: true }, { new: true });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Account Unlocked Successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// 5. PORTFOLIO & PROFILE ROUTES
// ==========================================
app.post('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) return res.status(404).json({message: "User not found"});
    if (!user.hasPaid) return res.status(403).json({ message: "You must pay the platform fee first." });

    user.profile = {
      guestName: req.body.guestName,
      guestImage: req.body.guestImage,
      guestDescription: req.body.guestDescription,
      youtubeUrl: req.body.youtubeUrl || '',
      businessCategory: req.body.businessCategory || '',
      location: req.body.location || '',
      phone: req.body.phone || '',
      website: req.body.website || ''
    };
    
    await user.save();
    res.json({ message: "Profile updated successfully", profile: user.profile });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get All Guests (Public)
app.get('/api/guests', async (req, res) => {
  try {
    // Only fetch users who have actually set up a profile name
    const users = await User.find({ "profile.guestName": { $exists: true, $ne: "" } });
    
    const guests = users.map(u => ({ id: u._id, ...u.profile }));
    res.json(guests);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get a Single Guest's Portfolio
app.get('/api/guests/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || !user.profile) return res.status(404).json({message: "Guest not found"});

    // Find all services associated with this user's ID
    const guestServices = await Service.find({ userId: req.params.id });

    res.json({
      profile: user.profile,
      services: guestServices
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// 6. SERVICE MANAGEMENT ROUTES
// ==========================================
app.get('/api/services', async (req, res) => {
  try {
    // Fetch all services, newest first
    const services = await Service.find().sort({ createdAt: -1 });
    res.json(services);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/my-services', verifyToken, async (req, res) => {
  try {
    const myServices = await Service.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(myServices);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/api/services', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.hasPaid) return res.status(403).json({ message: "You must pay the platform fee first." });
    
    const newService = new Service({
      userId: req.userId,
      serviceName: req.body.serviceName,
      serviceDescription: req.body.serviceDescription,
      redirectUrl: req.body.redirectUrl,
      thumbnailUrl: req.body.thumbnailUrl,
      category: req.body.category || 'General',
      subCategory: req.body.subCategory || '',
      price: req.body.price || ''
    });
    
    await newService.save();
    res.json(newService);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// SERVER START
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));