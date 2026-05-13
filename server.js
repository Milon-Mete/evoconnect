require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'irx_admin_2026';

// ==========================================
// RAZORPAY INIT
// ==========================================
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const PLAN_PRICES = {
  remote: 500000,        // ₹5,000 in paise
  studio: 1200000,       // ₹12,000 in paise
  amplification: 2500000 // ₹25,000 in paise
};

// ==========================================
// DB CONNECTION
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

const toJSONConfig = {
  virtuals: true,
  transform: (doc, ret) => { delete ret._id; delete ret.__v; }
};

// ==========================================
// SCHEMAS
// ==========================================
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  plan: { type: String, enum: ['none', 'remote', 'studio', 'amplification'], default: 'none' },
  episodeStatus: {
    type: String,
    enum: ['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'],
    default: 'pending'
  },
  profile: {
    guestName: String,
    guestImage: String,
    guestDescription: String,
    youtubeUrl: String,
    businessCategory: String,
    location: String,
    phone: String,
    website: String,
    linkedin: String,
  },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true, toJSON: toJSONConfig });

const serviceSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  serviceName: String,
  serviceDescription: String,
  redirectUrl: String,
  thumbnailUrl: String,
  category: { type: String, default: 'General' },
  price: String
}, { timestamps: true, toJSON: toJSONConfig });

const orderSchema = new mongoose.Schema({
  userId: String,
  razorpayOrderId: String,
  razorpayPaymentId: String,
  plan: String,
  amount: Number,
  status: { type: String, enum: ['created', 'paid', 'failed'], default: 'created' }
}, { timestamps: true, toJSON: toJSONConfig });

const User = mongoose.model('Usere', userSchema);
const Service = mongoose.model('Servicee', serviceSchema);
const Order = mongoose.model('Order', orderSchema);

// ==========================================
// MIDDLEWARE
// ==========================================
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: "No token provided." });
  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Unauthorized token" });
    req.userId = decoded.id;
    next();
  });
}

function verifyAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) return res.status(403).json({ message: "Admin access denied." });
  next();
}

// ==========================================
// AUTH ROUTES
// ==========================================
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required." });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, plan: 'none' });
    await user.save();
    res.status(201).json({ message: "Account created! Please log in." });
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
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, message: "Logged in successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// USER ROUTES
// ==========================================
app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({
      id: user._id,
      email: user.email,
      plan: user.plan,
      episodeStatus: user.episodeStatus,
      profile: user.profile
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.plan === 'none') return res.status(403).json({ message: "Purchase a package first." });
    user.profile = {
      guestName: req.body.guestName || '',
      guestImage: req.body.guestImage || '',
      guestDescription: req.body.guestDescription || '',
      youtubeUrl: req.body.youtubeUrl || '',
      businessCategory: req.body.businessCategory || '',
      location: req.body.location || '',
      phone: req.body.phone || '',
      website: req.body.website || '',
      linkedin: req.body.linkedin || '',
    };
    await user.save();
    res.json({ message: "Profile updated successfully", profile: user.profile });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// RAZORPAY PAYMENT ROUTES
// ==========================================

// Step 1: Create Razorpay Order
app.post('/api/create-order', verifyToken, async (req, res) => {
  try {
    const { selectedPlan } = req.body;
    const validPlans = ['remote', 'studio', 'amplification'];
    if (!validPlans.includes(selectedPlan)) {
      return res.status(400).json({ message: "Invalid plan." });
    }

    const amount = PLAN_PRICES[selectedPlan];
    const options = {
      amount,
      currency: 'INR',
      receipt: `irx_${req.userId.substring(0, 10)}_${Date.now()}`,
      notes: { userId: req.userId, plan: selectedPlan }
    };

    const razorpayOrder = await razorpay.orders.create(options);

    // Save order record
    const order = new Order({
      userId: req.userId,
      razorpayOrderId: razorpayOrder.id,
      plan: selectedPlan,
      amount,
      status: 'created'
    });
    await order.save();

    res.json({
      orderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Could not create payment order." });
  }
});

// Step 2: Verify Payment & Activate Plan
app.post('/api/verify-payment', verifyToken, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;

    // Cryptographic verification
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      await Order.findOneAndUpdate(
        { razorpayOrderId: razorpay_order_id },
        { status: 'failed' }
      );
      return res.status(400).json({ message: "Payment verification failed. Contact support." });
    }

    // Update order record
    await Order.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id },
      { razorpayPaymentId: razorpay_payment_id, status: 'paid' }
    );

    // Upgrade user plan
    await User.findByIdAndUpdate(req.userId, { plan });

    res.json({ message: `Plan upgraded to ${plan} successfully!`, plan });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Payment verification error." });
  }
});



// ==========================================
// PUBLIC ROUTES
// ==========================================
app.get('/api/guests', async (req, res) => {
  try {
    const users = await User.find({
      plan: { $ne: 'none' },
      "profile.guestName": { $exists: true, $ne: "" }
    });
    const guests = users.map(u => ({
      id: u._id,
      plan: u.plan,
      episodeStatus: u.episodeStatus,
      category: u.profile?.businessCategory,
      ...u.profile
    }));
    res.json(guests);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/guests/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || !user.profile) return res.status(404).json({ message: "Guest not found" });
    const services = await Service.find({ userId: req.params.id });
    res.json({ plan: user.plan, episodeStatus: user.episodeStatus, profile: user.profile, services });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/services', async (req, res) => {
  try {
    const services = await Service.find().sort({ createdAt: -1 });
    // Enrich with creator name
    const enriched = await Promise.all(services.map(async s => {
      const user = await User.findById(s.userId);
      return { ...s.toJSON(), creatorName: user?.profile?.guestName || 'Member' };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// SERVICE MANAGEMENT (USER)
// ==========================================
app.get('/api/my-services', verifyToken, async (req, res) => {
  try {
    const services = await Service.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(services);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/api/services', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.plan === 'none') {
      return res.status(403).json({ message: "Purchase a package first." });
    }
    const service = new Service({
      userId: req.userId,
      serviceName: req.body.serviceName,
      serviceDescription: req.body.serviceDescription,
      redirectUrl: req.body.redirectUrl,
      thumbnailUrl: req.body.thumbnailUrl,
      category: req.body.category || 'General',
      price: req.body.price || ''
    });
    await service.save();
    res.json(service);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete('/api/services/:id', verifyToken, async (req, res) => {
  try {
    const service = await Service.findOne({ _id: req.params.id, userId: req.userId });
    if (!service) return res.status(404).json({ message: "Service not found or not yours." });
    await Service.deleteOne({ _id: req.params.id });
    res.json({ message: "Service deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// ADMIN ROUTES
// ==========================================

// Admin Login
app.post('/api/admin/login', (req, res) => {
  const { secret } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ message: "Wrong admin secret." });
  res.json({ token: ADMIN_SECRET, message: "Admin access granted." });
});

// Get all users
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(users.map(async u => {
      const serviceCount = await Service.countDocuments({ userId: u._id });
      return {
        id: u._id,
        email: u.email,
        plan: u.plan,
        episodeStatus: u.episodeStatus,
        guestName: u.profile?.guestName || '',
        guestImage: u.profile?.guestImage || '',
        businessCategory: u.profile?.businessCategory || '',
        location: u.profile?.location || '',
        phone: u.profile?.phone || '',
        serviceCount,
        createdAt: u.createdAt
      };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update user plan (admin override)
app.patch('/api/admin/users/:id/plan', verifyAdmin, async (req, res) => {
  try {
    const { plan } = req.body;
    const validPlans = ['none', 'remote', 'studio', 'amplification'];
    if (!validPlans.includes(plan)) return res.status(400).json({ message: "Invalid plan." });
    const user = await User.findByIdAndUpdate(req.params.id, { plan }, { new: true });
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ message: "Plan updated.", plan: user.plan });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update episode status (admin)
app.patch('/api/admin/users/:id/episode', verifyAdmin, async (req, res) => {
  try {
    const { episodeStatus } = req.body;
    const validStatuses = ['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'];
    if (!validStatuses.includes(episodeStatus)) return res.status(400).json({ message: "Invalid status." });
    const user = await User.findByIdAndUpdate(req.params.id, { episodeStatus }, { new: true });
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ message: "Episode status updated.", episodeStatus: user.episodeStatus });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Delete user + their services
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Service.deleteMany({ userId: req.params.id });
    res.json({ message: "User and all their services deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get all services (admin)
app.get('/api/admin/services', verifyAdmin, async (req, res) => {
  try {
    const services = await Service.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(services.map(async s => {
      const user = await User.findById(s.userId);
      return { ...s.toJSON(), creatorName: user?.profile?.guestName || 'Unknown', creatorEmail: user?.email || '' };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Delete any service (admin)
app.delete('/api/admin/services/:id', verifyAdmin, async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.params.id);
    res.json({ message: "Service deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Dashboard stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const paidUsers = await User.countDocuments({ plan: { $ne: 'none' } });
    const totalServices = await Service.countDocuments();
    const planBreakdown = {
      remote: await User.countDocuments({ plan: 'remote' }),
      studio: await User.countDocuments({ plan: 'studio' }),
      amplification: await User.countDocuments({ plan: 'amplification' }),
    };
    const totalRevenue =
      planBreakdown.remote * 5000 +
      planBreakdown.studio * 12000 +
      planBreakdown.amplification * 25000;
    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5);
    res.json({
      totalUsers, paidUsers, totalServices, planBreakdown,
      totalRevenue,
      recentUsers: recentUsers.map(u => ({
        id: u._id, email: u.email, plan: u.plan,
        guestName: u.profile?.guestName || '', createdAt: u.createdAt
      }))
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Orders (admin)
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).limit(50);
    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ==========================================
// START
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 IRX Backend running on port ${PORT}`));
