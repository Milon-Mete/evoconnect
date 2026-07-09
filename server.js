require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const REQUIRED_ENV = ['JWT_SECRET', 'MONGO_URI', 'RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'ADMIN_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) { console.error(`Missing env: ${key}`); process.exit(1); }
}

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
const PLATFORM_FEE_PERCENT = parseFloat(process.env.PLATFORM_FEE_PERCENT || '0');
const IS_DEV = process.env.NODE_ENV !== 'production';

const ALLOWED_ORIGINS = IS_DEV
  ? ['http://localhost:3000', 'http://127.0.0.1:5501', 'http://localhost:5501', 'http://localhost:4173']
  : (process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',').map(u => u.trim()) : []);

if (!IS_DEV && ALLOWED_ORIGINS.length === 0) {
  console.error('FRONTEND_URL env var required in production.'); process.exit(1);
}

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS: origin ${origin} not allowed.`));
  },
  credentials: true,
};

const app = express();
app.use(helmet());
app.use(cors(corsOptions));

// Raw body for Razorpay webhook
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhook/razorpay') {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      req.rawBody = raw;
      try { req.body = JSON.parse(raw); } catch { req.body = {}; }
      next();
    });
  } else { next(); }
});

app.use(express.json({ limit: '50kb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { message: 'Too many attempts. Try again in 15 minutes.' }, standardHeaders: true, legacyHeaders: false });
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, message: { message: 'Too many requests.' } });
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/', generalLimiter);

const PLAN_PRICES = { remote: 500000, studio: 1200000, amplification: 2500000 };

const razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => { console.error('MongoDB Failed:', err.message); process.exit(1); });

const toJ = { virtuals: true, transform: (doc, ret) => { delete ret._id; delete ret.__v; } };

// ── Schemas ──
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, maxlength: 254 },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'seller', 'buyer'], default: 'buyer' },
  plan: { type: String, enum: ['none', 'remote', 'studio', 'amplification'], default: 'none' },
  episodeStatus: { type: String, enum: ['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'], default: 'pending' },
  profile: {
    guestName: { type: String, maxlength: 120 }, guestImage: { type: String, maxlength: 500 },
    guestBannerImage: { type: String, maxlength: 500 },
    guestDescription: { type: String, maxlength: 2000 }, youtubeUrl: { type: String, maxlength: 300 },
    businessCategory: { type: String, maxlength: 100 }, location: { type: String, maxlength: 200 },
    phone: { type: String, maxlength: 30 }, website: { type: String, maxlength: 300 },
    linkedin: { type: String, maxlength: 300 },
  },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true, toJSON: toJ });

const episodeSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  serviceIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Servicee' }],
  episodeNo: { type: Number, required: true },
  title: { type: String, required: true, maxlength: 300 },
  description: { type: String, default: '', maxlength: 5000 },
  youtubeUrl: { type: String, default: '', maxlength: 300 },
  youtubeId: { type: String, default: '', maxlength: 20 },
  thumbnail: { type: String, default: '', maxlength: 500 },
  tags: [{ type: String, maxlength: 60 }],
  featuredTag: { type: String, default: '', maxlength: 60 },
  duration: { type: String, default: '', maxlength: 20 },
  guests: [{ type: String, maxlength: 120 }],
  publishedAt: { type: Date, default: null },
  status: { type: String, enum: ['draft', 'published', 'archived'], default: 'published' },
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  adminNotes: { type: String, default: '', maxlength: 1000 },
}, { timestamps: true, toJSON: toJ });

episodeSchema.virtual('thumbnailUrl').get(function () {
  if (this.thumbnail) return this.thumbnail;
  if (this.youtubeId) return `https://img.youtube.com/vi/${this.youtubeId}/hqdefault.jpg`;
  return '';
});

function extractYouTubeId(url) {
  if (!url) return '';
  const m = url.match(/(?:v=|\/v\/|youtu\.be\/|\/embed\/|\/shorts\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : '';
}

const serviceSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  serviceName: { type: String, maxlength: 200 },
  serviceDescription: { type: String, maxlength: 3000 },
  redirectUrl: { type: String, maxlength: 500 },
  thumbnailUrl: { type: String, maxlength: 500 },
  category: { type: String, default: 'General', maxlength: 100 },
  pricingType: { type: String, enum: ['lead', 'one_time', 'subscription'], default: 'lead' },
  benefits: [{ 
    title: { type: String, default: '', maxlength: 200 }, 
    description: { type: String, default: '', maxlength: 500 }, 
    icon: { type: String, default: '', maxlength: 100 } 
  }],
  // NEW HYBRID FIELDS
  eventDate: { type: Date, default: null },
  scheduleText: { type: String, default: '', maxlength: 200 },
  duration: { type: String, default: '', maxlength: 100 },
  format: { type: String, default: '', maxlength: 100 },
  language: { type: String, default: '', maxlength: 50 },
  eventTime: { type: String, default: '', maxlength: 100 },
  whatYouWillLearn: [{ 
    topic: { type: String, maxlength: 250 }, 
    icon: { type: String, default: 'check_circle', maxlength: 50 } 
  }],
  price: { type: Number, default: 0 },
  requiresAddress: { type: Boolean, default: false },
}, { timestamps: true, toJSON: toJ });

const orderSchema = new mongoose.Schema({
  userId: String, razorpayOrderId: String, razorpayPaymentId: String,
  plan: String, amount: Number,
  status: { type: String, enum: ['created', 'paid', 'failed'], default: 'created' },
  originalAmount: { type: Number, default: 0 },
couponCode: { type: String, default: '' },
discountAmount: { type: Number, default: 0 }
}, { timestamps: true, toJSON: toJ });

const serviceTransactionSchema = new mongoose.Schema({
  serviceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Servicee', required: true },
  sellerId: { type: String, required: true },
  buyerId: { type: String, default: '' },
  buyerName: { type: String, required: true, maxlength: 120 },
  buyerEmail: { type: String, required: true, maxlength: 254 },
  buyerPhone: { type: String, default: '', maxlength: 30 },
  message: { type: String, default: '', maxlength: 2000 },
  shippingAddress: {
    line1: { type: String, default: '', maxlength: 200 }, line2: { type: String, default: '', maxlength: 200 },
    city: { type: String, default: '', maxlength: 100 }, state: { type: String, default: '', maxlength: 100 },
    pin: { type: String, default: '', maxlength: 20 },
  },
  amount: { type: Number, default: 0 }, platformFee: { type: Number, default: 0 },
  razorpayOrderId: { type: String, default: '' }, razorpayPaymentId: { type: String, default: '' },
  type: { type: String, enum: ['lead', 'one_time', 'subscription'], default: 'lead' },
  paymentStatus: { type: String, enum: ['not_required', 'pending', 'paid', 'failed'], default: 'not_required' },
  status: { type: String, enum: ['pending', 'contacted', 'converted', 'closed'], default: 'pending' },
  redirectUrl: { type: String, default: '', maxlength: 500 },
  originalAmount: { type: Number, default: 0 },
couponCode: { type: String, default: '' },
discountAmount: { type: Number, default: 0 },
}, { timestamps: true, toJSON: toJ });

const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true, trim: true, maxlength: 30 },
  description: { type: String, default: '', maxlength: 200 },
  discountType: { type: String, enum: ['percent', 'flat'], required: true },
  discountValue: { type: Number, required: true, min: 0 }, // percent: 0-100, flat: paise
  appliesTo: { type: String, enum: ['plan', 'service', 'all'], default: 'all' },
  applicablePlans: [{ type: String, enum: ['remote', 'studio', 'amplification'] }],
  applicableServices: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Servicee' }],
  minAmount: { type: Number, default: 0 },       // paise
  maxDiscount: { type: Number, default: null },  // cap for percent discounts, paise
  maxUses: { type: Number, default: null },      // null = unlimited overall
  usedCount: { type: Number, default: 0 },
  maxUsesPerUser: { type: Number, default: 1 },  // 0 = unlimited per user
  expiresAt: { type: Date, default: null },
  active: { type: Boolean, default: true },
}, { timestamps: true, toJSON: toJ });

const couponRedemptionSchema = new mongoose.Schema({
  couponId: { type: mongoose.Schema.Types.ObjectId, ref: 'Coupon', required: true },
  code: { type: String, required: true },
  userId: { type: String, default: '' },
  email: { type: String, default: '' },
  orderType: { type: String, enum: ['plan', 'service'], required: true },
  referenceId: { type: String, default: '' }, // Order/Txn _id
  discountAmount: { type: Number, default: 0 },
}, { timestamps: true, toJSON: toJ });

const Coupon = mongoose.model('Coupon', couponSchema);
const CouponRedemption = mongoose.model('CouponRedemption', couponRedemptionSchema);

const serviceExtraSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  serviceId: { type: String, default: '' },
  title: { type: String, required: true, maxlength: 300 },
  description: { type: String, default: '', maxlength: 5000 },
  videoUrl: { type: String, default: '', maxlength: 500 },
  thumbnail: { type: String, default: '', maxlength: 500 },
  tags: [{ type: String, maxlength: 60 }],
  featuredTag: { type: String, default: '', maxlength: 60 },
  duration: { type: String, default: '', maxlength: 20 },
  publishedAt: { type: Date, default: null },
  status: { type: String, enum: ['draft', 'published', 'archived'], default: 'published' },
  sortOrder: { type: Number, default: 0 },
}, { timestamps: true, toJSON: toJ });

const User = mongoose.model('Usere', userSchema);
const Episode = mongoose.model('Episode', episodeSchema);
const Service = mongoose.model('Servicee', serviceSchema);
const ServiceExtra = mongoose.model('ServiceExtra', serviceExtraSchema);
const Order = mongoose.model('Order', orderSchema);
const ServiceTransaction = mongoose.model('ServiceTransaction', serviceTransactionSchema);

// ── Middleware ──
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided.' });
  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized or expired token.' });
    req.userId = decoded.id; req.userRole = decoded.role; next();
  });
}
function optionalAuth(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) { next(); return; }
  try { const d = jwt.verify(token.split(' ')[1], JWT_SECRET); req.userId = d.id; req.userRole = d.role; } catch { }
  next();
}
async function verifySeller(req, res, next) {
  try {
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    if (!['seller', 'admin'].includes(user.role)) {
      return res.status(403).json({
        message: 'Seller account required.'
      });
    }

    next();
  } catch (err) {
    res.status(500).json({
      message: 'Server error.'
    });
  }
}
function verifyAdmin(req, res, next) {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return res.status(403).json({ message: 'Admin access denied.' });
  next();
}

async function getUserMap(ids) {
  const u = [...new Set(ids.filter(Boolean))];
  if (!u.length) return {};
  const users = await User.find({ _id: { $in: u } });
  return Object.fromEntries(users.map(x => [x._id.toString(), x]));
}
async function getServiceMap(ids) {
  const u = [...new Set(ids.filter(Boolean).map(id => id.toString()))];
  if (!u.length) return {};
  const svcs = await Service.find({ _id: { $in: u } });
  return Object.fromEntries(svcs.map(s => [s._id.toString(), s]));
}

async function validateCoupon({ code, orderType, plan, serviceId, amount, userId, email }) {
  if (!code) return { valid: false, message: 'No coupon code provided.' };
  const coupon = await Coupon.findOne({ code: String(code).trim().toUpperCase() });
  if (!coupon) return { valid: false, message: 'Invalid coupon code.' };
  if (!coupon.active) return { valid: false, message: 'This coupon is no longer active.' };
  if (coupon.expiresAt && coupon.expiresAt < new Date()) return { valid: false, message: 'This coupon has expired.' };
  if (coupon.maxUses !== null && coupon.usedCount >= coupon.maxUses) return { valid: false, message: 'This coupon has reached its usage limit.' };

  if (coupon.appliesTo !== 'all' && coupon.appliesTo !== orderType) {
    return { valid: false, message: 'This coupon is not valid for this purchase.' };
  }
  if (orderType === 'plan' && coupon.applicablePlans?.length && !coupon.applicablePlans.includes(plan)) {
    return { valid: false, message: 'This coupon does not apply to the selected plan.' };
  }
  if (orderType === 'service' && coupon.applicableServices?.length &&
      !coupon.applicableServices.map(id => id.toString()).includes(serviceId?.toString())) {
    return { valid: false, message: 'This coupon does not apply to this service.' };
  }
  if (coupon.minAmount && amount < coupon.minAmount) {
    return { valid: false, message: `Minimum order amount is ₹${(coupon.minAmount / 100).toFixed(2)}.` };
  }

  if (coupon.maxUsesPerUser) {
    const or = [];
    if (userId) or.push({ userId });
    if (email) or.push({ email: String(email).toLowerCase().trim() });
    if (or.length) {
      const count = await CouponRedemption.countDocuments({ couponId: coupon._id, $or: or });
      if (count >= coupon.maxUsesPerUser) return { valid: false, message: 'You have already used this coupon.' };
    }
  }

  let discount = 0;
  if (coupon.discountType === 'percent') {
    discount = Math.round((amount * coupon.discountValue) / 100);
    if (coupon.maxDiscount) discount = Math.min(discount, coupon.maxDiscount);
  } else {
    discount = Math.round(coupon.discountValue);
  }
  discount = Math.min(discount, amount);
  return { valid: true, coupon, discount, finalAmount: amount - discount };
}

// Records a redemption. Call this ONLY from a code path that has already
// confirmed (via atomic findOneAndUpdate) that this is the first time the
// order/transaction transitioned to paid.
async function redeemCouponByCode(code, { userId, email, orderType, referenceId, discountAmount }) {
  if (!code) return;
  const coupon = await Coupon.findOne({ code });
  if (!coupon) return;
  await Coupon.findByIdAndUpdate(coupon._id, { $inc: { usedCount: 1 } });
  await new CouponRedemption({
    couponId: coupon._id, code: coupon.code, userId: userId || '', email: (email || '').toLowerCase().trim(),
    orderType, referenceId: referenceId || '', discountAmount: discountAmount || 0,
  }).save();
}

// ==============================================
// AUTH — ✅ FIX 1: SIGNUP NOW RETURNS JWT TOKEN
// User signs up → gets token → already logged in
// ==============================================
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });
    if (password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' });

    const allowedRoles = ['buyer', 'seller'];
    const assignedRole = allowedRoles.includes(role) ? role : 'buyer';

    if (await User.findOne({ email })) return res.status(400).json({ message: 'User already exists.' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, role: assignedRole, plan: 'none' });
    await user.save();

    // ✅ Return token immediately — frontend receives it and is logged in right away
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Account created successfully!', token, role: assignedRole });
  } catch (err) {
    console.error(err); res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found.' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Invalid credentials.' });
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, message: 'Logged in successfully.' });
  } catch (err) {
    console.error(err); res.status(500).json({ message: 'Server error' });
  }
});

// ── Profile ──
app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ id: user._id, email: user.email, role: user.role, plan: user.plan, episodeStatus: user.episodeStatus, profile: user.profile });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/profile', verifyToken, verifySeller, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if (user.plan === 'none') return res.status(403).json({ message: 'Purchase a package first.' });
    user.profile = { guestName: req.body.guestName || '', guestImage: req.body.guestImage || '', guestBannerImage: req.body.guestBannerImage || '', guestDescription: req.body.guestDescription || '', youtubeUrl: req.body.youtubeUrl || '', businessCategory: req.body.businessCategory || '', location: req.body.location || '', phone: req.body.phone || '', website: req.body.website || '', linkedin: req.body.linkedin || '' };
    await user.save();
    res.json({ message: 'Profile updated.', profile: user.profile });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/buyer-profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if (req.body.name !== undefined) user.profile.guestName = req.body.name;
    if (req.body.phone !== undefined) user.profile.phone = req.body.phone;
    await user.save();
    res.json({ message: 'Profile updated.', profile: user.profile });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Episodes helpers ──
function formatEpisode(ep, includeVideo = true) {
  const obj = ep.toJSON ? ep.toJSON() : { ...ep };
  obj.hasVideo = !!(ep.youtubeId || (ep.youtubeUrl && extractYouTubeId(ep.youtubeUrl)));
  obj.thumbnailUrl = (!obj.thumbnail && obj.youtubeId) ? `https://img.youtube.com/vi/${obj.youtubeId}/hqdefault.jpg` : (obj.thumbnail || '');
  if (includeVideo && obj.youtubeId) obj.embedUrl = `https://www.youtube.com/embed/${obj.youtubeId}`;
  else if (!includeVideo) { delete obj.youtubeUrl; delete obj.youtubeId; obj.embedUrl = null; }
  return obj;
}

// ── Episodes public ──
app.get('/api/episodes', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1), limit = Math.min(100, parseInt(req.query.limit) || 20);
    const filter = { status: 'published' };
    if (req.query.tag) filter.tags = { $in: [req.query.tag] };
    if (req.query.sellerId) filter.userId = req.query.sellerId;
    if (req.query.search) filter.$or = [{ title: { $regex: req.query.search, $options: 'i' } }, { description: { $regex: req.query.search, $options: 'i' } }];
    const total = await Episode.countDocuments(filter);
    const episodes = await Episode.find(filter).sort({ episodeNo: -1 }).skip((page - 1) * limit).limit(limit);
    const userMap = await getUserMap(episodes.map(ep => ep.userId));
    res.json({ total, page, totalPages: Math.ceil(total / limit), episodes: episodes.map(ep => ({ ...formatEpisode(ep, false), sellerName: userMap[ep.userId]?.profile?.guestName || 'Member', sellerImage: userMap[ep.userId]?.profile?.guestImage || '' })) });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/episodes/seller/:sellerId', async (req, res) => {
  try {
    const eps = await Episode.find({ userId: req.params.sellerId, status: 'published' }).sort({ episodeNo: -1 });
    res.json(eps.map(ep => formatEpisode(ep, false)));
  } catch { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/episodes/purchased/:serviceId', optionalAuth, async (req, res) => {
  try {
    const service = await Service.findById(req.params.serviceId);
    if (!service) return res.status(404).json({ message: 'Service not found.' });
    let hasPurchased = false;
    if (req.userId) {
      if (req.userId === service.userId) { hasPurchased = true; }
      else {
        const t1 = await ServiceTransaction.findOne({ serviceId: req.params.serviceId, buyerId: req.userId, paymentStatus: { $in: ['paid', 'not_required'] } });
        if (t1) hasPurchased = true;
        if (!hasPurchased) {
          const u = await User.findById(req.userId);
          if (u) { const t2 = await ServiceTransaction.findOne({ serviceId: req.params.serviceId, buyerEmail: u.email.toLowerCase().trim(), paymentStatus: { $in: ['paid', 'not_required'] } }); if (t2) hasPurchased = true; }
        }
      }
    }
    const allEps = await Episode.find({ userId: service.userId, status: 'published' }).sort({ episodeNo: -1 });
    const eps = allEps.filter(ep => !ep.serviceIds?.length || ep.serviceIds.map(id => id.toString()).includes(req.params.serviceId));
    res.json({ purchased: hasPurchased, episodes: eps.map(ep => formatEpisode(ep, hasPurchased)) });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/episodes/:id', async (req, res) => {
  try {
    const ep = await Episode.findById(req.params.id);
    if (!ep || ep.status === 'archived') return res.status(404).json({ message: 'Episode not found.' });
    const s = await User.findById(ep.userId);
    res.json({ ...formatEpisode(ep, false), sellerName: s?.profile?.guestName || 'Member', sellerImage: s?.profile?.guestImage || '', sellerCategory: s?.profile?.businessCategory || '', sellerLinkedin: s?.profile?.linkedin || '' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Episodes seller ──
app.get('/api/my-episodes', verifyToken, verifySeller, async (req, res) => {
  try { res.json((await Episode.find({ userId: req.userId }).sort({ episodeNo: -1 })).map(ep => formatEpisode(ep, true))); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/my-episodes', verifyToken, verifySeller, async (req, res) => {
  try {
    const { episodeNo, title, description, youtubeUrl, thumbnail, tags, featuredTag, duration, guests, publishedAt, status, serviceIds } = req.body;
    if (!episodeNo) return res.status(400).json({ message: 'episodeNo is required.' });
    if (!title) return res.status(400).json({ message: 'title is required.' });
    const youtubeId = youtubeUrl ? extractYouTubeId(youtubeUrl.trim()) : '';
    if (youtubeUrl && !youtubeId) return res.status(400).json({ message: 'Invalid YouTube URL.' });
    if (await Episode.findOne({ userId: req.userId, episodeNo })) return res.status(409).json({ message: `Episode #${episodeNo} already exists.` });
    const ep = new Episode({ userId: req.userId, serviceIds: (Array.isArray(serviceIds) ? serviceIds : []).filter(id => id && id !== 'undefined' && String(id).length === 24), episodeNo: parseInt(episodeNo), title: title.trim(), description: description?.trim() || '', youtubeUrl: youtubeUrl?.trim() || '', youtubeId, thumbnail: thumbnail || '', tags: Array.isArray(tags) ? tags.map(t => t.trim().toLowerCase()) : [], featuredTag: featuredTag?.trim() || '', duration: duration?.trim() || '', guests: Array.isArray(guests) ? guests.map(g => g.trim()) : [], publishedAt: publishedAt ? new Date(publishedAt) : null, status: ['draft', 'published', 'archived'].includes(status) ? status : 'published' });
    await ep.save();
    res.status(201).json(formatEpisode(ep, true));
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/my-episodes/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const ep = await Episode.findOne({ _id: req.params.id, userId: req.userId });
    if (!ep) return res.status(404).json({ message: 'Episode not found.' });
    ['episodeNo', 'title', 'description', 'thumbnail', 'tags', 'featuredTag', 'duration', 'guests', 'publishedAt', 'status', 'adminNotes'].forEach(f => { if (req.body[f] !== undefined) ep[f] = req.body[f]; });
    if (req.body.serviceIds !== undefined) ep.serviceIds = (Array.isArray(req.body.serviceIds) ? req.body.serviceIds : []).filter(id => id && id !== 'undefined' && id.toString().length === 24);
    if (req.body.youtubeUrl) { const id = extractYouTubeId(req.body.youtubeUrl); if (!id) return res.status(400).json({ message: 'Invalid YouTube URL.' }); ep.youtubeUrl = req.body.youtubeUrl; ep.youtubeId = id; }
    if (req.body.tags && Array.isArray(req.body.tags)) ep.tags = req.body.tags.map(t => t.trim().toLowerCase());
    if (req.body.guests && Array.isArray(req.body.guests)) ep.guests = req.body.guests.map(g => g.trim());
    await ep.save(); res.json(formatEpisode(ep, true));
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.delete('/api/my-episodes/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const ep = await Episode.findOne({ _id: req.params.id, userId: req.userId });
    if (!ep) return res.status(404).json({ message: 'Episode not found.' });
    await Episode.deleteOne({ _id: req.params.id }); res.json({ message: 'Episode deleted.' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Admin episodes ──
app.get('/api/admin/episodes', verifyAdmin, async (req, res) => {
  try {
    const eps = await Episode.find().sort({ createdAt: -1 });
    const uMap = await getUserMap(eps.map(e => e.userId));
    res.json({ total: eps.length, episodes: eps.map(e => ({ ...formatEpisode(e, true), sellerName: uMap[e.userId]?.profile?.guestName || 'Unknown', sellerEmail: uMap[e.userId]?.email || '' })) });
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/admin/episodes', verifyAdmin, async (req, res) => {
  try {
    const { userId, episodeNo, title, description, youtubeUrl, thumbnail, tags, featuredTag, duration, guests, publishedAt, status, adminNotes, views, likes, serviceIds } = req.body;
    if (!userId || !episodeNo || !title || !youtubeUrl) return res.status(400).json({ message: 'userId, episodeNo, title, youtubeUrl required.' });
    const youtubeId = extractYouTubeId(youtubeUrl);
    if (!youtubeId) return res.status(400).json({ message: 'Invalid YouTube URL.' });
    const ep = new Episode({ userId, serviceIds: Array.isArray(serviceIds) ? serviceIds : [], episodeNo: parseInt(episodeNo), title: title.trim(), description: description?.trim() || '', youtubeUrl: youtubeUrl.trim(), youtubeId, thumbnail: thumbnail || '', tags: Array.isArray(tags) ? tags.map(t => t.trim().toLowerCase()) : [], featuredTag: featuredTag?.trim() || '', duration: duration?.trim() || '', guests: Array.isArray(guests) ? guests.map(g => g.trim()) : [], publishedAt: publishedAt ? new Date(publishedAt) : null, status: ['draft', 'published', 'archived'].includes(status) ? status : 'published', adminNotes: adminNotes || '', views: views || 0, likes: likes || 0 });
    await ep.save(); res.status(201).json(formatEpisode(ep, true));
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});
app.put('/api/admin/episodes/:id', verifyAdmin, async (req, res) => {
  try {
    const ep = await Episode.findById(req.params.id);
    if (!ep) return res.status(404).json({ message: 'Episode not found.' });
    ['episodeNo', 'title', 'description', 'thumbnail', 'tags', 'featuredTag', 'duration', 'guests', 'publishedAt', 'status', 'views', 'likes', 'adminNotes', 'userId', 'serviceIds'].forEach(f => { if (req.body[f] !== undefined) ep[f] = req.body[f]; });
    if (req.body.youtubeUrl) { const id = extractYouTubeId(req.body.youtubeUrl); if (!id) return res.status(400).json({ message: 'Invalid YouTube URL.' }); ep.youtubeUrl = req.body.youtubeUrl; ep.youtubeId = id; }
    if (req.body.tags && Array.isArray(req.body.tags)) ep.tags = req.body.tags.map(t => t.trim().toLowerCase());
    if (req.body.guests && Array.isArray(req.body.guests)) ep.guests = req.body.guests.map(g => g.trim());
    await ep.save(); res.json(formatEpisode(ep, true));
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.patch('/api/admin/episodes/:id/status', verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body; if (!['draft', 'published', 'archived'].includes(status)) return res.status(400).json({ message: 'Invalid status.' });
    const ep = await Episode.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!ep) return res.status(404).json({ message: 'Not found.' });
    res.json({ message: 'Updated.', status: ep.status });
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.delete('/api/admin/episodes/:id', verifyAdmin, async (req, res) => {
  try { await Episode.findByIdAndDelete(req.params.id); res.json({ message: 'Deleted.' }); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/coupons/validate', optionalAuth, async (req, res) => {
  try {
    const { code, orderType, plan, serviceId, buyerEmail } = req.body;
    let amount;
    if (orderType === 'plan') {
      if (!['remote', 'studio', 'amplification'].includes(plan)) return res.status(400).json({ message: 'Invalid plan.' });
      amount = PLAN_PRICES[plan];
    } else if (orderType === 'service') {
      const service = await Service.findById(serviceId);
      if (!service) return res.status(404).json({ message: 'Service not found.' });
      amount = service.price;
    } else {
      return res.status(400).json({ message: 'Invalid orderType.' });
    }

    let email = buyerEmail;
    if (req.userId && !email) { const u = await User.findById(req.userId); email = u?.email; }

    const result = await validateCoupon({ code, orderType, plan, serviceId, amount, userId: req.userId, email });
    if (!result.valid) return res.status(400).json({ valid: false, message: result.message });

    res.json({
      valid: true,
      discountAmount: result.discount,
      originalAmount: amount,
      finalAmount: result.finalAmount,
      description: result.coupon.description,
    });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

// ── Plan purchase (sellers only) ──
app.post('/api/create-order', verifyToken, async (req, res) => {
  try {
    const { selectedPlan, couponCode } = req.body;
    if (!['remote', 'studio', 'amplification'].includes(selectedPlan)) return res.status(400).json({ message: 'Invalid plan.' });

    const originalAmount = PLAN_PRICES[selectedPlan];
    let amount = originalAmount;
    let discountAmount = 0;
    let appliedCoupon = null;
    const u = await User.findById(req.userId);

    if (couponCode) {
      const result = await validateCoupon({ code: couponCode, orderType: 'plan', plan: selectedPlan, amount, userId: req.userId, email: u?.email });
      if (!result.valid) return res.status(400).json({ message: result.message });
      discountAmount = result.discount; amount = result.finalAmount; appliedCoupon = result.coupon;
    }

    // Fully covered by coupon — grant plan immediately, skip Razorpay
    if (amount <= 0) {
      const upd = { plan: selectedPlan };
      if (u?.role === 'buyer') upd.role = 'seller';
      await User.findByIdAndUpdate(req.userId, upd);

      // Record a "free" Order so dashboards/history stay consistent
      await new Order({ userId: req.userId, razorpayOrderId: `free_${req.userId}_${Date.now()}`, plan: selectedPlan, amount: 0, originalAmount, couponCode: appliedCoupon?.code || '', discountAmount, status: 'paid' }).save();

      if (appliedCoupon) await redeemCouponByCode(appliedCoupon.code, { userId: req.userId, email: u?.email, orderType: 'plan', discountAmount });
      return res.json({ free: true, message: `Plan upgraded to ${selectedPlan}!`, plan: selectedPlan, discountAmount, originalAmount });
    }

    const ro = await razorpay.orders.create({
      amount, currency: 'INR',
      receipt: `irx_plan_${req.userId.toString().substring(0, 10)}_${Date.now()}`,
      notes: { userId: req.userId, plan: selectedPlan, orderType: 'plan_purchase', couponCode: appliedCoupon?.code || '' }
    });
    await new Order({ userId: req.userId, razorpayOrderId: ro.id, plan: selectedPlan, amount, originalAmount, couponCode: appliedCoupon?.code || '', discountAmount, status: 'created' }).save();
    res.json({ orderId: ro.id, amount: ro.amount, currency: ro.currency, keyId: process.env.RAZORPAY_KEY_ID, discountAmount, originalAmount });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Could not create order.' }); }
});

app.post('/api/verify-payment', verifyToken, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
    if (expected !== razorpay_signature) {
      await Order.findOneAndUpdate({ razorpayOrderId: razorpay_order_id, status: { $ne: 'paid' } }, { status: 'failed' });
      return res.status(400).json({ message: 'Verification failed.' });
    }

    // Atomic: only the FIRST caller to mark this order paid gets `order` back non-null.
    const order = await Order.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id, status: { $ne: 'paid' } },
      { razorpayPaymentId: razorpay_payment_id, status: 'paid' },
      { new: true }
    );

    const upd = { plan };
    const u = await User.findById(req.userId);
    if (u?.role === 'buyer') upd.role = 'seller';
    await User.findByIdAndUpdate(req.userId, upd);

    if (order?.couponCode) {
      await redeemCouponByCode(order.couponCode, { userId: req.userId, email: u?.email, orderType: 'plan', referenceId: order._id.toString(), discountAmount: order.discountAmount });
    }

    res.json({ message: `Plan upgraded to ${plan}!`, plan });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Verification error.' }); }
});

// ==============================================
// SERVICE PURCHASE — ✅ FIX 2: ANY USER CAN BUY
// Buyers (and sellers) can purchase services
// No verifySeller check here — only login needed
// ==============================================
app.post('/api/services/create-order', async (req, res) => {
  try {
    const { serviceId, buyerName, buyerEmail, buyerPhone, message, couponCode } = req.body;
    if (!serviceId) return res.status(400).json({ message: 'serviceId required.' });
    if (!buyerName?.trim()) return res.status(400).json({ message: 'Name required.' });
    if (!buyerEmail?.trim()) return res.status(400).json({ message: 'Email required.' });
    if (!buyerPhone?.trim()) return res.status(400).json({ message: 'Phone required.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(buyerEmail.trim())) return res.status(400).json({ message: 'Invalid email.' });
    if (buyerPhone.replace(/\D/g, '').length < 7) return res.status(400).json({ message: 'Invalid phone.' });

    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Service not found.' });

    let buyerId = '';
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      try { const d = jwt.verify(authHeader.split(' ')[1], JWT_SECRET); buyerId = d.id; } catch { }
    }

    // ── Lead / free enquiry — no login required (unchanged) ──
    if (service.pricingType === 'lead' || service.price === 0) {
      const existing = await ServiceTransaction.findOne({ serviceId, buyerEmail: buyerEmail.trim().toLowerCase() });
      if (existing) return res.status(409).json({ message: 'Already submitted an enquiry.', redirectUrl: service.redirectUrl || null, alreadySubmitted: true });
      const txn = await new ServiceTransaction({ serviceId, sellerId: service.userId, buyerId, buyerName: buyerName.trim(), buyerEmail: buyerEmail.trim().toLowerCase(), buyerPhone: buyerPhone.trim(), message: message?.trim() || '', amount: 0, platformFee: 0, type: 'lead', paymentStatus: 'not_required', status: 'pending', redirectUrl: service.redirectUrl || '' }).save();
      return res.status(201).json({ message: 'Enquiry submitted!', redirectUrl: service.redirectUrl || null, transactionId: txn._id, paymentRequired: false, requiresAddress: service.requiresAddress || false });
    }

    // ── Paid service — login required (buyer OR seller) ──
    if (!buyerId) {
      return res.status(401).json({ message: 'Please log in to purchase this service.', requiresLogin: true });
    }

    if (service.pricingType === 'one_time') {
      const already = await ServiceTransaction.findOne({ serviceId, paymentStatus: 'paid', type: 'one_time', $or: [{ buyerId }, { buyerEmail: buyerEmail.trim().toLowerCase() }] });
      if (already) return res.status(409).json({ message: 'Already purchased.', alreadyPurchased: true, redirectUrl: already.redirectUrl || service.redirectUrl || null, transactionId: already._id, requiresAddress: service.requiresAddress || false });
    }

    const originalAmount = service.price;
    let amount = originalAmount;
    let discountAmount = 0;
    let appliedCoupon = null;

    if (couponCode) {
      const result = await validateCoupon({ code: couponCode, orderType: 'service', serviceId, amount, userId: buyerId, email: buyerEmail.trim().toLowerCase() });
      if (!result.valid) return res.status(400).json({ message: result.message });
      discountAmount = result.discount; amount = result.finalAmount; appliedCoupon = result.coupon;
    }

    const platformFee = Math.round(amount * PLATFORM_FEE_PERCENT / 100);

    // Fully covered by coupon — mark paid immediately, no Razorpay
    if (amount <= 0) {
      const txn = await new ServiceTransaction({
        serviceId, sellerId: service.userId, buyerId, buyerName: buyerName.trim(), buyerEmail: buyerEmail.trim().toLowerCase(),
        buyerPhone: buyerPhone.trim(), message: message?.trim() || '', amount: 0, platformFee: 0,
        originalAmount, couponCode: appliedCoupon?.code || '', discountAmount,
        type: service.pricingType, paymentStatus: 'paid', status: 'pending', redirectUrl: service.redirectUrl || ''
      }).save();
      if (appliedCoupon) await redeemCouponByCode(appliedCoupon.code, { userId: buyerId, email: buyerEmail, orderType: 'service', referenceId: txn._id.toString(), discountAmount });
      return res.status(201).json({ message: 'Purchase confirmed!', redirectUrl: txn.redirectUrl || service.redirectUrl || null, transactionId: txn._id, paymentRequired: false, requiresAddress: service.requiresAddress || false, discountAmount, originalAmount });
    }

    const ro = await razorpay.orders.create({ amount, currency: 'INR', receipt: `irx_svc_${serviceId.toString().substring(0, 8)}_${Date.now()}`, notes: { serviceId, sellerId: service.userId, buyerId, buyerName: buyerName.trim(), orderType: 'service_purchase', couponCode: appliedCoupon?.code || '' } });
    const txn = await new ServiceTransaction({
      serviceId, sellerId: service.userId, buyerId, buyerName: buyerName.trim(), buyerEmail: buyerEmail.trim().toLowerCase(),
      buyerPhone: buyerPhone.trim(), message: message?.trim() || '', amount, platformFee,
      originalAmount, couponCode: appliedCoupon?.code || '', discountAmount,
      razorpayOrderId: ro.id, type: service.pricingType, paymentStatus: 'pending', status: 'pending', redirectUrl: service.redirectUrl || ''
    }).save();
    res.status(201).json({ orderId: ro.id, amount: ro.amount, currency: ro.currency, keyId: process.env.RAZORPAY_KEY_ID, transactionId: txn._id, paymentRequired: true, requiresAddress: service.requiresAddress || false, discountAmount, originalAmount });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Could not create order.' }); }
});

app.post('/api/services/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
    if (expected !== razorpay_signature) {
      await ServiceTransaction.findOneAndUpdate({ razorpayOrderId: razorpay_order_id, paymentStatus: { $ne: 'paid' } }, { paymentStatus: 'failed' });
      return res.status(400).json({ message: 'Verification failed.' });
    }

    // Atomic: only the FIRST caller (verify-payment vs webhook) to mark paid gets `txn` non-null.
    const txn = await ServiceTransaction.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id, paymentStatus: { $ne: 'paid' } },
      { razorpayPaymentId: razorpay_payment_id, paymentStatus: 'paid' },
      { new: true }
    );

    // Fetch the txn either way (for response data) — it may already be paid from the webhook.
    const finalTxn = txn || await ServiceTransaction.findOne({ razorpayOrderId: razorpay_order_id });
    if (!finalTxn) return res.status(404).json({ message: 'Transaction not found.' });

    if (txn?.couponCode) {
      await redeemCouponByCode(txn.couponCode, { userId: txn.buyerId, email: txn.buyerEmail, orderType: 'service', referenceId: txn._id.toString(), discountAmount: txn.discountAmount });
    }

    const svc = await Service.findById(finalTxn.serviceId);
    res.json({ message: 'Purchase confirmed!', redirectUrl: finalTxn.redirectUrl || null, transactionId: finalTxn._id, requiresAddress: svc?.requiresAddress || false });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Verification error.' }); }
});

app.get('/api/admin/coupons', verifyAdmin, async (req, res) => {
  try { res.json(await Coupon.find().sort({ createdAt: -1 })); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/coupons', verifyAdmin, async (req, res) => {
  try {
    const { code, description, discountType, discountValue, appliesTo, applicablePlans, applicableServices, minAmount, maxDiscount, maxUses, maxUsesPerUser, expiresAt, active } = req.body;
    if (!code || !discountType || discountValue === undefined) return res.status(400).json({ message: 'code, discountType, discountValue required.' });
    if (!['percent', 'flat'].includes(discountType)) return res.status(400).json({ message: 'Invalid discountType.' });
    if (discountType === 'percent' && (discountValue < 0 || discountValue > 100)) return res.status(400).json({ message: 'Percent discount must be between 0 and 100.' });
    if (await Coupon.findOne({ code: code.trim().toUpperCase() })) return res.status(409).json({ message: 'Coupon code already exists.' });

    const coupon = await new Coupon({
      code: code.trim().toUpperCase(), description: description || '', discountType, discountValue,
      appliesTo: ['plan', 'service', 'all'].includes(appliesTo) ? appliesTo : 'all',
      applicablePlans: Array.isArray(applicablePlans) ? applicablePlans.filter(p => ['remote','studio','amplification'].includes(p)) : [],
      applicableServices: Array.isArray(applicableServices) ? applicableServices.filter(id => id && String(id).length === 24) : [],
      minAmount: minAmount || 0, maxDiscount: maxDiscount ?? null,
      maxUses: maxUses ?? null, maxUsesPerUser: maxUsesPerUser ?? 1,
      expiresAt: expiresAt ? new Date(expiresAt) : null, active: active !== false,
    }).save();
    res.status(201).json(coupon);
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/admin/coupons/:id', verifyAdmin, async (req, res) => {
  try {
    const coupon = await Coupon.findById(req.params.id);
    if (!coupon) return res.status(404).json({ message: 'Not found.' });
    ['description', 'discountType', 'discountValue', 'appliesTo', 'applicablePlans', 'applicableServices', 'minAmount', 'maxDiscount', 'maxUses', 'maxUsesPerUser', 'active'].forEach(f => { if (req.body[f] !== undefined) coupon[f] = req.body[f]; });
    if (req.body.expiresAt !== undefined) coupon.expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt) : null;
    if (req.body.code) {
      const newCode = req.body.code.trim().toUpperCase();
      if (newCode !== coupon.code && await Coupon.findOne({ code: newCode })) return res.status(409).json({ message: 'Coupon code already exists.' });
      coupon.code = newCode;
    }
    await coupon.save(); res.json(coupon);
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.delete('/api/admin/coupons/:id', verifyAdmin, async (req, res) => {
  try { await Coupon.findByIdAndDelete(req.params.id); res.json({ message: 'Deleted.' }); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/coupons/:id/redemptions', verifyAdmin, async (req, res) => {
  try { res.json(await CouponRedemption.find({ couponId: req.params.id }).sort({ createdAt: -1 })); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/services/save-address', optionalAuth, async (req, res) => {
  try {
    const { transactionId, buyerEmail, address } = req.body;
    if (!address?.line1 || !address?.city || !address?.state || !address?.pin) return res.status(400).json({ message: 'Incomplete address.' });
    let txn = transactionId ? await ServiceTransaction.findById(transactionId) : null;
    if (!txn && req.userId && req.body.serviceId) txn = await ServiceTransaction.findOne({ serviceId: req.body.serviceId, buyerId: req.userId, paymentStatus: { $in: ['paid', 'not_required'] } });
    if (!txn && buyerEmail && req.body.serviceId) txn = await ServiceTransaction.findOne({ serviceId: req.body.serviceId, buyerEmail: buyerEmail.toLowerCase().trim(), paymentStatus: { $in: ['paid', 'not_required'] } });
    if (!txn) return res.status(404).json({ message: 'Transaction not found.' });
    txn.shippingAddress = { line1: address.line1.trim(), line2: (address.line2 || '').trim(), city: address.city.trim(), state: address.state.trim(), pin: address.pin.trim() };
    await txn.save(); res.json({ message: 'Address saved.', shippingAddress: txn.shippingAddress });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error.' }); }
});

// ✅ FIX 3: my-purchases works for ALL logged-in users (buyers + sellers)
app.get('/api/my-purchases', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    const [byId, byEmail] = await Promise.all([
      ServiceTransaction.find({ buyerId: req.userId, paymentStatus: { $in: ['paid', 'not_required'] } }),
      ServiceTransaction.find({ buyerEmail: user.email.toLowerCase().trim(), paymentStatus: { $in: ['paid', 'not_required'] } }),
    ]);
    const seen = new Set(); const all = [];
    for (const t of [...byId, ...byEmail]) { const id = t._id.toString(); if (!seen.has(id)) { seen.add(id); all.push(t); } }
    all.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const svcMap = await getServiceMap(all.map(t => t.serviceId));
    const selMap = await getUserMap([...new Set(all.map(t => t.sellerId).filter(Boolean))]);
    const enriched = all.map(t => ({ ...t.toJSON(), serviceName: svcMap[t.serviceId?.toString()]?.serviceName || 'Deleted Service', sellerName: selMap[t.sellerId]?.profile?.guestName || 'Unknown', redirectUrl: t.redirectUrl || svcMap[t.serviceId?.toString()]?.redirectUrl || null, requiresAddress: svcMap[t.serviceId?.toString()]?.requiresAddress || false }));
    res.json({ totalPurchases: enriched.length, purchasedServiceIds: enriched.map(t => t.serviceId?.toString()).filter(Boolean), purchases: enriched });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Razorpay Webhook ──
app.post('/api/webhook/razorpay', async (req, res) => {
  try {
    const sig = req.headers['x-razorpay-signature'];
    if (RAZORPAY_WEBHOOK_SECRET) {
      const expected = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(req.rawBody).digest('hex');
      if (expected !== sig) return res.status(400).json({ message: 'Invalid signature.' });
    }
    const eventType = req.body?.event;

    if (eventType === 'payment.captured') {
      const payment = req.body.payload?.payment?.entity;
      const oid = payment?.order_id; const pid = payment?.id;
      if (!oid) return res.status(200).json({ message: 'No order_id.' });

      // ── Plan order ──
      const planOrder = await Order.findOneAndUpdate(
        { razorpayOrderId: oid, status: { $ne: 'paid' } },
        { razorpayPaymentId: pid, status: 'paid' },
        { new: true }
      );
      if (planOrder) {
        const upd = { plan: planOrder.plan };
        const u = await User.findById(planOrder.userId);
        if (u?.role === 'buyer') upd.role = 'seller';
        await User.findByIdAndUpdate(planOrder.userId, upd);

        if (planOrder.couponCode) {
          await redeemCouponByCode(planOrder.couponCode, { userId: planOrder.userId, email: u?.email, orderType: 'plan', referenceId: planOrder._id.toString(), discountAmount: planOrder.discountAmount });
        }
        return res.status(200).json({ message: 'Plan processed.' });
      }
      // Already-paid plan order — acknowledge without reprocessing
      if (await Order.findOne({ razorpayOrderId: oid })) return res.status(200).json({ message: 'Already processed.' });

      // ── Service transaction ──
      const st = await ServiceTransaction.findOneAndUpdate(
        { razorpayOrderId: oid, paymentStatus: { $ne: 'paid' } },
        { razorpayPaymentId: pid, paymentStatus: 'paid' },
        { new: true }
      );
      if (st) {
        if (st.couponCode) {
          await redeemCouponByCode(st.couponCode, { userId: st.buyerId, email: st.buyerEmail, orderType: 'service', referenceId: st._id.toString(), discountAmount: st.discountAmount });
        }
        return res.status(200).json({ message: 'Service payment processed.' });
      }
      if (await ServiceTransaction.findOne({ razorpayOrderId: oid })) return res.status(200).json({ message: 'Already processed.' });
    }

    if (eventType === 'payment.failed') {
      const oid = req.body.payload?.payment?.entity?.order_id;
      if (oid) {
        const p = await Order.findOneAndUpdate({ razorpayOrderId: oid, status: { $ne: 'paid' } }, { status: 'failed' });
        if (!p) await ServiceTransaction.findOneAndUpdate({ razorpayOrderId: oid, paymentStatus: { $ne: 'paid' } }, { paymentStatus: 'failed' });
      }
    }

    res.status(200).json({ message: 'Webhook processed.' });
  } catch (err) { console.error('Webhook error:', err); res.status(200).json({ message: 'Acknowledged.' }); }
});

// ── Public: Guests + Services ──
app.get('/api/guests', async (req, res) => {
  try {
    const users = await User.find({ role: 'seller', plan: { $ne: 'none' }, 'profile.guestName': { $exists: true, $ne: '' } });
    const ids = users.map(u => u._id.toString());
    const counts = await Episode.aggregate([{ $match: { userId: { $in: ids }, status: 'published' } }, { $group: { _id: '$userId', count: { $sum: 1 } } }]);
    const cm = Object.fromEntries(counts.map(c => [c._id, c.count]));
    res.json(users.map(u => ({ id: u._id, plan: u.plan, episodeStatus: u.episodeStatus, category: u.profile?.businessCategory, episodeCount: cm[u._id.toString()] || 0, ...u.profile })));
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.get('/api/guests/:id', async (req, res) => {
  try {
    const u = await User.findById(req.params.id);
    if (!u?.profile) return res.status(404).json({ message: 'Guest not found.' });
    const [svcs, eps] = await Promise.all([Service.find({ userId: req.params.id }), Episode.find({ userId: req.params.id, status: 'published' }).sort({ episodeNo: -1 })]);
    res.json({ plan: u.plan, episodeStatus: u.episodeStatus, profile: u.profile, services: svcs, episodes: eps.map(e => formatEpisode(e, false)) });
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.get('/api/services', async (req, res) => {
  try {
    const svcs = await Service.find().sort({ createdAt: -1 });
    const uMap = await getUserMap(svcs.map(s => s.userId));
    res.json(svcs.map(s => ({ ...s.toJSON(), creatorName: uMap[s.userId]?.profile?.guestName || 'Member' })));
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Seller service management ──
app.get('/api/my-services', verifyToken, verifySeller, async (req, res) => {
  try { res.json(await Service.find({ userId: req.userId }).sort({ createdAt: -1 })); }
  catch (err) { res.status(500).json({ message: err.message }); }
});
app.post('/api/services', verifyToken, verifySeller, async (req, res) => {
  try {
    const u = await User.findById(req.userId);
    if (!u || u.plan === 'none') return res.status(403).json({ message: 'Purchase a package first.' });
    
    const pricingType = req.body.pricingType || 'lead';
    const price = pricingType === 'lead' ? 0 : (parseInt(req.body.price) || 0);
    
    // Parse new hybrid fields safely
    const eventDate = req.body.eventDate ? new Date(req.body.eventDate) : null;
    const eventTime = req.body.eventTime || '';
    const whatYouWillLearn = Array.isArray(req.body.whatYouWillLearn) ? req.body.whatYouWillLearn : [];

    const s = await new Service({ 
      userId: req.userId, 
      serviceName: req.body.serviceName, 
      serviceDescription: req.body.serviceDescription, 
      redirectUrl: req.body.redirectUrl, 
      thumbnailUrl: req.body.thumbnailUrl, 
      scheduleText: req.body.scheduleText || '',
      duration: req.body.duration || '',
      format: req.body.format || '',
      language: req.body.language || '',
      category: req.body.category || 'General', 
      benefits: Array.isArray(req.body.benefits) ? req.body.benefits : [], 
      eventDate,
      eventTime,
      whatYouWillLearn,
      pricingType, 
      price, 
      requiresAddress: req.body.requiresAddress === true || req.body.requiresAddress === 'true' 
    }).save();
    
    res.json(s);
  } catch (err) { 
    console.error(err); 
    res.status(500).json({ message: 'Server error', error: err.message }); 
  }
});
app.put('/api/services/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const s = await Service.findOne({ _id: req.params.id, userId: req.userId });
    if (!s) return res.status(404).json({ message: 'Not found.' });
    
    // Process standard string/array fields
const updatableFields = [
      'serviceName', 'serviceDescription', 'redirectUrl', 'thumbnailUrl', 
      'category', 'pricingType', 'price', 'requiresAddress', 'benefits', 
      'eventTime', 'whatYouWillLearn', 'scheduleText', 'duration', 'format', 'language'
    ];
    
    updatableFields.forEach(f => { 
      if (req.body[f] !== undefined) s[f] = req.body[f]; 
    });

    // Handle date casting explicitly
    if (req.body.eventDate !== undefined) {
      s.eventDate = req.body.eventDate ? new Date(req.body.eventDate) : null;
    }

    // Enforce pricing logic
    if (s.pricingType === 'lead') s.price = 0;
    
    await s.save(); 
    res.json(s);
  } catch (err) { 
    console.error(err); 
    res.status(500).json({ message: 'Server error', error: err.message }); 
  }
});
app.delete('/api/services/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const s = await Service.findOne({ _id: req.params.id, userId: req.userId });
    if (!s) return res.status(404).json({ message: 'Not found.' });
    await Service.deleteOne({ _id: req.params.id }); res.json({ message: 'Deleted.' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Seller dashboard + sales ──
app.get('/api/my-dashboard', verifyToken, verifySeller, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const [services, episodes, transactions] = await Promise.all([Service.find({ userId: req.userId }), Episode.find({ userId: req.userId, status: 'published' }), ServiceTransaction.find({ sellerId: req.userId }).sort({ createdAt: -1 })]);
    const svcMap = Object.fromEntries(services.map(s => [s._id.toString(), s]));
    const pp = t => ({ paid: 0, pending: 1, not_required: 2, failed: 3 }[t.paymentStatus] ?? 4);
    const deduped = new Map();
    for (const t of transactions) { const k = `${t.buyerEmail?.toLowerCase()?.trim()}__${t.serviceId}`; const ex = deduped.get(k); if (!ex || pp(t) < pp(ex)) deduped.set(k, t); }
    const leads = Array.from(deduped.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const paid = leads.filter(t => t.paymentStatus === 'paid');
    res.json({ profile: user?.profile || {}, plan: user?.plan, episodeStatus: user?.episodeStatus, summary: { totalLeads: leads.length, newLeads: leads.filter(t => t.status === 'pending').length, contacted: leads.filter(t => t.status === 'contacted').length, converted: leads.filter(t => t.status === 'converted').length, closed: leads.filter(t => t.status === 'closed').length, totalRevenue: paid.reduce((s, t) => s + (t.amount || 0), 0), netRevenue: paid.reduce((s, t) => s + ((t.amount || 0) - (t.platformFee || 0)), 0), totalServices: services.length, totalEpisodes: episodes.length, addressPending: leads.filter(t => { const sv = svcMap[t.serviceId?.toString()]; return sv?.requiresAddress && !t.shippingAddress?.line1; }).length }, recentLeads: leads.slice(0, 10).map(t => ({ ...t.toJSON(), serviceName: svcMap[t.serviceId?.toString()]?.serviceName || 'Deleted', requiresAddress: svcMap[t.serviceId?.toString()]?.requiresAddress || false })) });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});
app.get('/api/my-sales', verifyToken, verifySeller, async (req, res) => {
  try {
    const txns = await ServiceTransaction.find({ sellerId: req.userId }).sort({ createdAt: -1 });
    const svcMap = await getServiceMap(txns.map(t => t.serviceId));
    const enriched = txns.map(t => ({ ...t.toJSON(), serviceName: svcMap[t.serviceId?.toString()]?.serviceName || 'Deleted', requiresAddress: svcMap[t.serviceId?.toString()]?.requiresAddress || false }));
    const pp = t => ({ paid: 0, pending: 1, not_required: 2, failed: 3 }[t.paymentStatus] ?? 4);
    const deduped = new Map();
    for (const t of enriched) { const k = `${t.buyerEmail?.toLowerCase()?.trim()}__${t.serviceId}`; const ex = deduped.get(k); if (!ex || pp(t) < pp(ex)) deduped.set(k, t); }
    const list = Array.from(deduped.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const paid = list.filter(t => t.paymentStatus === 'paid');
    res.json({ summary: { totalLeads: list.length, converted: list.filter(t => t.status === 'converted').length, totalRevenue: paid.reduce((s, t) => s + (t.amount || 0), 0), netRevenue: paid.reduce((s, t) => s + ((t.amount || 0) - (t.platformFee || 0)), 0) }, transactions: list });
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});
app.patch('/api/my-sales/:txnId', verifyToken, verifySeller, async (req, res) => {
  try {
    const { status } = req.body; if (!['pending', 'contacted', 'converted', 'closed'].includes(status)) return res.status(400).json({ message: 'Invalid status.' });
    const t = await ServiceTransaction.findOne({ _id: req.params.txnId, sellerId: req.userId });
    if (!t) return res.status(404).json({ message: 'Not found.' });
    t.status = status; await t.save(); res.json({ message: 'Updated.', status: t.status });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Service Extras (Seller) ──
app.get('/api/my-service-extras', verifyToken, verifySeller, async (req, res) => {
  try { res.json(await ServiceExtra.find({ userId: req.userId }).sort({ sortOrder: -1, createdAt: -1 })); }
  catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/my-service-extras', verifyToken, verifySeller, async (req, res) => {
  try {
    const { title, description, videoUrl, thumbnail, tags, featuredTag, duration, publishedAt, status, sortOrder, serviceId } = req.body;
    if (!title) return res.status(400).json({ message: 'Title is required.' });
    const se = new ServiceExtra({
      userId: req.userId,
      serviceId: serviceId || '',
      title: title.trim(),
      description: description?.trim() || '',
      videoUrl: videoUrl?.trim() || '',
      thumbnail: thumbnail || '',
      tags: Array.isArray(tags) ? tags.map(t => t.trim().toLowerCase()) : [],
      featuredTag: featuredTag?.trim() || '',
      duration: duration?.trim() || '',
      publishedAt: publishedAt ? new Date(publishedAt) : null,
      status: ['draft', 'published', 'archived'].includes(status) ? status : 'published',
      sortOrder: sortOrder || 0,
    });
    await se.save();
    res.status(201).json(se.toJSON ? se.toJSON() : se);
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/my-service-extras/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const se = await ServiceExtra.findOne({ _id: req.params.id, userId: req.userId });
    if (!se) return res.status(404).json({ message: 'Service extra not found.' });
    ['title', 'description', 'videoUrl', 'thumbnail', 'tags', 'featuredTag', 'duration', 'publishedAt', 'status', 'sortOrder', 'serviceId'].forEach(f => {
      if (req.body[f] !== undefined) se[f] = req.body[f];
    });
    if (req.body.tags && Array.isArray(req.body.tags)) se.tags = req.body.tags.map(t => t.trim().toLowerCase());
    await se.save();
    res.json(se.toJSON ? se.toJSON() : se);
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.delete('/api/my-service-extras/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const se = await ServiceExtra.findOne({ _id: req.params.id, userId: req.userId });
    if (!se) return res.status(404).json({ message: 'Service extra not found.' });
    await ServiceExtra.deleteOne({ _id: req.params.id });
    res.json({ message: 'Service extra deleted.' });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Service Extras (Public) ──
app.get('/api/service-extras/:sellerId', async (req, res) => {
  try {
    const extras = await ServiceExtra.find({ userId: req.params.sellerId, status: 'published' }).sort({ sortOrder: -1, createdAt: -1 });
    res.json(extras);
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/service-extras/service/:serviceId', async (req, res) => {
  try {
    const extras = await ServiceExtra.find({ serviceId: req.params.serviceId, status: 'published' }).sort({ sortOrder: -1, createdAt: -1 });
    res.json(extras);
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// ── Service Extras (Admin) ──
app.get('/api/admin/service-extras', verifyAdmin, async (req, res) => {
  try {
    const extras = await ServiceExtra.find().sort({ createdAt: -1 });
    const uMap = await getUserMap(extras.map(e => e.userId));
    res.json({ total: extras.length, extras: extras.map(e => ({ ...(e.toJSON ? e.toJSON() : e), sellerName: uMap[e.userId]?.profile?.guestName || 'Unknown', sellerEmail: uMap[e.userId]?.email || '' })) });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/service-extras', verifyAdmin, async (req, res) => {
  try {
    const { userId, title, description, videoUrl, thumbnail, tags, featuredTag, duration, publishedAt, status, sortOrder, serviceId } = req.body;
    if (!userId || !title) return res.status(400).json({ message: 'userId and title required.' });
    const se = new ServiceExtra({
      userId, serviceId: serviceId || '', title: title.trim(), description: description?.trim() || '',
      videoUrl: videoUrl?.trim() || '', thumbnail: thumbnail || '',
      tags: Array.isArray(tags) ? tags.map(t => t.trim().toLowerCase()) : [],
      featuredTag: featuredTag?.trim() || '', duration: duration?.trim() || '',
      publishedAt: publishedAt ? new Date(publishedAt) : null,
      status: ['draft', 'published', 'archived'].includes(status) ? status : 'published',
      sortOrder: sortOrder || 0,
    });
    await se.save();
    res.status(201).json(se.toJSON ? se.toJSON() : se);
  } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/admin/service-extras/:id', verifyAdmin, async (req, res) => {
  try {
    const se = await ServiceExtra.findById(req.params.id);
    if (!se) return res.status(404).json({ message: 'Not found.' });
    ['title', 'description', 'videoUrl', 'thumbnail', 'tags', 'featuredTag', 'duration', 'publishedAt', 'status', 'sortOrder', 'userId', 'serviceId'].forEach(f => {
      if (req.body[f] !== undefined) se[f] = req.body[f];
    });
    if (req.body.tags && Array.isArray(req.body.tags)) se.tags = req.body.tags.map(t => t.trim().toLowerCase());
    await se.save();
    res.json(se.toJSON ? se.toJSON() : se);
  } catch { res.status(500).json({ message: 'Server error' }); }
});

app.delete('/api/admin/service-extras/:id', verifyAdmin, async (req, res) => {
  try { await ServiceExtra.findByIdAndDelete(req.params.id); res.json({ message: 'Deleted.' }); }
  catch { res.status(500).json({ message: 'Server error' }); }
});

// ── Admin ──
app.post('/api/admin/login', (req, res) => { if (req.body.secret !== ADMIN_SECRET) return res.status(403).json({ message: 'Wrong secret.' }); res.json({ token: ADMIN_SECRET, message: 'Admin access granted.' }); });
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    const ids = users.map(u => u._id.toString());
    const [sc, lc, ec] = await Promise.all([
      Service.aggregate([{ $match: { userId: { $in: ids } } }, { $group: { _id: '$userId', count: { $sum: 1 } } }]),
      ServiceTransaction.aggregate([{ $match: { sellerId: { $in: ids } } }, { $group: { _id: '$sellerId', count: { $sum: 1 } } }]),
      Episode.aggregate([{ $match: { userId: { $in: ids } } }, { $group: { _id: '$userId', count: { $sum: 1 } } }]),
    ]);
    const scm = Object.fromEntries(sc.map(c => [c._id, c.count])), lcm = Object.fromEntries(lc.map(c => [c._id, c.count])), ecm = Object.fromEntries(ec.map(c => [c._id, c.count]));
    res.json(users.map(u => ({ id: u._id, email: u.email, role: u.role, plan: u.plan, episodeStatus: u.episodeStatus, guestName: u.profile?.guestName || '', guestImage: u.profile?.guestImage || '', businessCategory: u.profile?.businessCategory || '', location: u.profile?.location || '', phone: u.profile?.phone || '', serviceCount: scm[u._id.toString()] || 0, leadCount: lcm[u._id.toString()] || 0, episodeCount: ecm[u._id.toString()] || 0, createdAt: u.createdAt })));
  } catch { res.status(500).json({ message: 'Server error' }); }
});
app.patch('/api/admin/users/:id/role', verifyAdmin, async (req, res) => { try { const { role } = req.body; if (!['admin', 'seller', 'buyer'].includes(role)) return res.status(400).json({ message: 'Invalid.' }); const u = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }); if (!u) return res.status(404).json({ message: 'Not found.' }); res.json({ message: 'Updated.', role: u.role }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.patch('/api/admin/users/:id/plan', verifyAdmin, async (req, res) => { try { const { plan } = req.body; if (!['none', 'remote', 'studio', 'amplification'].includes(plan)) return res.status(400).json({ message: 'Invalid.' }); const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ message: 'Not found.' }); const upd = { plan }; if (plan !== 'none' && u.role === 'buyer') upd.role = 'seller'; if (plan === 'none' && u.role === 'seller') upd.role = 'buyer'; const updated = await User.findByIdAndUpdate(req.params.id, upd, { new: true }); res.json({ message: 'Updated.', plan: updated.plan, role: updated.role }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.patch('/api/admin/users/:id/episode', verifyAdmin, async (req, res) => { try { const { episodeStatus } = req.body; if (!['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'].includes(episodeStatus)) return res.status(400).json({ message: 'Invalid.' }); const u = await User.findByIdAndUpdate(req.params.id, { episodeStatus }, { new: true }); if (!u) return res.status(404).json({ message: 'Not found.' }); res.json({ message: 'Updated.', episodeStatus: u.episodeStatus }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => { try { const id = req.params.id; await User.findByIdAndDelete(id); await Service.deleteMany({ userId: id }); await Episode.deleteMany({ userId: id }); await ServiceTransaction.updateMany({ sellerId: id }, { $set: { sellerId: '' } }); await ServiceTransaction.updateMany({ buyerId: id }, { $set: { buyerId: '' } }); res.json({ message: 'User deleted.' }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.get('/api/admin/services', verifyAdmin, async (req, res) => { try { const svcs = await Service.find().sort({ createdAt: -1 }); const uMap = await getUserMap(svcs.map(s => s.userId)); const lc = await ServiceTransaction.aggregate([{ $match: { serviceId: { $in: svcs.map(s => s._id) } } }, { $group: { _id: '$serviceId', count: { $sum: 1 } } }]); const lcm = Object.fromEntries(lc.map(c => [c._id.toString(), c.count])); res.json(svcs.map(s => ({ ...s.toJSON(), creatorName: uMap[s.userId]?.profile?.guestName || 'Unknown', creatorEmail: uMap[s.userId]?.email || '', leadCount: lcm[s._id.toString()] || 0 }))); } catch { res.status(500).json({ message: 'Server error' }); } });
app.delete('/api/admin/services/:id', verifyAdmin, async (req, res) => { try { await Service.findByIdAndDelete(req.params.id); res.json({ message: 'Deleted.' }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.get('/api/admin/service-sales', verifyAdmin, async (req, res) => { try { const txns = await ServiceTransaction.find().sort({ createdAt: -1 }); const svcMap = await getServiceMap(txns.map(t => t.serviceId)); const [sMap, bMap] = await Promise.all([getUserMap([...new Set(txns.map(t => t.sellerId).filter(Boolean))]), getUserMap([...new Set(txns.map(t => t.buyerId).filter(Boolean))])]); const enriched = txns.map(t => ({ ...t.toJSON(), serviceName: svcMap[t.serviceId?.toString()]?.serviceName || 'Deleted', requiresAddress: svcMap[t.serviceId?.toString()]?.requiresAddress || false, sellerName: sMap[t.sellerId]?.profile?.guestName || 'Unknown', sellerEmail: sMap[t.sellerId]?.email || '', buyerAccount: bMap[t.buyerId]?.email || t.buyerEmail })); const paid = enriched.filter(t => t.paymentStatus === 'paid'); res.json({ summary: { totalTransactions: enriched.length, totalRevenue: paid.reduce((s, t) => s + (t.amount || 0), 0), totalPlatformFee: paid.reduce((s, t) => s + (t.platformFee || 0), 0), byType: { lead: enriched.filter(t => t.type === 'lead').length, one_time: enriched.filter(t => t.type === 'one_time').length, subscription: enriched.filter(t => t.type === 'subscription').length }, byPaymentStatus: { not_required: enriched.filter(t => t.paymentStatus === 'not_required').length, pending: enriched.filter(t => t.paymentStatus === 'pending').length, paid: enriched.filter(t => t.paymentStatus === 'paid').length, failed: enriched.filter(t => t.paymentStatus === 'failed').length }, byCRMStatus: { pending: enriched.filter(t => t.status === 'pending').length, contacted: enriched.filter(t => t.status === 'contacted').length, converted: enriched.filter(t => t.status === 'converted').length, closed: enriched.filter(t => t.status === 'closed').length } }, transactions: enriched }); } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); } });
app.patch('/api/admin/service-sales/:txnId', verifyAdmin, async (req, res) => { try { const { status, paymentStatus, amount } = req.body; const upd = {}; if (status !== undefined) { if (!['pending', 'contacted', 'converted', 'closed'].includes(status)) return res.status(400).json({ message: 'Invalid status.' }); upd.status = status; } if (paymentStatus !== undefined) { if (!['pending', 'paid', 'failed', 'not_required'].includes(paymentStatus)) return res.status(400).json({ message: 'Invalid paymentStatus.' }); upd.paymentStatus = paymentStatus; } if (amount !== undefined) upd.amount = amount; const t = await ServiceTransaction.findByIdAndUpdate(req.params.txnId, upd, { new: true }); if (!t) return res.status(404).json({ message: 'Not found.' }); res.json({ message: 'Updated.', transaction: t }); } catch { res.status(500).json({ message: 'Server error' }); } });
app.get('/api/admin/stats', verifyAdmin, async (req, res) => { try { const [tu, ts, tb, ps, tsvc, tl, te, pr, pst, pa, ru, rl, re, pst2] = await Promise.all([User.countDocuments(), User.countDocuments({ role: 'seller' }), User.countDocuments({ role: 'buyer' }), User.countDocuments({ role: 'seller', plan: { $ne: 'none' } }), Service.countDocuments(), ServiceTransaction.countDocuments(), Episode.countDocuments({ status: 'published' }), User.countDocuments({ plan: 'remote' }), User.countDocuments({ plan: 'studio' }), User.countDocuments({ plan: 'amplification' }), User.find().sort({ createdAt: -1 }).limit(5), ServiceTransaction.find().sort({ createdAt: -1 }).limit(5), Episode.find({ status: 'published' }).sort({ createdAt: -1 }).limit(5), ServiceTransaction.find({ paymentStatus: 'paid' })]); res.json({ totalUsers: tu, totalSellers: ts, totalBuyers: tb, paidSellers: ps, totalServices: tsvc, totalLeads: tl, totalEpisodes: te, planBreakdown: { remote: pr, studio: pst, amplification: pa }, planRevenue: pr * 5000 + pst * 12000 + pa * 25000, serviceRevenue: pst2.reduce((s, t) => s + (t.amount || 0), 0), platformFees: pst2.reduce((s, t) => s + (t.platformFee || 0), 0), recentUsers: ru.map(u => ({ id: u._id, email: u.email, role: u.role, plan: u.plan, guestName: u.profile?.guestName || '', createdAt: u.createdAt })), recentLeads: rl, recentEpisodes: re.map(e => formatEpisode(e, true)) }); } catch (err) { console.error(err); res.status(500).json({ message: 'Server error' }); } });
app.get('/api/admin/orders', verifyAdmin, async (req, res) => { try { res.json(await Order.find().sort({ createdAt: -1 }).limit(50)); } catch { res.status(500).json({ message: 'Server error' }); } });
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString(), env: IS_DEV ? 'development' : 'production' }));
app.use((err, req, res, next) => { if (err.message?.startsWith('CORS:')) return res.status(403).json({ message: err.message }); console.error(err); res.status(500).json({ message: 'Internal server error.' }); });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`IRX Backend running on port ${PORT} [${IS_DEV ? 'development' : 'production'}]`); console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`); });
