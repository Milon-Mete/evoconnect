require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();

// ==========================================
// RAW BODY FOR RAZORPAY WEBHOOK (must come BEFORE express.json())
// ==========================================
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhook/razorpay') {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      req.rawBody = raw;
      try { req.body = JSON.parse(raw); } catch { req.body = {}; }
      next();
    });
  } else {
    next();
  }
});

app.use(cors());
app.use(express.json());

// ==========================================
// ENV / CONSTANTS
// ==========================================
const JWT_SECRET               = process.env.JWT_SECRET;
const ADMIN_SECRET             = process.env.ADMIN_SECRET || 'irx_admin_2026';
const RAZORPAY_WEBHOOK_SECRET  = process.env.RAZORPAY_WEBHOOK_SECRET;
const PLATFORM_FEE_PERCENT     = parseFloat(process.env.PLATFORM_FEE_PERCENT || '0');

const PLAN_PRICES = {
  remote:        500000,   // ₹5,000 in paise
  studio:        1200000,  // ₹12,000 in paise
  amplification: 2500000   // ₹25,000 in paise
};

// ==========================================
// RAZORPAY INSTANCE
// ==========================================
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ==========================================
// DB CONNECTION
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

const toJSONConfig = {
  virtuals: true,
  transform: (doc, ret) => { delete ret._id; delete ret.__v; }
};

// ==========================================
// SCHEMAS & MODELS
// ==========================================

// --- User ---
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: {
    type:    String,
    enum:    ['admin', 'seller', 'buyer'],
    default: 'buyer'
  },
  plan: {
    type:    String,
    enum:    ['none', 'remote', 'studio', 'amplification'],
    default: 'none'
  },
  episodeStatus: {
    type:    String,
    enum:    ['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'],
    default: 'pending'
  },
  profile: {
    guestName:        String,
    guestImage:       String,
    guestDescription: String,
    youtubeUrl:       String,
    businessCategory: String,
    location:         String,
    phone:            String,
    website:          String,
    linkedin:         String,
  },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true, toJSON: toJSONConfig });

// --- Episode ---
const episodeSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },

  episodeNo:   { type: Number, required: true },
  title:       { type: String, required: true },
  description: { type: String, default: '' },

  youtubeUrl:  { type: String, default: '' },
  youtubeId:   { type: String, default: '' },

  thumbnail:   { type: String, default: '' },

  tags:        [{ type: String }],
  featuredTag: { type: String, default: '' },

  duration:    { type: String, default: '' },

  guests:      [{ type: String }],

  publishedAt: { type: Date, default: null },

  status: {
    type:    String,
    enum:    ['draft', 'published', 'archived'],
    default: 'published'
  },

  views:       { type: Number, default: 0 },
  likes:       { type: Number, default: 0 },

  adminNotes:  { type: String, default: '' },

}, { timestamps: true, toJSON: toJSONConfig });

episodeSchema.virtual('thumbnailUrl').get(function () {
  if (this.thumbnail) return this.thumbnail;
  if (this.youtubeId) return `https://img.youtube.com/vi/${this.youtubeId}/hqdefault.jpg`;
  return '';
});

function extractYouTubeId(url) {
  if (!url) return '';
  const patterns = [
    /(?:v=|\/v\/|youtu\.be\/|\/embed\/|\/shorts\/)([a-zA-Z0-9_-]{11})/
  ];
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) return match[1];
  }
  return '';
}

// --- Service ---
const serviceSchema = new mongoose.Schema({
  userId:             { type: String, required: true },
  serviceName:        String,
  serviceDescription: String,
  redirectUrl:        String,
  thumbnailUrl:       String,
  category:           { type: String, default: 'General' },
  pricingType: {
    type:    String,
    enum:    ['lead', 'one_time', 'subscription'],
    default: 'lead'
  },
  price:            { type: Number, default: 0 },
  requiresAddress:  { type: Boolean, default: false },  // ← NEW: shipping address gate
}, { timestamps: true, toJSON: toJSONConfig });

// --- Plan Order ---
const orderSchema = new mongoose.Schema({
  userId:            String,
  razorpayOrderId:   String,
  razorpayPaymentId: String,
  plan:              String,
  amount:            Number,
  status:            { type: String, enum: ['created', 'paid', 'failed'], default: 'created' }
}, { timestamps: true, toJSON: toJSONConfig });

// --- Service Transaction ---
const serviceTransactionSchema = new mongoose.Schema({
  serviceId:         { type: mongoose.Schema.Types.ObjectId, ref: 'Servicee', required: true },
  sellerId:          { type: String, required: true },
  buyerId:           { type: String, default: '' },

  buyerName:         { type: String, required: true },
  buyerEmail:        { type: String, required: true },
  buyerPhone:        { type: String, default: '' },
  message:           { type: String, default: '' },

  // ── Shipping address (only populated when service.requiresAddress === true) ──
  shippingAddress: {
    line1:  { type: String, default: '' },
    line2:  { type: String, default: '' },
    city:   { type: String, default: '' },
    state:  { type: String, default: '' },
    pin:    { type: String, default: '' },
  },

  amount:            { type: Number, default: 0 },
  platformFee:       { type: Number, default: 0 },

  razorpayOrderId:   { type: String, default: '' },
  razorpayPaymentId: { type: String, default: '' },

  type: {
    type:    String,
    enum:    ['lead', 'one_time', 'subscription'],
    default: 'lead'
  },
  paymentStatus: {
    type:    String,
    enum:    ['not_required', 'pending', 'paid', 'failed'],
    default: 'not_required'
  },
  status: {
    type:    String,
    enum:    ['pending', 'contacted', 'converted', 'closed'],
    default: 'pending'
  },
  redirectUrl: { type: String, default: '' },
}, { timestamps: true, toJSON: toJSONConfig });

const User               = mongoose.model('Usere',              userSchema);
const Episode            = mongoose.model('Episode',            episodeSchema);
const Service            = mongoose.model('Servicee',           serviceSchema);
const Order              = mongoose.model('Order',              orderSchema);
const ServiceTransaction = mongoose.model('ServiceTransaction', serviceTransactionSchema);

// ==========================================
// MIDDLEWARE
// ==========================================
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided. Please log in.' });
  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized or expired token. Please log in again.' });
    req.userId   = decoded.id;
    req.userRole = decoded.role;
    next();
  });
}

// Optional auth — attaches userId if token is valid but doesn't block the request
function optionalAuth(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) { next(); return; }
  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    req.userId   = decoded.id;
    req.userRole = decoded.role;
  } catch { /* invalid / expired — continue as guest */ }
  next();
}

function verifySeller(req, res, next) {
  if (!['seller', 'admin'].includes(req.userRole)) {
    return res.status(403).json({ message: 'Seller account required.' });
  }
  next();
}

function verifyAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) return res.status(403).json({ message: 'Admin access denied.' });
  next();
}

// ==========================================
// AUTH ROUTES
// ==========================================

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

    const allowedRoles = ['buyer', 'seller'];
    const assignedRole = allowedRoles.includes(role) ? role : 'buyer';

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'User already exists.' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, role: assignedRole, plan: 'none' });
    await user.save();
    res.status(201).json({ message: 'Account created! Please log in.', role: assignedRole });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials.' });
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, role: user.role, message: 'Logged in successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// USER / PROFILE ROUTES
// ==========================================

app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({
      id:            user._id,
      email:         user.email,
      role:          user.role,
      plan:          user.plan,
      episodeStatus: user.episodeStatus,
      profile:       user.profile
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/profile', verifyToken, verifySeller, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    if (user.plan === 'none') return res.status(403).json({ message: 'Purchase a package first.' });
    user.profile = {
      guestName:        req.body.guestName        || '',
      guestImage:       req.body.guestImage        || '',
      guestDescription: req.body.guestDescription  || '',
      youtubeUrl:       req.body.youtubeUrl         || '',
      businessCategory: req.body.businessCategory   || '',
      location:         req.body.location           || '',
      phone:            req.body.phone              || '',
      website:          req.body.website            || '',
      linkedin:         req.body.linkedin           || '',
    };
    await user.save();
    res.json({ message: 'Profile updated successfully.', profile: user.profile });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/buyer-profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    const { name, phone } = req.body;
    if (name !== undefined) user.profile.guestName = name;
    if (phone !== undefined) user.profile.phone = phone;
    await user.save();
    res.json({ message: 'Buyer profile updated successfully.', profile: user.profile });
  } catch (err) {
    console.error('Error updating buyer profile:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// EPISODES — FULL CRUD
// ==========================================

// ── Helper: build safe episode object ──
function formatEpisode(ep, includeVideo = true) {
  const obj = ep.toJSON ? ep.toJSON() : { ...ep };

  // Always set hasVideo correctly based on the raw database fields
  obj.hasVideo = !!(ep.youtubeId || (ep.youtubeUrl && extractYouTubeId(ep.youtubeUrl)));

  // Thumbnail logic
  if (!obj.thumbnail && obj.youtubeId) {
    obj.thumbnailUrl = `https://img.youtube.com/vi/${obj.youtubeId}/hqdefault.jpg`;
  } else {
    obj.thumbnailUrl = obj.thumbnail || '';
  }

  // Video URL stripping logic
  if (includeVideo && obj.youtubeId) {
    obj.embedUrl = `https://www.youtube.com/embed/${obj.youtubeId}`;
  } else if (!includeVideo) {
    delete obj.youtubeUrl;
    delete obj.youtubeId;
    obj.embedUrl = null;
  }

  return obj;
}

// ── PUBLIC: all published episodes (paginated) ──
// NOTE: youtubeUrl / youtubeId are NOT returned here — callers must use
//       /api/episodes/purchased/:serviceId to get the full video data.
app.get('/api/episodes', async (req, res) => {
  try {
    const page     = parseInt(req.query.page)  || 1;
    const limit    = parseInt(req.query.limit) || 20;
    const tag      = req.query.tag   || '';
    const search   = req.query.search || '';
    const sellerId = req.query.sellerId || '';

    const filter = { status: 'published' };
    if (tag)      filter.tags      = { $in: [tag] };
    if (sellerId) filter.userId    = sellerId;
    if (search)   filter.$or = [
      { title:       { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } },
      { tags:        { $regex: search, $options: 'i' } },
    ];

    const total    = await Episode.countDocuments(filter);
    const episodes = await Episode.find(filter)
      .sort({ episodeNo: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const enriched = await Promise.all(episodes.map(async ep => {
      const seller = await User.findById(ep.userId);
      return {
        ...formatEpisode(ep, false),  // ← no video URLs in public listing
        sellerName:  seller?.profile?.guestName  || 'Member',
        sellerImage: seller?.profile?.guestImage || '',
      };
    }));

    res.json({
      total,
      page,
      totalPages: Math.ceil(total / limit),
      episodes:   enriched
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── PUBLIC: all published episodes for a specific seller (no video URLs) ──
app.get('/api/episodes/seller/:sellerId', async (req, res) => {
  try {
    const episodes = await Episode.find({
      userId: req.params.sellerId,
      status: 'published'
    }).sort({ episodeNo: -1 });

    res.json(episodes.map(ep => formatEpisode(ep, false)));
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── PURCHASED: episodes with full video data for a buyer who owns a service ──
// Returns full youtubeUrl / youtubeId / embedUrl only if:
//   a) the caller is authenticated AND
//   b) they have a paid ServiceTransaction for the given serviceId
// The serviceId links a service to its seller's episodes.
app.get('/api/episodes/purchased/:serviceId', optionalAuth, async (req, res) => {
  try {
    const { serviceId } = req.params;
    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Service not found.' });

    const sellerId = service.userId;
    let hasPurchased = false;

    if (req.userId) {
      // FIX: Grant the seller access to their own service
      if (req.userId === sellerId) {
        hasPurchased = true;
      } else {
        // Existing buyer checks...
        const txnById = await ServiceTransaction.findOne({
          serviceId,
          buyerId:       req.userId,
          paymentStatus: { $in: ['paid', 'not_required'] }
        });
        if (txnById) hasPurchased = true;

        if (!hasPurchased) {
          const user = await User.findById(req.userId);
          if (user) {
            const txnByEmail = await ServiceTransaction.findOne({
              serviceId,
              buyerEmail:    user.email.toLowerCase().trim(),
              paymentStatus: { $in: ['paid', 'not_required'] }
            });
            if (txnByEmail) hasPurchased = true;
          }
        }
      }
    }
// ... rest of the route

    // Fetch published episodes for this seller
    const episodes = await Episode.find({
      userId: sellerId,
      status: 'published'
    }).sort({ episodeNo: -1 });

    if (hasPurchased) {
      // Full data including video URLs
      res.json({
        purchased: true,
        episodes:  episodes.map(ep => formatEpisode(ep, true))
      });
    } else {
      // Teaser data — no video URLs, but enough to render locked cards
      res.json({
        purchased: false,
        episodes:  episodes.map(ep => formatEpisode(ep, false))
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── PUBLIC: single episode detail ──
app.get('/api/episodes/:id', async (req, res) => {
  try {
    const episode = await Episode.findById(req.params.id);
    if (!episode || episode.status === 'archived') {
      return res.status(404).json({ message: 'Episode not found.' });
    }
    const seller = await User.findById(episode.userId);
    res.json({
      ...formatEpisode(episode, false),  // public detail — no video
      sellerName:       seller?.profile?.guestName        || 'Member',
      sellerImage:      seller?.profile?.guestImage       || '',
      sellerCategory:   seller?.profile?.businessCategory || '',
      sellerLinkedin:   seller?.profile?.linkedin         || '',
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── SELLER: get my episodes ──
app.get('/api/my-episodes', verifyToken, verifySeller, async (req, res) => {
  try {
    const episodes = await Episode.find({ userId: req.userId }).sort({ episodeNo: -1 });
    res.json(episodes.map(ep => formatEpisode(ep, true)));  // sellers always see full data
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── SELLER: create episode ──
app.post('/api/my-episodes', verifyToken, verifySeller, async (req, res) => {
  try {
    const {
      episodeNo, title, description, youtubeUrl, thumbnail,
      tags, featuredTag, duration, guests, publishedAt, status
    } = req.body;

    if (!episodeNo)   return res.status(400).json({ message: 'episodeNo is required.' });
    if (!title)       return res.status(400).json({ message: 'Episode title is required.' });
const youtubeId = youtubeUrl ? extractYouTubeId(youtubeUrl.trim()) : '';
if (youtubeUrl && !youtubeId) {
  return res.status(400).json({ message: 'Could not extract a valid YouTube video ID from the URL.' });
}

    const existing = await Episode.findOne({ userId: req.userId, episodeNo });
    if (existing) return res.status(409).json({ message: `Episode #${episodeNo} already exists for your account.` });

    const episode = new Episode({
      userId:      req.userId,
      episodeNo:   parseInt(episodeNo),
      title:       title.trim(),
      description: description ? description.trim() : '',
      youtubeUrl:  youtubeUrl ? youtubeUrl.trim() : '',
      youtubeId,
      thumbnail:   thumbnail || '',
      tags:        Array.isArray(tags) ? tags.map(t => t.trim().toLowerCase()) : [],
      featuredTag: featuredTag ? featuredTag.trim() : '',
      duration:    duration   ? duration.trim()    : '',
      guests:      Array.isArray(guests) ? guests.map(g => g.trim()) : [],
      publishedAt: publishedAt ? new Date(publishedAt) : null,
      status:      ['draft', 'published', 'archived'].includes(status) ? status : 'published',
    });

    await episode.save();
    res.status(201).json(formatEpisode(episode, true));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── SELLER: update episode ──
app.put('/api/my-episodes/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const episode = await Episode.findOne({ _id: req.params.id, userId: req.userId });
    if (!episode) return res.status(404).json({ message: 'Episode not found or not yours.' });

    const fields = ['episodeNo', 'title', 'description', 'thumbnail', 'tags',
                    'featuredTag', 'duration', 'guests', 'publishedAt', 'status',
                    'views', 'likes', 'adminNotes'];

    fields.forEach(f => {
      if (req.body[f] !== undefined) episode[f] = req.body[f];
    });

    if (req.body.youtubeUrl) {
      const newId = extractYouTubeId(req.body.youtubeUrl);
      if (!newId) return res.status(400).json({ message: 'Invalid YouTube URL.' });
      episode.youtubeUrl = req.body.youtubeUrl;
      episode.youtubeId  = newId;
    }

    if (req.body.tags && Array.isArray(req.body.tags)) {
      episode.tags = req.body.tags.map(t => t.trim().toLowerCase());
    }
    if (req.body.guests && Array.isArray(req.body.guests)) {
      episode.guests = req.body.guests.map(g => g.trim());
    }

    await episode.save();
    res.json(formatEpisode(episode, true));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── SELLER: delete episode ──
app.delete('/api/my-episodes/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const episode = await Episode.findOne({ _id: req.params.id, userId: req.userId });
    if (!episode) return res.status(404).json({ message: 'Episode not found or not yours.' });
    await Episode.deleteOne({ _id: req.params.id });
    res.json({ message: 'Episode deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── ADMIN: all episodes ──
app.get('/api/admin/episodes', verifyAdmin, async (req, res) => {
  try {
    const episodes = await Episode.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(episodes.map(async ep => {
      const seller = await User.findById(ep.userId);
      return {
        ...formatEpisode(ep, true),
        sellerName:  seller?.profile?.guestName || 'Unknown',
        sellerEmail: seller?.email              || '',
      };
    }));
    res.json({ total: enriched.length, episodes: enriched });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── ADMIN: create episode for any seller ──
app.post('/api/admin/episodes', verifyAdmin, async (req, res) => {
  try {
    const {
      userId, episodeNo, title, description, youtubeUrl, thumbnail,
      tags, featuredTag, duration, guests, publishedAt, status, adminNotes,
      views, likes
    } = req.body;

    if (!userId)     return res.status(400).json({ message: 'userId is required.' });
    if (!episodeNo)  return res.status(400).json({ message: 'episodeNo is required.' });
    if (!title)      return res.status(400).json({ message: 'title is required.' });
    if (!youtubeUrl) return res.status(400).json({ message: 'youtubeUrl is required.' });

    const youtubeId = extractYouTubeId(youtubeUrl);
    if (!youtubeId) return res.status(400).json({ message: 'Invalid YouTube URL.' });

    const episode = new Episode({
      userId,
      episodeNo:   parseInt(episodeNo),
      title:       title.trim(),
      description: description ? description.trim() : '',
      youtubeUrl:  youtubeUrl ? youtubeUrl.trim() : '',
      youtubeId,
      thumbnail:   thumbnail   || '',
      tags:        Array.isArray(tags)   ? tags.map(t => t.trim().toLowerCase()) : [],
      featuredTag: featuredTag ? featuredTag.trim() : '',
      duration:    duration    ? duration.trim()    : '',
      guests:      Array.isArray(guests) ? guests.map(g => g.trim()) : [],
      publishedAt: publishedAt ? new Date(publishedAt) : null,
      status:      ['draft', 'published', 'archived'].includes(status) ? status : 'published',
      adminNotes:  adminNotes  || '',
      views:       views       || 0,
      likes:       likes       || 0,
    });

    await episode.save();
    res.status(201).json(formatEpisode(episode, true));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── ADMIN: update any episode ──
app.put('/api/admin/episodes/:id', verifyAdmin, async (req, res) => {
  try {
    const episode = await Episode.findById(req.params.id);
    if (!episode) return res.status(404).json({ message: 'Episode not found.' });

    const fields = ['episodeNo', 'title', 'description', 'thumbnail', 'tags',
                    'featuredTag', 'duration', 'guests', 'publishedAt', 'status',
                    'views', 'likes', 'adminNotes', 'userId'];
    fields.forEach(f => { if (req.body[f] !== undefined) episode[f] = req.body[f]; });

    if (req.body.youtubeUrl) {
      const newId = extractYouTubeId(req.body.youtubeUrl);
      if (!newId) return res.status(400).json({ message: 'Invalid YouTube URL.' });
      episode.youtubeUrl = req.body.youtubeUrl;
      episode.youtubeId  = newId;
    }
    if (req.body.tags   && Array.isArray(req.body.tags))   episode.tags   = req.body.tags.map(t => t.trim().toLowerCase());
    if (req.body.guests && Array.isArray(req.body.guests)) episode.guests = req.body.guests.map(g => g.trim());

    await episode.save();
    res.json(formatEpisode(episode, true));
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── ADMIN: quick status change ──
app.patch('/api/admin/episodes/:id/status', verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['draft', 'published', 'archived'];
    if (!valid.includes(status)) return res.status(400).json({ message: 'Invalid status.' });
    const episode = await Episode.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!episode) return res.status(404).json({ message: 'Episode not found.' });
    res.json({ message: 'Episode status updated.', status: episode.status });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ── ADMIN: delete episode ──
app.delete('/api/admin/episodes/:id', verifyAdmin, async (req, res) => {
  try {
    await Episode.findByIdAndDelete(req.params.id);
    res.json({ message: 'Episode deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// SELLER → IRX PLAN PURCHASE (Razorpay)
// ==========================================

app.post('/api/create-order', verifyToken, verifySeller, async (req, res) => {
  try {
    const { selectedPlan } = req.body;
    const validPlans = ['remote', 'studio', 'amplification'];
    if (!validPlans.includes(selectedPlan)) return res.status(400).json({ message: 'Invalid plan.' });

    const amount = PLAN_PRICES[selectedPlan];
    const options = {
      amount,
      currency: 'INR',
      receipt:  `irx_plan_${req.userId.toString().substring(0, 10)}_${Date.now()}`,
      notes:    { userId: req.userId, plan: selectedPlan, orderType: 'plan_purchase' }
    };
    const razorpayOrder = await razorpay.orders.create(options);

    const order = new Order({
      userId:          req.userId,
      razorpayOrderId: razorpayOrder.id,
      plan:            selectedPlan,
      amount,
      status:          'created'
    });
    await order.save();

    res.json({
      orderId:  razorpayOrder.id,
      amount:   razorpayOrder.amount,
      currency: razorpayOrder.currency,
      keyId:    process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not create payment order.' });
  }
});

app.post('/api/verify-payment', verifyToken, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;

    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      await Order.findOneAndUpdate({ razorpayOrderId: razorpay_order_id }, { status: 'failed' });
      return res.status(400).json({ message: 'Payment verification failed. Contact support.' });
    }

    await Order.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id },
      { razorpayPaymentId: razorpay_payment_id, status: 'paid' }
    );
    await User.findByIdAndUpdate(req.userId, { plan });

    res.json({ message: `Plan upgraded to ${plan} successfully!`, plan });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Payment verification error.' });
  }
});

// ==========================================
// BUYER → SERVICE PURCHASE / LEAD
// ==========================================
app.post('/api/services/create-order', async (req, res) => {
  try {
    const { serviceId, buyerName, buyerEmail, buyerPhone, message } = req.body;

    if (!serviceId)   return res.status(400).json({ message: 'serviceId is required.' });
    if (!buyerName || !buyerName.trim())   return res.status(400).json({ message: 'Your name is required.' });
    if (!buyerEmail || !buyerEmail.trim()) return res.status(400).json({ message: 'Your email address is required.' });
    if (!buyerPhone || !buyerPhone.trim()) return res.status(400).json({ message: 'Your phone number is required.' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(buyerEmail.trim())) return res.status(400).json({ message: 'Please enter a valid email address.' });

    const phoneDigits = buyerPhone.replace(/\D/g, '');
    if (phoneDigits.length < 7) return res.status(400).json({ message: 'Please enter a valid phone number.' });

    const service = await Service.findById(serviceId);
    if (!service) return res.status(404).json({ message: 'Service not found.' });

    let buyerId = '';
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      try {
        const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        buyerId = decoded.id;
      } catch { /* unauthenticated visitor */ }
    }

    if (service.pricingType === 'lead' || service.price === 0) {
      const existingLead = await ServiceTransaction.findOne({
        serviceId,
        buyerEmail: buyerEmail.trim().toLowerCase(),
      });
      if (existingLead) {
        return res.status(409).json({
          message:          'You have already submitted an enquiry for this service.',
          redirectUrl:      service.redirectUrl || null,
          alreadySubmitted: true
        });
      }

      const txn = new ServiceTransaction({
        serviceId,
        sellerId:      service.userId,
        buyerId:       buyerId || '',
        buyerName:     buyerName.trim(),
        buyerEmail:    buyerEmail.trim().toLowerCase(),
        buyerPhone:    buyerPhone.trim(),
        message:       message ? message.trim() : '',
        amount:        0,
        platformFee:   0,
        type:          'lead',
        paymentStatus: 'not_required',
        status:        'pending',
        redirectUrl:   service.redirectUrl || ''
      });
      await txn.save();

      return res.status(201).json({
        message:          'Enquiry submitted successfully!',
        redirectUrl:      service.redirectUrl || null,
        transactionId:    txn._id,
        paymentRequired:  false,
        requiresAddress:  service.requiresAddress || false,
      });
    }

    if (service.pricingType === 'one_time') {
      let purchaseQuery = { serviceId, paymentStatus: 'paid', type: 'one_time' };
      if (buyerId) {
        purchaseQuery.buyerId = buyerId;
      } else {
        purchaseQuery.buyerEmail = buyerEmail.trim().toLowerCase();
      }
      const alreadyPurchased = await ServiceTransaction.findOne(purchaseQuery);
      if (alreadyPurchased) {
        return res.status(409).json({
          message:          'You have already purchased this service.',
          alreadyPurchased: true,
          redirectUrl:      alreadyPurchased.redirectUrl || service.redirectUrl || null,
          transactionId:    alreadyPurchased._id,
          requiresAddress:  service.requiresAddress || false,
        });
      }
    }

    const amount      = service.price;
    const platformFee = Math.round(amount * PLATFORM_FEE_PERCENT / 100);

    const options = {
      amount,
      currency: 'INR',
      receipt:  `irx_svc_${serviceId.toString().substring(0, 8)}_${Date.now()}`,
      notes: {
        serviceId,
        sellerId:  service.userId,
        buyerId:   buyerId || 'guest',
        buyerName: buyerName.trim(),
        orderType: 'service_purchase'
      }
    };
    const razorpayOrder = await razorpay.orders.create(options);

    const txn = new ServiceTransaction({
      serviceId,
      sellerId:        service.userId,
      buyerId,
      buyerName:       buyerName.trim(),
      buyerEmail:      buyerEmail.trim().toLowerCase(),
      buyerPhone:      buyerPhone.trim(),
      message:         message ? message.trim() : '',
      amount,
      platformFee,
      razorpayOrderId: razorpayOrder.id,
      type:            service.pricingType,
      paymentStatus:   'pending',
      status:          'pending',
      redirectUrl:     service.redirectUrl || ''
    });
    await txn.save();

    res.status(201).json({
      orderId:         razorpayOrder.id,
      amount:          razorpayOrder.amount,
      currency:        razorpayOrder.currency,
      keyId:           process.env.RAZORPAY_KEY_ID,
      transactionId:   txn._id,
      paymentRequired: true,
      requiresAddress: service.requiresAddress || false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Could not create service order.' });
  }
});

app.post('/api/services/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      await ServiceTransaction.findOneAndUpdate({ razorpayOrderId: razorpay_order_id }, { paymentStatus: 'failed' });
      return res.status(400).json({ message: 'Payment verification failed. Contact support.' });
    }

    const txn = await ServiceTransaction.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id },
      { razorpayPaymentId: razorpay_payment_id, paymentStatus: 'paid' },
      { new: true }
    );

    if (!txn) return res.status(404).json({ message: 'Transaction not found.' });

    // Check if associated service requires address
    const service = await Service.findById(txn.serviceId);
    const requiresAddress = service?.requiresAddress || false;

    res.json({
      message:         'Service purchase confirmed!',
      redirectUrl:     txn.redirectUrl || null,
      transactionId:   txn._id,
      requiresAddress,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Service payment verification error.' });
  }
});

// ── NEW: Save / update shipping address on a transaction ──
app.post('/api/services/save-address', optionalAuth, async (req, res) => {
  try {
    const { transactionId, buyerEmail, address } = req.body;

    if (!address || !address.line1 || !address.city || !address.state || !address.pin) {
      return res.status(400).json({ message: 'Address is incomplete. Please fill all required fields.' });
    }

    let txn = null;

    if (transactionId) {
      txn = await ServiceTransaction.findById(transactionId);
    }

    // Also allow lookup by buyerId + serviceId if transactionId not supplied
    if (!txn && req.userId && req.body.serviceId) {
      txn = await ServiceTransaction.findOne({
        serviceId:     req.body.serviceId,
        buyerId:       req.userId,
        paymentStatus: { $in: ['paid', 'not_required'] }
      });
    }

    // Fallback: lookup by email + serviceId
    if (!txn && buyerEmail && req.body.serviceId) {
      txn = await ServiceTransaction.findOne({
        serviceId:     req.body.serviceId,
        buyerEmail:    buyerEmail.toLowerCase().trim(),
        paymentStatus: { $in: ['paid', 'not_required'] }
      });
    }

    if (!txn) return res.status(404).json({ message: 'Transaction not found.' });

    txn.shippingAddress = {
      line1: address.line1.trim(),
      line2: (address.line2 || '').trim(),
      city:  address.city.trim(),
      state: address.state.trim(),
      pin:   address.pin.trim(),
    };
    await txn.save();

    res.json({ message: 'Shipping address saved successfully.', shippingAddress: txn.shippingAddress });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/my-purchases', verifyToken, async (req, res) => {
  try {
    const transactions = await ServiceTransaction
      .find({ buyerId: req.userId, paymentStatus: { $in: ['paid', 'not_required'] } })
      .sort({ createdAt: -1 });

    const enriched = await Promise.all(transactions.map(async txn => {
      const service = await Service.findById(txn.serviceId);
      const seller  = await User.findById(txn.sellerId);
      return {
        ...txn.toJSON(),
        serviceName:     service?.serviceName           || 'Deleted Service',
        sellerName:      seller?.profile?.guestName     || 'Unknown Seller',
        redirectUrl:     txn.redirectUrl || service?.redirectUrl || null,
        requiresAddress: service?.requiresAddress       || false,
      };
    }));

    const purchasedServiceIds = enriched.map(t => t.serviceId?.toString()).filter(Boolean);
    res.json({ totalPurchases: enriched.length, purchasedServiceIds, purchases: enriched });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// RAZORPAY WEBHOOK
// ==========================================
app.post('/api/webhook/razorpay', async (req, res) => {
  try {
    const receivedSignature = req.headers['x-razorpay-signature'];

    if (!RAZORPAY_WEBHOOK_SECRET) {
      console.warn('⚠️  RAZORPAY_WEBHOOK_SECRET not set — skipping signature verification (unsafe!)');
    } else {
      const expectedSignature = crypto
        .createHmac('sha256', RAZORPAY_WEBHOOK_SECRET)
        .update(req.rawBody)
        .digest('hex');
      if (expectedSignature !== receivedSignature) {
        console.warn('❌ Webhook signature mismatch');
        return res.status(400).json({ message: 'Invalid webhook signature.' });
      }
    }

    const event     = req.body;
    const eventType = event?.event;
    console.log(`📦 Razorpay Webhook received: ${eventType}`);

    if (eventType === 'payment.captured') {
      const payment           = event.payload?.payment?.entity;
      const razorpayOrderId   = payment?.order_id;
      const razorpayPaymentId = payment?.id;

      if (!razorpayOrderId) return res.status(200).json({ message: 'No order_id, skipping.' });

      const planOrder = await Order.findOne({ razorpayOrderId });
      if (planOrder) {
        if (planOrder.status === 'paid') return res.status(200).json({ message: 'Already processed.' });
        await Order.findByIdAndUpdate(planOrder._id, { razorpayPaymentId, status: 'paid' });
        await User.findByIdAndUpdate(planOrder.userId, { plan: planOrder.plan });
        const u = await User.findById(planOrder.userId);
        if (u && u.role === 'buyer') {
          await User.findByIdAndUpdate(planOrder.userId, { role: 'seller' });
        }
        console.log(`✅ Webhook [PLAN]: User ${planOrder.userId} → "${planOrder.plan}"`);
        return res.status(200).json({ message: 'Plan payment processed.' });
      }

      const serviceTxn = await ServiceTransaction.findOne({ razorpayOrderId });
      if (serviceTxn) {
        if (serviceTxn.paymentStatus === 'paid') return res.status(200).json({ message: 'Already processed.' });
        await ServiceTransaction.findByIdAndUpdate(serviceTxn._id, { razorpayPaymentId, paymentStatus: 'paid' });
        console.log(`✅ Webhook [SERVICE]: Transaction ${serviceTxn._id} marked paid.`);
        return res.status(200).json({ message: 'Service payment processed.' });
      }

      console.warn(`⚠️  Webhook: No matching order for ${razorpayOrderId}`);
      return res.status(200).json({ message: 'Order not found, acknowledged.' });
    }

    if (eventType === 'payment.failed') {
      const payment         = event.payload?.payment?.entity;
      const razorpayOrderId = payment?.order_id;
      if (razorpayOrderId) {
        const updatedPlan = await Order.findOneAndUpdate({ razorpayOrderId }, { status: 'failed' });
        if (!updatedPlan) {
          await ServiceTransaction.findOneAndUpdate({ razorpayOrderId }, { paymentStatus: 'failed' });
        }
        console.log(`❌ Webhook: Payment failed for order ${razorpayOrderId}`);
      }
    }

    res.status(200).json({ message: 'Webhook processed.' });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(200).json({ message: 'Webhook handler error, acknowledged.' });
  }
});

// ==========================================
// PUBLIC ROUTES
// ==========================================

app.get('/api/guests', async (req, res) => {
  try {
    const users = await User.find({
      role:                'seller',
      plan:                { $ne: 'none' },
      'profile.guestName': { $exists: true, $ne: '' }
    });
    const guests = await Promise.all(users.map(async u => {
      const episodeCount = await Episode.countDocuments({ userId: u._id.toString(), status: 'published' });
      return {
        id:            u._id,
        plan:          u.plan,
        episodeStatus: u.episodeStatus,
        category:      u.profile?.businessCategory,
        episodeCount,
        ...u.profile
      };
    }));
    res.json(guests);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/guests/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || !user.profile) return res.status(404).json({ message: 'Guest not found.' });
    const services = await Service.find({ userId: req.params.id });

    // Public profile shows episodes WITHOUT video URLs (gated behind purchase)
    const episodes = await Episode.find({
      userId: req.params.id,
      status: 'published'
    }).sort({ episodeNo: -1 });

    res.json({
      plan:          user.plan,
      episodeStatus: user.episodeStatus,
      profile:       user.profile,
      services,
      episodes:      episodes.map(ep => formatEpisode(ep, false))
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/services', async (req, res) => {
  try {
    const services = await Service.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(services.map(async s => {
      const user = await User.findById(s.userId);
      return { ...s.toJSON(), creatorName: user?.profile?.guestName || 'Member' };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// SELLER — SERVICE MANAGEMENT
// ==========================================

app.get('/api/my-services', verifyToken, verifySeller, async (req, res) => {
  try {
    const services = await Service.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(services);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/services', verifyToken, verifySeller, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.plan === 'none') return res.status(403).json({ message: 'Purchase a package first.' });

    const pricingType = req.body.pricingType || 'lead';
    let price = parseInt(req.body.price) || 0;
    if (pricingType === 'lead') price = 0;

    const service = new Service({
      userId:             req.userId,
      serviceName:        req.body.serviceName,
      serviceDescription: req.body.serviceDescription,
      redirectUrl:        req.body.redirectUrl,
      thumbnailUrl:       req.body.thumbnailUrl,
      category:           req.body.category || 'General',
      pricingType,
      price,
      requiresAddress:    req.body.requiresAddress === true || req.body.requiresAddress === 'true',
    });
    await service.save();
    res.json(service);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/services/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const service = await Service.findOne({ _id: req.params.id, userId: req.userId });
    if (!service) return res.status(404).json({ message: 'Service not found or not yours.' });

    const fields = ['serviceName', 'serviceDescription', 'redirectUrl', 'thumbnailUrl', 'category', 'pricingType', 'price', 'requiresAddress'];
    fields.forEach(f => { if (req.body[f] !== undefined) service[f] = req.body[f]; });
    if (service.pricingType === 'lead') service.price = 0;

    await service.save();
    res.json(service);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/services/:id', verifyToken, verifySeller, async (req, res) => {
  try {
    const service = await Service.findOne({ _id: req.params.id, userId: req.userId });
    if (!service) return res.status(404).json({ message: 'Service not found or not yours.' });
    await Service.deleteOne({ _id: req.params.id });
    res.json({ message: 'Service deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// SELLER — ANALYTICS / LEADS
// ==========================================

app.get('/api/my-sales', verifyToken, verifySeller, async (req, res) => {
  try {
    const transactions = await ServiceTransaction
      .find({ sellerId: req.userId })
      .sort({ createdAt: -1 });

    const enriched = await Promise.all(transactions.map(async txn => {
      const service = await Service.findById(txn.serviceId);
      return {
        ...txn.toJSON(),
        serviceName:     service?.serviceName     || 'Deleted Service',
        requiresAddress: service?.requiresAddress || false,
      };
    }));

    // ── Deduplication ──
    function paymentPriority(txn) {
      switch (txn.paymentStatus) {
        case 'paid':          return 0;
        case 'pending':       return 1;
        case 'not_required':  return 2;
        case 'failed':        return 3;
        default:              return 4;
      }
    }

    const deduped = new Map();
    for (const txn of enriched) {
      const key = `${(txn.buyerEmail || '').toLowerCase().trim()}__${txn.serviceId}`;
      const existing = deduped.get(key);
      if (!existing) { deduped.set(key, txn); continue; }
      const newRank = paymentPriority(txn);
      const exRank  = paymentPriority(existing);
      if (newRank < exRank) deduped.set(key, txn);
    }

    const dedupedList = Array.from(deduped.values());
    dedupedList.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const totalLeads   = dedupedList.length;
    const converted    = dedupedList.filter(t => t.status === 'converted').length;
    const paidSales    = dedupedList.filter(t => t.paymentStatus === 'paid');
    const totalRevenue = paidSales.reduce((sum, t) => sum + (t.amount  || 0), 0);
    const netRevenue   = paidSales.reduce((sum, t) => sum + ((t.amount || 0) - (t.platformFee || 0)), 0);

    res.json({
      summary:      { totalLeads, converted, totalRevenue, netRevenue },
      transactions: dedupedList
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/my-sales/:txnId', verifyToken, verifySeller, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['pending', 'contacted', 'converted', 'closed'];
    if (!validStatuses.includes(status)) return res.status(400).json({ message: 'Invalid status.' });
    const txn = await ServiceTransaction.findOne({ _id: req.params.txnId, sellerId: req.userId });
    if (!txn) return res.status(404).json({ message: 'Transaction not found or not yours.' });
    txn.status = status;
    await txn.save();
    res.json({ message: 'Lead status updated.', status: txn.status });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// ADMIN ROUTES
// ==========================================

app.post('/api/admin/login', (req, res) => {
  const { secret } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ message: 'Wrong admin secret.' });
  res.json({ token: ADMIN_SECRET, message: 'Admin access granted.' });
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(users.map(async u => {
      const serviceCount = await Service.countDocuments({ userId: u._id });
      const leadCount    = await ServiceTransaction.countDocuments({ sellerId: u._id.toString() });
      const episodeCount = await Episode.countDocuments({ userId: u._id.toString() });
      return {
        id:               u._id,
        email:            u.email,
        role:             u.role,
        plan:             u.plan,
        episodeStatus:    u.episodeStatus,
        guestName:        u.profile?.guestName        || '',
        guestImage:       u.profile?.guestImage       || '',
        businessCategory: u.profile?.businessCategory || '',
        location:         u.profile?.location         || '',
        phone:            u.profile?.phone            || '',
        serviceCount,
        leadCount,
        episodeCount,
        createdAt: u.createdAt
      };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/admin/users/:id/role', verifyAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const validRoles = ['admin', 'seller', 'buyer'];
    if (!validRoles.includes(role)) return res.status(400).json({ message: 'Invalid role.' });
    const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'Role updated.', role: user.role });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/admin/users/:id/plan', verifyAdmin, async (req, res) => {
  try {
    const { plan } = req.body;
    const validPlans = ['none', 'remote', 'studio', 'amplification'];
    if (!validPlans.includes(plan)) return res.status(400).json({ message: 'Invalid plan.' });
    const user = await User.findByIdAndUpdate(req.params.id, { plan }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'Plan updated.', plan: user.plan });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/admin/users/:id/episode', verifyAdmin, async (req, res) => {
  try {
    const { episodeStatus } = req.body;
    const validStatuses = ['pending', 'confirmed', 'pre_production', 'recorded', 'post_production', 'live'];
    if (!validStatuses.includes(episodeStatus)) return res.status(400).json({ message: 'Invalid status.' });
    const user = await User.findByIdAndUpdate(req.params.id, { episodeStatus }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'Episode status updated.', episodeStatus: user.episodeStatus });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Service.deleteMany({ userId: req.params.id });
    await Episode.deleteMany({ userId: req.params.id });
    res.json({ message: 'User, their services and episodes deleted. Transaction history preserved.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/services', verifyAdmin, async (req, res) => {
  try {
    const services = await Service.find().sort({ createdAt: -1 });
    const enriched = await Promise.all(services.map(async s => {
      const user      = await User.findById(s.userId);
      const leadCount = await ServiceTransaction.countDocuments({ serviceId: s._id });
      return {
        ...s.toJSON(),
        creatorName:  user?.profile?.guestName || 'Unknown',
        creatorEmail: user?.email              || '',
        leadCount
      };
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/services/:id', verifyAdmin, async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.params.id);
    res.json({ message: 'Service deleted. Transaction history preserved.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/service-sales', verifyAdmin, async (req, res) => {
  try {
    const transactions = await ServiceTransaction.find().sort({ createdAt: -1 });

    const enriched = await Promise.all(transactions.map(async txn => {
      const service = await Service.findById(txn.serviceId);
      const seller  = await User.findById(txn.sellerId);
      const buyer   = await User.findById(txn.buyerId);
      return {
        ...txn.toJSON(),
        serviceName:     service?.serviceName       || 'Deleted Service',
        requiresAddress: service?.requiresAddress   || false,
        sellerName:      seller?.profile?.guestName || 'Unknown Seller',
        sellerEmail:     seller?.email              || '',
        buyerAccount:    buyer?.email               || txn.buyerEmail
      };
    }));

    const totalTransactions = enriched.length;
    const paidTxns          = enriched.filter(t => t.paymentStatus === 'paid');
    const totalRevenue      = paidTxns.reduce((sum, t) => sum + (t.amount || 0), 0);
    const totalPlatformFee  = paidTxns.reduce((sum, t) => sum + (t.platformFee || 0), 0);

    const byType = {
      lead:         enriched.filter(t => t.type === 'lead').length,
      one_time:     enriched.filter(t => t.type === 'one_time').length,
      subscription: enriched.filter(t => t.type === 'subscription').length,
    };
    const byPaymentStatus = {
      not_required: enriched.filter(t => t.paymentStatus === 'not_required').length,
      pending:      enriched.filter(t => t.paymentStatus === 'pending').length,
      paid:         enriched.filter(t => t.paymentStatus === 'paid').length,
      failed:       enriched.filter(t => t.paymentStatus === 'failed').length,
    };
    const byCRMStatus = {
      pending:   enriched.filter(t => t.status === 'pending').length,
      contacted: enriched.filter(t => t.status === 'contacted').length,
      converted: enriched.filter(t => t.status === 'converted').length,
      closed:    enriched.filter(t => t.status === 'closed').length,
    };

    res.json({
      summary: { totalTransactions, totalRevenue, totalPlatformFee, byType, byPaymentStatus, byCRMStatus },
      transactions: enriched
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/admin/service-sales/:txnId', verifyAdmin, async (req, res) => {
  try {
    const { status, paymentStatus, amount } = req.body;
    const validStatuses        = ['pending', 'contacted', 'converted', 'closed'];
    const validPaymentStatuses = ['pending', 'paid', 'failed', 'not_required'];
    const update = {};
    if (status)               { if (!validStatuses.includes(status))               return res.status(400).json({ message: 'Invalid status.' });        update.status        = status; }
    if (paymentStatus)        { if (!validPaymentStatuses.includes(paymentStatus)) return res.status(400).json({ message: 'Invalid paymentStatus.' }); update.paymentStatus = paymentStatus; }
    if (amount !== undefined) { update.amount = amount; }
    const txn = await ServiceTransaction.findByIdAndUpdate(req.params.txnId, update, { new: true });
    if (!txn) return res.status(404).json({ message: 'Transaction not found.' });
    res.json({ message: 'Transaction updated.', transaction: txn });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const totalUsers    = await User.countDocuments();
    const totalSellers  = await User.countDocuments({ role: 'seller' });
    const totalBuyers   = await User.countDocuments({ role: 'buyer' });
    const paidSellers   = await User.countDocuments({ role: 'seller', plan: { $ne: 'none' } });
    const totalServices = await Service.countDocuments();
    const totalLeads    = await ServiceTransaction.countDocuments();
    const totalEpisodes = await Episode.countDocuments({ status: 'published' });

    const planBreakdown = {
      remote:        await User.countDocuments({ plan: 'remote' }),
      studio:        await User.countDocuments({ plan: 'studio' }),
      amplification: await User.countDocuments({ plan: 'amplification' }),
    };
    const planRevenue =
      planBreakdown.remote * 5000 +
      planBreakdown.studio * 12000 +
      planBreakdown.amplification * 25000;

    const paidServiceTxns = await ServiceTransaction.find({ paymentStatus: 'paid' });
    const serviceRevenue  = paidServiceTxns.reduce((sum, t) => sum + (t.amount || 0), 0);
    const platformFees    = paidServiceTxns.reduce((sum, t) => sum + (t.platformFee || 0), 0);

    const recentUsers    = await User.find().sort({ createdAt: -1 }).limit(5);
    const recentLeads    = await ServiceTransaction.find().sort({ createdAt: -1 }).limit(5);
    const recentEpisodes = await Episode.find({ status: 'published' }).sort({ createdAt: -1 }).limit(5);

    res.json({
      totalUsers, totalSellers, totalBuyers, paidSellers,
      totalServices, totalLeads, totalEpisodes,
      planBreakdown, planRevenue,
      serviceRevenue, platformFees,
      recentUsers: recentUsers.map(u => ({
        id: u._id, email: u.email, role: u.role, plan: u.plan,
        guestName: u.profile?.guestName || '', createdAt: u.createdAt
      })),
      recentLeads,
      recentEpisodes: recentEpisodes.map(ep => formatEpisode(ep, true))
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).limit(50);
    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==========================================
// HEALTH CHECK
// ==========================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==========================================
// START
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 IRX Backend running on port ${PORT}`));
