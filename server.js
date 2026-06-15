const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ============================================================
// DATABASE CONNECTION
// ============================================================
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/plotline';

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log('✓ MongoDB connected successfully');
    console.log(`  Database: ${mongoUri}`);
  })
  .catch(err => {
    console.error('✗ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ============================================================
// MODELS (inline for simplicity in starter)
// ============================================================

// User Model
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['buyer', 'seller', 'admin'], required: true },
  profileImage: String,
  bio: String,
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  lastActive: Date,
  createdAt: { type: Date, default: Date.now }
});

const bcrypt = require('bcryptjs');
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', UserSchema);

// Listing Model
const ListingSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  title: { type: String, required: true, index: true },
  type: { type: String, enum: ['Plot', 'Land', 'Agricultural Land', 'Residential Building', 'Apartment', 'Commercial Space'], required: true },
  price: { type: Number, required: true, index: true },
  location: { type: String, required: true, index: true },
  area: { type: Number, required: true },
  areaUnit: { type: String, enum: ['sq.ft', 'sq.yd', 'cents', 'acres'], required: true },
  facing: String,
  description: String,
  images: [String],
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sellerName: String,
  sellerPhone: String,
  sellerEmail: String,
  status: { type: String, enum: ['Available', 'Sold'], default: 'Available', index: true },
  views: { type: Number, default: 0 },
  postedDate: { type: Date, default: Date.now, index: true },
  updatedDate: { type: Date, default: Date.now }
});

const Listing = mongoose.model('Listing', ListingSchema);

// Favorite Model
const FavoriteSchema = new mongoose.Schema({
  buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  listingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Listing', required: true, index: true },
  savedDate: { type: Date, default: Date.now }
});

FavoriteSchema.index({ buyerId: 1, listingId: 1 }, { unique: true });
const Favorite = mongoose.model('Favorite', FavoriteSchema);

// Activity Model
const ActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  userName: String,
  userRole: { type: String, enum: ['buyer', 'seller', 'admin'] },
  action: {
    type: String,
    enum: ['login', 'logout', 'view_listing', 'save_favorite', 'unsave_favorite', 'post_listing', 'edit_listing', 'delete_listing', 'mark_sold', 'contact_seller'],
    required: true,
    index: true
  },
  listingId: mongoose.Schema.Types.ObjectId,
  listingTitle: String,
  description: String,
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now, index: true }
});

const Activity = mongoose.model('Activity', ActivitySchema);

// ============================================================
// MIDDLEWARE - JWT Auth
// ============================================================
const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    req.userId = decoded.userId;
    req.userRole = decoded.role;

    // Fire-and-forget heartbeat so admins can see who's currently active
    User.findByIdAndUpdate(decoded.userId, { lastActive: new Date() }).exec().catch(() => {});

    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Restricts access to admin accounts only. Must be used after `auth`.
const adminAuth = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============================================================
// AUTH ROUTES
// ============================================================

const generateToken = (userId, role) => {
  return jwt.sign(
    { userId, role },
    process.env.JWT_SECRET || 'your_secret_key',
    { expiresIn: '7d' }
  );
};

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;

    // Validation
    if (!name || !email || !phone || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create new user
    user = new User({ name, email, phone, password, role });
    await user.save();

    // Log activity
    await Activity.create({
      userId: user._id,
      userName: user.name,
      userRole: user.role,
      action: 'login',
      description: 'User registered and logged in',
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    const token = generateToken(user._id, user.role);
    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    if (user.isActive === false) {
      return res.status(403).json({ error: 'Your account has been suspended. Please contact support.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    user.lastActive = new Date();
    await user.save();

    // Log activity
    await Activity.create({
      userId: user._id,
      userName: user.name,
      userRole: user.role,
      action: 'login',
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    const token = generateToken(user._id, user.role);
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    await Activity.create({
      userId: req.userId,
      action: 'logout',
      ipAddress: req.ip
    });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// LISTING ROUTES
// ============================================================

// Get all listings (public)
app.get('/api/listings', async (req, res) => {
  try {
    const { type, minPrice, maxPrice, location, sort } = req.query;
    let query = { status: 'Available' };

    if (type) query.type = type;
    if (location) query.location = new RegExp(location, 'i');
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = parseInt(minPrice);
      if (maxPrice) query.price.$lte = parseInt(maxPrice);
    }

    let sortObj = { postedDate: -1 };
    if (sort === 'price-low') sortObj = { price: 1 };
    if (sort === 'price-high') sortObj = { price: -1 };

    const listings = await Listing.find(query).sort(sortObj).limit(100);
    res.json(listings);
  } catch (err) {
    console.error('Get listings error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get listing by ID (track view)
app.get('/api/listings/:id', auth, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    // Increment view count
    listing.views = (listing.views || 0) + 1;
    await listing.save();

    // Log activity
    await Activity.create({
      userId: req.userId,
      action: 'view_listing',
      listingId: listing._id,
      listingTitle: listing.title,
      ipAddress: req.ip
    });

    res.json(listing);
  } catch (err) {
    console.error('Get listing error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Create listing (seller only)
app.post('/api/listings', auth, async (req, res) => {
  if (req.userRole !== 'seller') {
    return res.status(403).json({ error: 'Only sellers can create listings' });
  }

  try {
    const seller = await User.findById(req.userId);
    const count = await Listing.countDocuments();
    const nextId = 'PLT-' + (1001 + count);

    const listing = new Listing({
      ...req.body,
      id: nextId,
      sellerId: req.userId,
      sellerName: seller.name,
      sellerEmail: seller.email,
      sellerPhone: seller.phone
    });

    await listing.save();

    // Log activity
    await Activity.create({
      userId: req.userId,
      userName: seller.name,
      userRole: 'seller',
      action: 'post_listing',
      listingId: listing._id,
      listingTitle: listing.title,
      description: `Posted ${listing.type} in ${listing.location}`,
      ipAddress: req.ip
    });

    res.status(201).json(listing);
  } catch (err) {
    console.error('Create listing error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Update listing (seller only)
app.put('/api/listings/:id', auth, async (req, res) => {
  if (req.userRole !== 'seller') {
    return res.status(403).json({ error: 'Only sellers can update listings' });
  }

  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    if (listing.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Can only edit your own listings' });
    }

    Object.assign(listing, req.body);
    listing.updatedDate = new Date();
    await listing.save();

    // Log activity
    const seller = await User.findById(req.userId);
    await Activity.create({
      userId: req.userId,
      userName: seller.name,
      userRole: 'seller',
      action: 'edit_listing',
      listingId: listing._id,
      listingTitle: listing.title,
      ipAddress: req.ip
    });

    res.json(listing);
  } catch (err) {
    console.error('Update listing error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete listing (seller only)
app.delete('/api/listings/:id', auth, async (req, res) => {
  if (req.userRole !== 'seller') {
    return res.status(403).json({ error: 'Only sellers can delete listings' });
  }

  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    if (listing.sellerId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Can only delete your own listings' });
    }

    const seller = await User.findById(req.userId);
    await Activity.create({
      userId: req.userId,
      userName: seller.name,
      userRole: 'seller',
      action: 'delete_listing',
      listingId: listing._id,
      listingTitle: listing.title,
      ipAddress: req.ip
    });

    await Listing.findByIdAndDelete(req.params.id);
    res.json({ message: 'Listing deleted' });
  } catch (err) {
    console.error('Delete listing error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get my listings (seller only)
app.get('/api/listings/my/listings', auth, async (req, res) => {
  try {
    const listings = await Listing.find({ sellerId: req.userId }).sort({ postedDate: -1 });
    res.json(listings);
  } catch (err) {
    console.error('Get my listings error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// FAVORITES ROUTES
// ============================================================

// Get my favorites
app.get('/api/favorites', auth, async (req, res) => {
  try {
    const favorites = await Favorite.find({ buyerId: req.userId })
      .populate('listingId')
      .sort({ savedDate: -1 });
    res.json(favorites);
  } catch (err) {
    console.error('Get favorites error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Add to favorites
app.post('/api/favorites/:listingId', auth, async (req, res) => {
  try {
    let favorite = await Favorite.findOne({
      buyerId: req.userId,
      listingId: req.params.listingId
    });

    if (favorite) {
      return res.status(400).json({ error: 'Already favorited' });
    }

    favorite = new Favorite({
      buyerId: req.userId,
      listingId: req.params.listingId
    });

    await favorite.save();

    // Log activity
    await Activity.create({
      userId: req.userId,
      action: 'save_favorite',
      listingId: req.params.listingId,
      ipAddress: req.ip
    });

    res.status(201).json(favorite);
  } catch (err) {
    console.error('Add favorite error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Remove from favorites
app.delete('/api/favorites/:listingId', auth, async (req, res) => {
  try {
    await Favorite.findOneAndDelete({
      buyerId: req.userId,
      listingId: req.params.listingId
    });

    // Log activity
    await Activity.create({
      userId: req.userId,
      action: 'unsave_favorite',
      listingId: req.params.listingId,
      ipAddress: req.ip
    });

    res.json({ message: 'Removed from favorites' });
  } catch (err) {
    console.error('Remove favorite error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ACTIVITIES ROUTES
// ============================================================

// Get my activities
app.get('/api/activities/my', auth, async (req, res) => {
  try {
    const activities = await Activity.find({ userId: req.userId })
      .sort({ timestamp: -1 })
      .limit(100);
    res.json(activities);
  } catch (err) {
    console.error('Get my activities error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get all activities (for seller dashboard)
app.get('/api/activities/seller-stats', auth, async (req, res) => {
  if (req.userRole !== 'seller') {
    return res.status(403).json({ error: 'Only sellers can access this' });
  }

  try {
    const listings = await Listing.find({ sellerId: req.userId });
    const listingIds = listings.map(l => l._id);

    const stats = {
      totalListings: listings.length,
      totalViews: listings.reduce((sum, l) => sum + (l.views || 0), 0),
      recentViews: await Activity.countDocuments({
        action: 'view_listing',
        listingId: { $in: listingIds },
        timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      }),
      recentActivities: await Activity.find({
        action: 'view_listing',
        listingId: { $in: listingIds }
      }).sort({ timestamp: -1 }).limit(20)
    };

    res.json(stats);
  } catch (err) {
    console.error('Get seller stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
// All routes below require a valid token AND an 'admin' role.

const ONLINE_WINDOW_MS = 5 * 60 * 1000; // users active in the last 5 minutes are "online"

// ---- Overview stats ----
app.get('/api/admin/stats', auth, adminAuth, async (req, res) => {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const onlineSince = new Date(now.getTime() - ONLINE_WINDOW_MS);

    const [
      totalUsers, totalBuyers, totalSellers, totalAdmins,
      blockedUsers, onlineNow,
      newUsersToday, newUsersThisWeek,
      totalListings, activeListings, soldListings, newListingsToday,
      totalFavorites,
      listingViewsAgg,
      recentSignups, recentActivities
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'buyer' }),
      User.countDocuments({ role: 'seller' }),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({ isActive: false }),
      User.countDocuments({ lastActive: { $gte: onlineSince } }),
      User.countDocuments({ createdAt: { $gte: startOfToday } }),
      User.countDocuments({ createdAt: { $gte: startOfWeek } }),
      Listing.countDocuments(),
      Listing.countDocuments({ status: 'Available' }),
      Listing.countDocuments({ status: 'Sold' }),
      Listing.countDocuments({ postedDate: { $gte: startOfToday } }),
      Favorite.countDocuments(),
      Listing.aggregate([{ $group: { _id: null, total: { $sum: '$views' } } }]),
      User.find().sort({ createdAt: -1 }).limit(5).select('name email role createdAt'),
      Activity.find().sort({ timestamp: -1 }).limit(10)
    ]);

    res.json({
      users: {
        total: totalUsers,
        buyers: totalBuyers,
        sellers: totalSellers,
        admins: totalAdmins,
        blocked: blockedUsers,
        onlineNow,
        newToday: newUsersToday,
        newThisWeek: newUsersThisWeek
      },
      listings: {
        total: totalListings,
        active: activeListings,
        sold: soldListings,
        newToday: newListingsToday,
        totalViews: listingViewsAgg[0]?.total || 0
      },
      favorites: { total: totalFavorites },
      recentSignups,
      recentActivities
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---- Users management ----

// List users (search, filter by role/status, paginate)
app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
  try {
    const { search, role, status, page = 1, limit = 20 } = req.query;
    const query = {};

    if (role) query.role = role;
    if (status === 'blocked') query.isActive = false;
    if (status === 'active') query.isActive = { $ne: false };
    if (search) {
      const re = new RegExp(search, 'i');
      query.$or = [{ name: re }, { email: re }, { phone: re }];
    }

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum),
      User.countDocuments(query)
    ]);

    // Attach listing counts for sellers and favorite counts for buyers
    const userIds = users.map(u => u._id);
    const [listingCounts, favoriteCounts] = await Promise.all([
      Listing.aggregate([
        { $match: { sellerId: { $in: userIds } } },
        { $group: { _id: '$sellerId', count: { $sum: 1 } } }
      ]),
      Favorite.aggregate([
        { $match: { buyerId: { $in: userIds } } },
        { $group: { _id: '$buyerId', count: { $sum: 1 } } }
      ])
    ]);

    const listingCountMap = {};
    listingCounts.forEach(l => { listingCountMap[l._id.toString()] = l.count; });
    const favoriteCountMap = {};
    favoriteCounts.forEach(f => { favoriteCountMap[f._id.toString()] = f.count; });

    const onlineSince = new Date(Date.now() - ONLINE_WINDOW_MS);

    const enriched = users.map(u => ({
      ...u.toObject(),
      listingCount: listingCountMap[u._id.toString()] || 0,
      favoriteCount: favoriteCountMap[u._id.toString()] || 0,
      isOnline: !!(u.lastActive && u.lastActive >= onlineSince)
    }));

    res.json({
      users: enriched,
      total,
      page: pageNum,
      pages: Math.ceil(total / limitNum) || 1
    });
  } catch (err) {
    console.error('Admin list users error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Block / unblock a user
app.put('/api/admin/users/:id/status', auth, adminAuth, async (req, res) => {
  try {
    const { isActive } = req.body;

    if (req.params.id === req.userId.toString() && isActive === false) {
      return res.status(400).json({ error: 'You cannot block your own account' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.isActive = !!isActive;
    await user.save();

    res.json({ message: `User ${user.isActive ? 'unblocked' : 'blocked'}`, user: { _id: user._id, isActive: user.isActive } });
  } catch (err) {
    console.error('Admin update user status error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Change a user's role (buyer / seller / admin)
app.put('/api/admin/users/:id/role', auth, adminAuth, async (req, res) => {
  try {
    const { role } = req.body;

    if (!['buyer', 'seller', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    if (req.params.id === req.userId.toString() && role !== 'admin') {
      return res.status(400).json({ error: 'You cannot remove your own admin access' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.role = role;
    await user.save();

    res.json({ message: 'Role updated', user: { _id: user._id, role: user.role } });
  } catch (err) {
    console.error('Admin update user role error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a user (and cascade their listings, favorites, activities)
app.delete('/api/admin/users/:id', auth, adminAuth, async (req, res) => {
  try {
    if (req.params.id === req.userId.toString()) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const listings = await Listing.find({ sellerId: user._id }).select('_id');
    const listingIds = listings.map(l => l._id);

    await Promise.all([
      Listing.deleteMany({ sellerId: user._id }),
      Favorite.deleteMany({ $or: [{ buyerId: user._id }, { listingId: { $in: listingIds } }] }),
      Activity.deleteMany({ $or: [{ userId: user._id }, { listingId: { $in: listingIds } }] }),
      User.findByIdAndDelete(user._id)
    ]);

    res.json({ message: 'User and related data deleted' });
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---- Listings management ----

// List all listings (search, filter, paginate)
app.get('/api/admin/listings', auth, adminAuth, async (req, res) => {
  try {
    const { search, status, type, page = 1, limit = 20 } = req.query;
    const query = {};

    if (status) query.status = status;
    if (type) query.type = type;
    if (search) {
      const re = new RegExp(search, 'i');
      query.$or = [{ title: re }, { location: re }, { id: re }, { sellerName: re }, { sellerEmail: re }];
    }

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    const [listings, total] = await Promise.all([
      Listing.find(query)
        .sort({ postedDate: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum),
      Listing.countDocuments(query)
    ]);

    res.json({
      listings,
      total,
      page: pageNum,
      pages: Math.ceil(total / limitNum) || 1
    });
  } catch (err) {
    console.error('Admin list listings error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Toggle a listing's status (Available / Sold)
app.put('/api/admin/listings/:id/status', auth, adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['Available', 'Sold'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const listing = await Listing.findById(req.params.id);
    if (!listing) return res.status(404).json({ error: 'Listing not found' });

    listing.status = status;
    listing.updatedDate = new Date();
    await listing.save();

    res.json(listing);
  } catch (err) {
    console.error('Admin update listing status error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete any listing (and its favorites)
app.delete('/api/admin/listings/:id', auth, adminAuth, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) return res.status(404).json({ error: 'Listing not found' });

    await Promise.all([
      Favorite.deleteMany({ listingId: listing._id }),
      Listing.findByIdAndDelete(listing._id)
    ]);

    res.json({ message: 'Listing deleted' });
  } catch (err) {
    console.error('Admin delete listing error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---- Activity log ----

app.get('/api/admin/activities', auth, adminAuth, async (req, res) => {
  try {
    const { action, role, page = 1, limit = 30 } = req.query;
    const query = {};

    if (action) query.action = action;
    if (role) query.userRole = role;

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit)));

    const [activities, total] = await Promise.all([
      Activity.find(query)
        .sort({ timestamp: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum),
      Activity.countDocuments(query)
    ]);

    res.json({
      activities,
      total,
      page: pageNum,
      pages: Math.ceil(total / limitNum) || 1
    });
  } catch (err) {
    console.error('Admin list activities error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVE FRONTEND (static files)
// ============================================================

app.use(express.static(path.join(__dirname, '../frontend')));

// Root /api health check
app.get('/api', (req, res) => {
  res.json({ status: 'PlotLine API running', version: '1.0.0' });
});

// Any other route → serve index.html (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ============================================================
// ERROR HANDLING
// ============================================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// START SERVER
// ============================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 PlotLine Server Running`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   API: http://localhost:${PORT}/api`);
  console.log(`\n✓ Ready to accept connections\n`);
});

module.exports = app;
