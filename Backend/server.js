// server.js - Backend for the Text Utility Application
// Version: 5.0 (Enhanced with Security Measures, Auth, Metrics, and Caching)

/**
 * @file server.js
 * @description This Node.js Express server provides text transformation services,
 * manages user authentication (signup/login), stores operation logs, integrates
 * Prometheus for application metrics, and utilizes Redis for caching frequently
 * accessed data like operation history. This version focuses on robust security.
 *
 * @overview
 * This backend implements a robust architecture suitable for a modern web application.
 * It features user registration and login using JWTs for secure authentication,
 * password hashing with bcrypt, MongoDB for persistent data storage,
 * Redis for high-performance caching of dynamic data, and Prometheus for real-time
 * application monitoring. Crucially, it incorporates security best practices
 * to protect against common web vulnerabilities.
 *
 * @technologies
 * - **Node.js**: Server-side JavaScript runtime.
 * - **Express**: Web framework for building RESTful APIs.
 * - **Mongoose**: ODM for MongoDB, simplifying database interactions.
 * - **CORS**: Middleware for handling Cross-Origin Resource Sharing.
 * - **dotenv**: Manages environment variables.
 * - **validator**: Utility for string validation.
 * - **bcryptjs**: Library for hashing passwords securely.
 * - **jsonwebtoken (JWT)**: For creating and verifying secure tokens for authentication.
 * - **prom-client**: Node.js client for Prometheus metrics.
 * - **redis**: Node.js client for Redis, used for caching.
 * - **helmet**: Helps secure Express apps by setting various HTTP headers.
 * - **express-rate-limit**: Basic rate limiting middleware to protect against brute-force attacks.
 *
 * @features
 * - **User Authentication**: Secure signup and login with hashed passwords and JWTs.
 * - **Text Transformations**: API endpoints for standard text manipulations (protected).
 * - **Operation Logging**: Stores detailed records of each operation to MongoDB (protected).
 * - **History Retrieval**: Provides an endpoint to fetch recent operation logs, optimized with Redis caching.
 * - **IP Address Logging**: Records client IP for analytics/security.
 * - **Prometheus Metrics**: Exposes custom application metrics at `/metrics`.
 * - **Redis Caching**: Caches operation history to reduce database load and improve response times.
 * - **Authentication Middleware**: Protects routes requiring user login.
 * - **Comprehensive Error Handling**: Robust error handling across the application.
 * - **Environment Configuration**: Utilizes `.env` for all sensitive configurations.
 * - **Security Headers**: Utilizes Helmet.js to set various HTTP security headers.
 * - **Rate Limiting**: Implements rate limiting for API endpoints to prevent abuse.
 */

// --- Module Imports ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const client = require('prom-client');
const redis = require('redis');
const helmet = require('helmet'); // Import helmet for security headers
const rateLimit = require('express-rate-limit'); // Import express-rate-limit

// Load environment variables from .env file
dotenv.config();

// --- Express App Initialization ---
const app = express();
const PORT = process.env.PORT || 5000;

// --- Prometheus Metrics Setup ---
const register = new client.Registry();
register.setDefaultLabels({
  app: 'textmate-backend'
});
client.collectDefaultMetrics({ register });

// Custom Metrics for HTTP Requests
const httpRequestCounter = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

const httpRequestDurationHistogram = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.05, 0.1, 0.2, 0.5, 1, 2, 5],
  registers: [register],
});

// Custom Metrics for Authentication
const signupAttemptsCounter = new client.Counter({
  name: 'auth_signup_attempts_total',
  help: 'Total number of sign-up attempts',
  labelNames: ['status'],
  registers: [register],
});

const loginAttemptsCounter = new client.Counter({
  name: 'auth_login_attempts_total',
  help: 'Total number of login attempts',
  labelNames: ['status'],
  registers: [register],
});


// --- Middleware Setup ---

// 1. Helmet for security headers
app.use(helmet());

// 2. CORS Configuration (More restrictive than default `cors()`)
// IMPORTANT: Add your frontend's actual development URL here, e.g., 'http://localhost:5173'
const allowedOrigins = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173']; // Added http://localhost:5173
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST'], // Specify allowed methods
  credentials: true, // Allow sending cookies, authorization headers etc.
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
}));

app.use(express.json()); // Parse JSON request bodies

// 3. Rate Limiting for all API requests (general protection)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per 15 minutes
  message: 'Too many requests from this IP, please try again after 15 minutes.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
// Apply to all routes starting with /api/
app.use('/api/', apiLimiter);

// 4. Stricter Rate Limiting for Auth Endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login/signup requests per 15 minutes
  message: 'Too many authentication attempts from this IP, please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);


// Prometheus HTTP request metric middleware (must be after other middleware like bodyParser)
app.use((req, res, next) => {
  const end = httpRequestDurationHistogram.startTimer();
  res.on('finish', () => {
    const route = req.route ? req.route.path : req.path;
    httpRequestCounter.inc({
      method: req.method,
      route: route,
      status_code: res.statusCode,
    });
    end({
      method: req.method,
      route: route,
      status_code: res.statusCode,
    });
  });
  next();
});

// General request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// --- MongoDB Connection ---
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/textmate_db';
if (!MONGODB_URI) {
  console.error('CRITICAL: MONGODB_URI is not defined in environment variables or .env file.');
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected successfully!');
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// --- Redis Connection ---
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const redisClient = redis.createClient({ url: REDIS_URL });

redisClient.on('connect', () => console.log('Redis connected successfully!'));
redisClient.on('error', (err) => {
  console.error('Redis connection error:', err);
  // Log the error, but do not exit the process. The app can function without Redis (no caching).
});

// Attempt to connect Redis only once when the application starts
(async () => {
  try {
    await redisClient.connect();
  } catch (error) {
    console.error('Initial Redis connection failed, continuing without caching:', error);
  }
})();


// --- Mongoose Schemas and Models ---

// User Schema for Authentication
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true, // Trim whitespace
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long'],
  },
  createdAt: { type: Date, default: Date.now },
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Operation Log Schema
const operationLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Optional, as operations can be anonymous
  },
  text: {
    type: String,
    required: true,
    trim: true,
    minlength: [1, 'Text cannot be empty.']
  },
  textLength: {
    type: Number,
    required: true,
    min: [0, 'Text length cannot be negative.']
  },
  operationType: {
    type: String,
    required: true,
    enum: ['uppercase', 'lowercase', 'titlecase', 'reverse', 'analyze', 'login', 'signup'],
    lowercase: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    expires: '7d' // TTL index: documents expire after 7 days
  },
  ipAddress: {
    type: String,
    validate: {
      validator: (v) => validator.isIP(v, 4) || validator.isIP(v, 6),
      message: props => `${props.value} is not a valid IP address!`
    },
    required: false
  },
}, {
  timestamps: true
});

operationLogSchema.index({ timestamp: 1 });
const OperationLog = mongoose.model('OperationLog', operationLogSchema);


// --- Helper Functions and Authentication Middleware ---

const generateAuthToken = (userId) => {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('CRITICAL: JWT_SECRET is not defined!');
    process.exit(1);
  }
  return jwt.sign({ id: userId }, jwtSecret, { expiresIn: '1h' });
};

const logOperation = async (text, operationType, req, userId = null) => {
  try {
    const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
    await OperationLog.create({
      userId: userId,
      text: text,
      textLength: text.length,
      operationType: operationType,
      ipAddress: ipAddress
    });
    console.log(`[LOG] Operation '${operationType}' for text length ${text.length} logged successfully by user ${userId || 'anonymous'}.`);
    // Invalidate Redis cache for history (only if Redis is connected)
    if (redisClient.isReady) {
      await redisClient.del('operationHistoryCache'); // Clear general history cache
      if (userId) { // Clear user-specific history cache
        await redisClient.del(`operationHistoryCache:user:${userId}:limit=20`); // Assuming default limit 20
        // If you have different limits, you might need to clear all keys related to user history.
      }
    }
  } catch (error) {
    console.error(`[ERROR] Failed to log operation '${operationType}':`, error.message);
  }
};

const validateTextPayload = (req, res, next) => {
  const { text } = req.body;
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return res.status(400).json({ success: false, message: 'Invalid or empty text provided. Please provide a non-empty string.' });
  }
  // If validation passes, trim text and move to next middleware/route handler
  req.body.text = text.trim();
  next();
};

// This middleware attempts to authenticate a user but doesn't block the request if no token is found.
// It populates req.user if a valid token is present.
const optionalAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const jwtSecret = process.env.JWT_SECRET;
      if (!jwtSecret) {
        console.warn('JWT_SECRET is not configured. Authentication will not work.');
        return next(); // Continue without authentication if secret is missing
      }
      const decoded = jwt.verify(token, jwtSecret);
      req.user = decoded; // Attach user payload (e.g., { id: userId }) to the request
    } catch (error) {
      console.warn('Optional authentication failed (invalid/expired token):', error.message);
      // Do not throw error or return 401 here, just don't set req.user
    }
  }
  next(); // Always continue to the next middleware/route handler
};

// This middleware *requires* authentication and will block the request if no valid token is found.
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authorization token not provided or malformed.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not configured on the server.');
    }
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error for protected route:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired. Please log in again.' });
    }
    return res.status(401).json({ success: false, message: 'Invalid or unauthorized token.' });
  }
};


// --- API Routes ---

/**
 * @route POST /api/signup
 * @description Registers a new user.
 */
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  signupAttemptsCounter.inc({ status: 'attempt' });

  if (!username || !password) {
    signupAttemptsCounter.inc({ status: 'failure' });
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  // Basic server-side validation against common issues
  if (username.length < 3 || username.length > 30) {
    signupAttemptsCounter.inc({ status: 'failure' });
    return res.status(400).json({ success: false, message: 'Username must be between 3 and 30 characters.' });
  }
  if (password.length < 6) {
    signupAttemptsCounter.inc({ status: 'failure' });
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
  }

  try {
    const existingUser = await User.findOne({ username: username.toLowerCase() }); // Store username as lowercase for uniqueness
    if (existingUser) {
      signupAttemptsCounter.inc({ status: 'failure' });
      return res.status(409).json({ success: false, message: 'Username already taken.' });
    }

    const newUser = new User({ username: username.toLowerCase(), password }); // Save lowercase username
    await newUser.save();
    await logOperation(`User ${username} signed up.`, 'signup', req, newUser._id);
    signupAttemptsCounter.inc({ status: 'success' });
    res.status(201).json({ success: true, message: 'User registered successfully!' });
  } catch (error) {
    console.error('Signup error:', error);
    signupAttemptsCounter.inc({ status: 'failure' });
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({ success: false, message: messages.join(', ') });
    }
    res.status(500).json({ success: false, message: 'Server error during signup.' });
  }
});

/**
 * @route POST /api/login
 * @description Authenticates a user and returns a JWT.
 */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  loginAttemptsCounter.inc({ status: 'attempt' });

  if (!username || !password) {
    loginAttemptsCounter.inc({ status: 'failure' });
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const user = await User.findOne({ username: username.toLowerCase() }); // Find user by lowercase username
    if (!user) {
      loginAttemptsCounter.inc({ status: 'failure' });
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      loginAttemptsCounter.inc({ status: 'failure' });
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    const token = generateAuthToken(user._id);
    await logOperation(`User ${username} logged in.`, 'login', req, user._id);
    loginAttemptsCounter.inc({ status: 'success' });
    res.json({ success: true, message: 'Logged in successfully!', token });
  } catch (error) {
    console.error('Login error:', error);
    loginAttemptsCounter.inc({ status: 'failure' });
    res.status(500).json({ success: false, message: 'Server error during login.' });
  }
});

// --- Text Transformation Endpoints (Middleware added for validation and logging) ---
// These endpoints now use `optionalAuthMiddleware` to allow both logged-in and anonymous usage.

/**
 * @route POST /api/uppercase
 * @description Transforms the input text to uppercase.
 * Accessible to both authenticated and unauthenticated users.
 * Operation is logged with userId if authenticated, else anonymously.
 */
app.post('/api/uppercase', optionalAuthMiddleware, validateTextPayload, async (req, res) => {
  const userId = req.user ? req.user.id : null; // Get user ID if authenticated
  await logOperation(req.body.text, 'uppercase', req, userId);
  const transformedText = req.body.text.toUpperCase();
  res.json({ success: true, transformedText });
});

/**
 * @route POST /api/lowercase
 * @description Transforms the input text to lowercase.
 * Accessible to both authenticated and unauthenticated users.
 * Operation is logged with userId if authenticated, else anonymously.
 */
app.post('/api/lowercase', optionalAuthMiddleware, validateTextPayload, async (req, res) => {
  const userId = req.user ? req.user.id : null;
  await logOperation(req.body.text, 'lowercase', req, userId);
  const transformedText = req.body.text.toLowerCase();
  res.json({ success: true, transformedText });
});

/**
 * @route POST /api/titlecase
 * @description Transforms the input text to title case.
 * Accessible to both authenticated and unauthenticated users.
 * Operation is logged with userId if authenticated, else anonymously.
 */
app.post('/api/titlecase', optionalAuthMiddleware, validateTextPayload, async (req, res) => {
  const userId = req.user ? req.user.id : null;
  await logOperation(req.body.text, 'titlecase', req, userId);
  const transformedText = req.body.text.replace(/\b\w/g, char => char.toUpperCase());
  res.json({ success: true, transformedText });
});

/**
 * @route POST /api/reverse
 * @description Reverses the input text.
 * Accessible to both authenticated and unauthenticated users.
 * Operation is logged with userId if authenticated, else anonymously.
 */
app.post('/api/reverse', optionalAuthMiddleware, validateTextPayload, async (req, res) => {
  const userId = req.user ? req.user.id : null;
  await logOperation(req.body.text, 'reverse', req, userId);
  const transformedText = req.body.text.split('').reverse().join('');
  res.json({ success: true, transformedText });
});

/**
 * @route POST /api/analyse
 * @description Performs analysis on the input text.
 * Accessible to both authenticated and unauthenticated users.
 * Operation is logged with userId if authenticated, else anonymously.
 */
app.post('/api/analyse', optionalAuthMiddleware, validateTextPayload, async (req, res) => {
  const { text } = req.body;
  const userId = req.user ? req.user.id : null;

  try {
    const words = text.trim().split(/\s+/).filter(word => word.length > 0);
    const wordCount = words.length;
    const charCount = text.replace(/\s/g, "").length;
    const sentences = text.trim().split(/[.!?]+\s*/).filter(s => s.length > 0);
    const sentenceCount = sentences.length;
    const readTime = Math.ceil(wordCount * 0.005);

    await logOperation(text, 'analyze', req, userId);
    res.json({
      success: true,
      analysis: {
        wordCount,
        charCount,
        sentenceCount,
        readTime
      }
    });
  } catch (error) {
    console.error('[ERROR] Error during analyse operation:', error);
    res.status(500).json({ success: false, message: 'Failed to perform text analysis.' });
  }
});


/**
 * @route GET /api/operation-history
 * @description Retrieves a list of recent text operations from the database, using Redis cache.
 * REQUIRES AUTHENTICATION. History is specific to the logged-in user.
 */
app.get('/api/operation-history', authMiddleware, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    if (limit <= 0 || limit > 100) {
      return res.status(400).json({ success: false, message: 'Limit must be a positive number up to 100.' });
    }

    const userId = req.user.id;
    const cacheKey = `operationHistoryCache:user:${userId}:limit=${limit}`;
    let history;

    if (redisClient.isReady) {
        const cachedHistory = await redisClient.get(cacheKey);
        if (cachedHistory) {
          history = JSON.parse(cachedHistory);
          console.log(`[REDIS] Serving history for user ${userId} from cache.`);
          return res.json({ success: true, history });
        }
    }

    console.log(`[MONGO] Fetching history for user ${userId} from MongoDB.`);
    history = await OperationLog.find({ userId: userId })
      .select('text textLength operationType timestamp ipAddress')
      .sort({ timestamp: -1 })
      .limit(limit);

    if (redisClient.isReady) {
        await redisClient.setEx(cacheKey, 60, JSON.stringify(history));
    }
    res.json({ success: true, history });

  } catch (error) {
    console.error('[ERROR] Error fetching operation history:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch operation history.' });
  }
});

/**
 * @route GET /metrics
 * @description Exposes Prometheus metrics.
 */
app.get('/metrics', async (req, res) => {
  res.setHeader('Content-Type', register.contentType);
  res.end(await register.metrics());
});

/**
 * @route GET /
 * @description A simple root endpoint to confirm the server is running.
 */
app.get('/', (req, res) => {
  res.send('Welcome to the TextMate Backend API!');
});


// --- Global Error Handler (Middleware) ---
app.use((err, req, res, next) => {
  console.error('[GLOBAL_ERROR]', err.stack);
  res.status(500).json({
    success: false,
    message: 'An unexpected server error occurred.',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});


// --- Server Start ---
app.listen(PORT, () => {
  console.log(`TextMate Backend Server is running successfully.`);
  console.log(`Access it at: http://localhost:${PORT}`);
  console.log('MongoDB URI:', MONGODB_URI.replace(/mongodb:\/\/(.*)@/, 'mongodb://<user>:<password>@'));
  console.log('Redis URL:', REDIS_URL.replace(/redis:\/\/(.*)@/, 'redis://<user>:<password>@'));
});
