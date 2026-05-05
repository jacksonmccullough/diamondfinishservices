require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { engine } = require('express-handlebars');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const https = require('https');
const fs = require('fs');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

// Nodemailer setup (Gmail SMTP)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Generate a unique 8-character order number like "DF-A3K9M2X1"
function generateOrderNumber() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/0/1 to avoid confusion
  let code = '';
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return 'DF-' + code;
}

// HTML escaping – prevents XSS in emails
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Handlebars setup
app.engine('hbs', engine({
  extname: '.hbs',
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views/layouts'),
  partialsDir: path.join(__dirname, 'views/partials')
}));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('Connected to MongoDB Atlas');
    // ─── Schema migration: remove legacy documents that used `day` instead of `date` ───
    const [d, ls] = await Promise.all([
      Booking.deleteMany({ date: { $exists: false } }),
      BookingLS.deleteMany({ date: { $exists: false } })
    ]);
    if (d.deletedCount || ls.deletedCount) {
      console.log(`[Migration] Removed ${d.deletedCount} legacy detailing and ${ls.deletedCount} legacy landscaping bookings.`);
    }
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Allowed services — detailing
const VALID_SERVICES = ['Level 1', 'Level 2', 'Mowing', 'Mulching', 'Pressure Washing'];

// Allowed services — landscaping
const VALID_SERVICES_LS = ['Mowing', 'Mulching', 'Pressure Washing'];

// ─── Rolling window scheduling ───
// How many upcoming weekdays to keep open for booking
const WINDOW_DAYS = 10;

// Returns a Set of valid YYYY-MM-DD strings (next WINDOW_DAYS weekdays from today)
function getRollingWindowDates() {
  const dates = new Set();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  let cursor = new Date(today);
  while (dates.size < WINDOW_DAYS) {
    const dow = cursor.getDay();
    if (dow >= 1 && dow <= 5) {
      const y = cursor.getFullYear();
      const m = String(cursor.getMonth() + 1).padStart(2, '0');
      const d = String(cursor.getDate()).padStart(2, '0');
      dates.add(`${y}-${m}-${d}`);
    }
    cursor.setDate(cursor.getDate() + 1);
  }
  return dates;
}

// Returns a human-readable date string from a YYYY-MM-DD string
function formatBookingDate(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const dateObj = new Date(y, m - 1, d);
  return dateObj.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}

// Booking schema
const bookingSchema = new mongoose.Schema({
  orderNumber: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  city: { type: String, required: true },
  service: { type: String, required: true, enum: VALID_SERVICES },
  date: { type: String, required: true },  // YYYY-MM-DD
  time: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// One booking per date/time slot
bookingSchema.index({ date: 1, time: 1 }, { unique: true });

const Booking = mongoose.model('Booking', bookingSchema);

// Landscaping booking schema — separate collection (bookingls)
const bookingLSSchema = new mongoose.Schema({
  orderNumber: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  city: { type: String, required: true },
  service: { type: String, required: true, enum: VALID_SERVICES_LS },
  date: { type: String, required: true },  // YYYY-MM-DD
  time: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
bookingLSSchema.index({ date: 1, time: 1 }, { unique: true });
const BookingLS = mongoose.model('BookingLS', bookingLSSchema, 'bookingls');

// ─── SECURITY: Generate a unique CSP nonce per request ───
// Prevents XSS by only allowing inline scripts with a matching nonce
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

// ─── SECURITY: Helmet – hardens HTTP response headers ───
// Sets Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
// Strict-Transport-Security, Referrer-Policy, X-DNS-Prefetch-Control, and more
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      ...(process.env.NODE_ENV === 'production' ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: process.env.NODE_ENV === 'production' ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ─── SECURITY: Rate limiting – prevents brute-force attacks & DDoS ───
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});
const bookingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many booking attempts. Please try again later.' },
});
app.use(generalLimiter);

// Static files
app.use(express.static('public'));

// ─── SECURITY: Body size limits – prevents large-payload DoS ───
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// ─── SECURITY: NoSQL injection prevention ───
// Strips MongoDB query operators ($gt, $ne, $in, etc.) from user input
app.use(mongoSanitize());

// ─── SECURITY: HTTP Parameter Pollution prevention ───
app.use(hpp());

// ─── SECURITY: HTTPS redirect in production ───
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    next();
  });
}

// Page routes
app.get('/', (req, res) => {
  res.render('index', {
    pageTitle: 'Diamond Finish Detailing - Professional Mobile & Shop Detailing',
    metaDescription: 'Professional mobile & shop detailing service in Noblesville, IN. We restore shine and protect your vehicle\'s value with premium detailing packages.',
    activeDetailing: true
  });
});

app.get('/booking', (req, res) => {
  res.render('booking', {
    pageTitle: 'Book a Service - Diamond Finish Detailing',
    metaDescription: 'Book your car detailing service with Diamond Finish Detailing. Choose from our premium packages and reserve your time slot.',
    activeDetailing: true
  });
});

app.get('/booking_ls', (req, res) => {
  res.render('booking_ls', {
    pageTitle: 'Book a Landscaping Service - Midwest Landscaping',
    metaDescription: 'Book your landscaping service with Midwest Landscaping. Choose from mowing, mulching, pressure washing and more.',
    activeLandscaping: true
  });
});

app.get('/landscaping', (req, res) => {
  res.render('landscaping', {
    pageTitle: 'Diamond Finish Landscaping - Professional Lawn & Landscape Services',
    metaDescription: 'Professional landscaping services in Noblesville, IN. We transform your outdoor spaces with expert lawn care, mulching, and landscape design.',
    activeLandscaping: true
  });
});

// API: Get all bookings
app.get('/api/bookings', async (req, res) => {
  try {
    // ─── SECURITY: Strip PII – only expose scheduling data publicly ───
    const windowDates = [...getRollingWindowDates()];
    const bookings = await Booking.find(
      { date: { $in: windowDates } },
      { name: 0, email: 0, phone: 0, city: 0, __v: 0 }
    );
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// API: Create a booking
app.post('/api/bookings', bookingLimiter, async (req, res) => {
  try {
    const { name, email, phone, city, service, date, time } = req.body;

    // ─── SECURITY: Strict input validation at system boundary ───
    if (!name || !email || !phone || !city || !service || !date || !time) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    // Type checks – prevents object/array injection
    if (typeof name !== 'string' || typeof email !== 'string' || typeof phone !== 'string' ||
        typeof city !== 'string' || typeof service !== 'string' || typeof date !== 'string' ||
        typeof time !== 'string') {
      return res.status(400).json({ error: 'Invalid input types' });
    }
    // Length limits
    if (name.length > 50 || email.length > 254 || phone.length > 20 || city.length > 100) {
      return res.status(400).json({ error: 'Input exceeds maximum length' });
    }
    // Name format (letters, spaces, hyphens, apostrophes)
    if (!/^[A-Za-z][A-Za-z' \-]{0,48}[A-Za-z]$/.test(name.trim())) {
      return res.status(400).json({ error: 'Invalid name format' });
    }
    // Email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    // Phone format (7-15 digits)
    const phoneDigits = phone.replace(/\D/g, '');
    if (phoneDigits.length < 7 || phoneDigits.length > 15) {
      return res.status(400).json({ error: 'Invalid phone number' });
    }
    // City validation
    if (city.trim().length < 2) {
      return res.status(400).json({ error: 'Invalid city' });
    }
    // Service whitelist validation
    if (!VALID_SERVICES.includes(service)) {
      return res.status(400).json({ error: 'Invalid service selected' });
    }
    // Date format and rolling window validation
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format' });
    }
    if (!getRollingWindowDates().has(date)) {
      return res.status(400).json({ error: 'Date is not within the available booking window' });
    }
    // Time whitelist validation
    const VALID_TIMES = ['16-18', '18-20', '20-22'];
    if (!VALID_TIMES.includes(time)) {
      return res.status(400).json({ error: 'Invalid time slot' });
    }

    // Generate a unique order number (retry if collision)
    let orderNumber;
    for (let i = 0; i < 5; i++) {
      const candidate = generateOrderNumber();
      const exists = await Booking.findOne({ orderNumber: candidate });
      if (!exists) { orderNumber = candidate; break; }
    }
    if (!orderNumber) {
      return res.status(500).json({ error: 'Failed to generate order number. Please try again.' });
    }

    const booking = new Booking({
      orderNumber,
      name: name.trim(),
      email: email.trim(),
      phone: phone.trim(),
      city: city.trim(),
      service, date, time
    });
    await booking.save();

    // Send email confirmation via Nodemailer
    const timeLabels = {
      '16-18': '4:00 - 6:00 PM',
      '18-20': '6:00 - 8:00 PM',
      '20-22': '8:00 - 10:00 PM'
    };
    const humanTime = timeLabels[time] || time;
    const humanDate = formatBookingDate(date);
    try {
      await transporter.sendMail({
        from: `"Diamond Finish" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: `Booking Confirmed — Order #${orderNumber}`,
        text: `Diamond Finish Confirmation\n\nOrder #: ${orderNumber}\nName: ${name}\nService: ${service}\nDate: ${humanDate}\nTime: ${humanTime}\nPhone: ${phone}\nCity: ${city}\n\nSave this order number to cancel or modify your appointment.`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1a1a1a; border-bottom: 2px solid #c4a44a; padding-bottom: 10px;">Diamond Finish Confirmation ✅</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
              <tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(orderNumber)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(name)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(service)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr>
            </table>
            <p style="color: #555; font-size: 14px; margin-top: 16px;">Save this order number to cancel or modify your appointment.</p>
          </div>
        `
      });
    } catch (emailErr) {
      console.error('Email send failed:', emailErr.message);
      // Booking still succeeds even if email fails
    }

    // Notify owner of new detailing booking
    const ownerEmail = process.env.OWNER_EMAIL || process.env.GMAIL_USER;
    try {
      await transporter.sendMail({
        from: `"Diamond Finish" <${process.env.GMAIL_USER}>`,
        to: ownerEmail,
        subject: `New Detailing Booking — Order #${orderNumber}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1a1a1a; border-bottom: 2px solid #c4a44a; padding-bottom: 10px;">New Detailing Booking 🚗</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
              <tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(orderNumber)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(name)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Email</td><td style="padding: 8px 0;">${escapeHtml(email)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Phone</td><td style="padding: 8px 0;">${escapeHtml(phone)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">City</td><td style="padding: 8px 0;">${escapeHtml(city)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(service)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr>
            </table>
          </div>
        `
      });
    } catch (ownerEmailErr) {
      console.error('Owner notification email failed (detailing):', ownerEmailErr.message);
    }

    res.status(201).json({
      orderNumber: booking.orderNumber,
      service: booking.service,
      date: booking.date,
      time: booking.time,
      createdAt: booking.createdAt
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'This time slot is already reserved' });
    }
    res.status(500).json({ error: 'Failed to create booking' });
  }
});

// API: Get all landscaping bookings
app.get('/api/bookings_ls', async (req, res) => {
  try {
    const windowDates = [...getRollingWindowDates()];
    const bookings = await BookingLS.find(
      { date: { $in: windowDates } },
      { name: 0, email: 0, phone: 0, city: 0, __v: 0 }
    );
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// API: Create a landscaping booking
app.post('/api/bookings_ls', bookingLimiter, async (req, res) => {
  try {
    const { name, email, phone, city, service, date, time } = req.body;
    if (!name || !email || !phone || !city || !service || !date || !time) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (typeof name !== 'string' || typeof email !== 'string' || typeof phone !== 'string' ||
        typeof city !== 'string' || typeof service !== 'string' || typeof date !== 'string' ||
        typeof time !== 'string') {
      return res.status(400).json({ error: 'Invalid input types' });
    }
    if (name.length > 50 || email.length > 254 || phone.length > 20 || city.length > 100) {
      return res.status(400).json({ error: 'Input exceeds maximum length' });
    }
    if (!/^[A-Za-z][A-Za-z' \-]{0,48}[A-Za-z]$/.test(name.trim())) {
      return res.status(400).json({ error: 'Invalid name format' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    const phoneDigits = phone.replace(/\D/g, '');
    if (phoneDigits.length < 7 || phoneDigits.length > 15) {
      return res.status(400).json({ error: 'Invalid phone number' });
    }
    if (city.trim().length < 2) {
      return res.status(400).json({ error: 'Invalid city' });
    }
    if (!VALID_SERVICES_LS.includes(service)) {
      return res.status(400).json({ error: 'Invalid service selected' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format' });
    }
    if (!getRollingWindowDates().has(date)) {
      return res.status(400).json({ error: 'Date is not within the available booking window' });
    }
    const VALID_TIMES = ['16-18', '18-20', '20-22'];
    if (!VALID_TIMES.includes(time)) {
      return res.status(400).json({ error: 'Invalid time slot' });
    }
    let orderNumber;
    for (let i = 0; i < 5; i++) {
      const candidate = generateOrderNumber();
      const exists = await BookingLS.findOne({ orderNumber: candidate });
      if (!exists) { orderNumber = candidate; break; }
    }
    if (!orderNumber) {
      return res.status(500).json({ error: 'Failed to generate order number. Please try again.' });
    }
    const booking = new BookingLS({
      orderNumber,
      name: name.trim(),
      email: email.trim(),
      phone: phone.trim(),
      city: city.trim(),
      service, date, time
    });
    await booking.save();
    const timeLabels = { '16-18': '4:00 - 6:00 PM', '18-20': '6:00 - 8:00 PM', '20-22': '8:00 - 10:00 PM' };
    const humanTime = timeLabels[time] || time;
    const humanDate = formatBookingDate(date);
    try {
      await transporter.sendMail({
        from: `"Midwest Landscaping" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: `Landscaping Booking Confirmed — Order #${orderNumber}`,
        text: `Midwest Landscaping Confirmation\n\nOrder #: ${orderNumber}\nName: ${name}\nService: ${service}\nDate: ${humanDate}\nTime: ${humanTime}\nPhone: ${phone}\nCity: ${city}\n\nSave this order number to cancel or modify your appointment.`,
        html: `<div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;"><h2 style="color: #1a1a1a; border-bottom: 2px solid #555; padding-bottom: 10px;">Midwest Landscaping Confirmation ✅</h2><table style="width: 100%; border-collapse: collapse; margin: 16px 0;"><tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(orderNumber)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(name)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(service)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr></table><p style="color: #555; font-size: 14px; margin-top: 16px;">Save this order number to cancel or modify your appointment.</p></div>`
      });
    } catch (emailErr) {
      console.error('Landscaping email send failed:', emailErr.message);
    }

    // Notify owner of new landscaping booking
    const ownerEmailLS = process.env.OWNER_EMAIL || process.env.GMAIL_USER;
    try {
      await transporter.sendMail({
        from: `"Midwest Landscaping" <${process.env.GMAIL_USER}>`,
        to: ownerEmailLS,
        subject: `New Landscaping Booking — Order #${orderNumber}`,
        html: `<div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;"><h2 style="color: #1a1a1a; border-bottom: 2px solid #555; padding-bottom: 10px;">New Landscaping Booking 🌿</h2><table style="width: 100%; border-collapse: collapse; margin: 16px 0;"><tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(orderNumber)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(name)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Email</td><td style="padding: 8px 0;">${escapeHtml(email)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Phone</td><td style="padding: 8px 0;">${escapeHtml(phone)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">City</td><td style="padding: 8px 0;">${escapeHtml(city)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(service)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr></table></div>`
      });
    } catch (ownerEmailErr) {
      console.error('Owner notification email failed (landscaping):', ownerEmailErr.message);
    }

    res.status(201).json({
      orderNumber: booking.orderNumber,
      service: booking.service,
      date: booking.date,
      time: booking.time,
      createdAt: booking.createdAt
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'This time slot is already reserved' });
    }
    res.status(500).json({ error: 'Failed to create booking' });
  }
});

// API: Cancel a landscaping booking by order number
app.delete('/api/bookings_ls/cancel', bookingLimiter, async (req, res) => {
  try {
    const { orderNumber } = req.body;
    if (!orderNumber || typeof orderNumber !== 'string') {
      return res.status(400).json({ error: 'Order number is required' });
    }
    const sanitized = orderNumber.trim().toUpperCase();
    if (!/^DF-[A-Z0-9]{8}$/.test(sanitized)) {
      return res.status(400).json({ error: 'Invalid order number format' });
    }
    const result = await BookingLS.findOneAndDelete({ orderNumber: sanitized });
    if (!result) {
      return res.status(404).json({ error: 'No booking found with that order number' });
    }

    const timeLabels = { '16-18': '4:00 - 6:00 PM', '18-20': '6:00 - 8:00 PM', '20-22': '8:00 - 10:00 PM' };
    const humanTime = timeLabels[result.time] || result.time;
    const humanDate = formatBookingDate(result.date);

    // Notify customer of cancellation
    try {
      await transporter.sendMail({
        from: `"Midwest Landscaping" <${process.env.GMAIL_USER}>`,
        to: result.email,
        subject: `Landscaping Booking Cancelled — Order #${result.orderNumber}`,
        text: `Midwest Landscaping Cancellation\n\nOrder #: ${result.orderNumber}\nName: ${result.name}\nService: ${result.service}\nDate: ${humanDate}\nTime: ${humanTime}\n\nYour booking has been cancelled. If this was a mistake, please book a new appointment.`,
        html: `<div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;"><h2 style="color: #1a1a1a; border-bottom: 2px solid #555; padding-bottom: 10px;">Booking Cancelled ❌</h2><p style="color: #555;">Your landscaping appointment has been cancelled.</p><table style="width: 100%; border-collapse: collapse; margin: 16px 0;"><tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(result.orderNumber)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(result.name)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(result.service)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr></table><p style="color: #555; font-size: 14px;">If this was a mistake, please visit our site to rebook.</p></div>`
      });
    } catch (emailErr) {
      console.error('Landscaping cancellation customer email failed:', emailErr.message);
    }

    // Notify owner of cancellation
    const ownerEmailLS = process.env.OWNER_EMAIL || process.env.GMAIL_USER;
    try {
      await transporter.sendMail({
        from: `"Midwest Landscaping" <${process.env.GMAIL_USER}>`,
        to: ownerEmailLS,
        subject: `Landscaping Booking Cancelled — Order #${result.orderNumber}`,
        html: `<div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;"><h2 style="color: #1a1a1a; border-bottom: 2px solid #555; padding-bottom: 10px;">Landscaping Booking Cancelled 🌿</h2><table style="width: 100%; border-collapse: collapse; margin: 16px 0;"><tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(result.orderNumber)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(result.name)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Email</td><td style="padding: 8px 0;">${escapeHtml(result.email)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Phone</td><td style="padding: 8px 0;">${escapeHtml(result.phone)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(result.service)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr><tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr></table></div>`
      });
    } catch (ownerEmailErr) {
      console.error('Landscaping cancellation owner email failed:', ownerEmailErr.message);
    }

    res.json({
      message: 'Booking cancelled successfully',
      orderNumber: result.orderNumber,
      service: result.service,
      date: result.date,
      time: result.time
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

// API: Cancel a booking by order number
app.delete('/api/bookings/cancel', bookingLimiter, async (req, res) => {
  try {
    const { orderNumber } = req.body;
    if (!orderNumber || typeof orderNumber !== 'string') {
      return res.status(400).json({ error: 'Order number is required' });
    }
    const sanitized = orderNumber.trim().toUpperCase();
    // ─── SECURITY: Format validation prevents injection via malformed input ───
    if (!/^DF-[A-Z0-9]{8}$/.test(sanitized)) {
      return res.status(400).json({ error: 'Invalid order number format' });
    }
    const result = await Booking.findOneAndDelete({ orderNumber: sanitized });
    if (!result) {
      return res.status(404).json({ error: 'No booking found with that order number' });
    }

    const timeLabels = { '16-18': '4:00 - 6:00 PM', '18-20': '6:00 - 8:00 PM', '20-22': '8:00 - 10:00 PM' };
    const humanTime = timeLabels[result.time] || result.time;
    const humanDate = formatBookingDate(result.date);

    // Notify customer of cancellation
    try {
      await transporter.sendMail({
        from: `"Diamond Finish" <${process.env.GMAIL_USER}>`,
        to: result.email,
        subject: `Booking Cancelled — Order #${result.orderNumber}`,
        text: `Diamond Finish Cancellation\n\nOrder #: ${result.orderNumber}\nName: ${result.name}\nService: ${result.service}\nDate: ${humanDate}\nTime: ${humanTime}\n\nYour booking has been cancelled. If this was a mistake, please book a new appointment.`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1a1a1a; border-bottom: 2px solid #c4a44a; padding-bottom: 10px;">Booking Cancelled ❌</h2>
            <p style="color: #555;">Your detailing appointment has been cancelled.</p>
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
              <tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(result.orderNumber)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(result.name)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(result.service)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr>
            </table>
            <p style="color: #555; font-size: 14px;">If this was a mistake, please visit our site to rebook.</p>
          </div>
        `
      });
    } catch (emailErr) {
      console.error('Detailing cancellation customer email failed:', emailErr.message);
    }

    // Notify owner of cancellation
    const ownerEmail = process.env.OWNER_EMAIL || process.env.GMAIL_USER;
    try {
      await transporter.sendMail({
        from: `"Diamond Finish" <${process.env.GMAIL_USER}>`,
        to: ownerEmail,
        subject: `Detailing Booking Cancelled — Order #${result.orderNumber}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1a1a1a; border-bottom: 2px solid #c4a44a; padding-bottom: 10px;">Detailing Booking Cancelled 🚗</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
              <tr><td style="padding: 8px 0; font-weight: bold;">Order #</td><td style="padding: 8px 0;">${escapeHtml(result.orderNumber)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Name</td><td style="padding: 8px 0;">${escapeHtml(result.name)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Email</td><td style="padding: 8px 0;">${escapeHtml(result.email)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Phone</td><td style="padding: 8px 0;">${escapeHtml(result.phone)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Service</td><td style="padding: 8px 0;">${escapeHtml(result.service)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Date</td><td style="padding: 8px 0;">${escapeHtml(humanDate)}</td></tr>
              <tr><td style="padding: 8px 0; font-weight: bold;">Time</td><td style="padding: 8px 0;">${escapeHtml(humanTime)}</td></tr>
            </table>
          </div>
        `
      });
    } catch (ownerEmailErr) {
      console.error('Detailing cancellation owner email failed:', ownerEmailErr.message);
    }

    res.json({
      message: 'Booking cancelled successfully',
      orderNumber: result.orderNumber,
      service: result.service,
      date: result.date,
      time: result.time
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

// ─── Daily cleanup: remove bookings for past dates (runs at midnight every day) ───
// Because the rolling window uses specific dates, past bookings auto-expire.
// This cron removes them from MongoDB so they don't accumulate.
cron.schedule('0 0 * * *', async () => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;

    const [detailingResult, landscapingResult] = await Promise.all([
      Booking.deleteMany({ date: { $lt: todayStr } }),
      BookingLS.deleteMany({ date: { $lt: todayStr } })
    ]);

    if (detailingResult.deletedCount || landscapingResult.deletedCount) {
      console.log(`[Daily Cleanup] Removed ${detailingResult.deletedCount} past detailing and ${landscapingResult.deletedCount} past landscaping booking(s).`);
    }
  } catch (err) {
    console.error('[Daily Cleanup] Failed:', err.message);
  }
}, {
  timezone: 'America/Indiana/Indianapolis'
});

// ─── SECURITY: TLS/HTTPS server support ───
// For production, set TLS_CERT_PATH and TLS_KEY_PATH in .env
// Or use a reverse proxy (nginx, Cloudflare) for TLS termination
const TLS_CERT = process.env.TLS_CERT_PATH;
const TLS_KEY = process.env.TLS_KEY_PATH;

if (TLS_CERT && TLS_KEY && fs.existsSync(TLS_CERT) && fs.existsSync(TLS_KEY)) {
  const httpsOptions = {
    cert: fs.readFileSync(TLS_CERT),
    key: fs.readFileSync(TLS_KEY),
    minVersion: 'TLSv1.2', // Block TLS 1.0/1.1 (insecure)
  };
  https.createServer(httpsOptions, app).listen(443, () => {
    console.log('HTTPS server running on port 443 (TLS 1.2+)');
  });
  // HTTP → HTTPS redirect
  require('http').createServer((req, res) => {
    res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
    res.end();
  }).listen(PORT, () => {
    console.log(`HTTP→HTTPS redirect running on port ${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    if (process.env.NODE_ENV === 'production') {
      console.warn('⚠ WARNING: No TLS certificates found. Set TLS_CERT_PATH and TLS_KEY_PATH in .env for HTTPS.');
    }
  });
}
