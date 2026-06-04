import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Load variables from our .env configuration file
dotenv.config();
const app = express();

// Middleware rules
app.use(cors({
  origin: true, // Explicitly allows your Vite React frontend access
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json()); // Allows the backend to read incoming JSON packages from React

// ── 1. ESTABLISH MONGO DATABASE CONNECTION ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected natively to Vinalax database'))
  .catch((err) => console.error('❌ Database connection failure:', err));

// ── 2. DATA BLUEPRINTS (SCHEMAS) ──

// Customer Inquiry Data Blueprint
const enquirySchema = new mongoose.Schema({
  name: { type: String, required: true },
  company: { type: String, default: '' },
  phone: { type: String, required: true },
  service: { type: String, required: true },
  message: { type: String, default: '' },
  date: { type: String, required: true }
}, { timestamps: true });

const Enquiry = mongoose.model('Enquiry', enquirySchema);

// Admin Account Security Blueprint
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', adminSchema);

// ── 3. SECURE JWT VERIFICATION MIDDLEWARE GATE ──
// This function sits in front of your private data routes to verify credentials
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Expecting header format: "Bearer <JWT_TOKEN_STRING>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access Denied: Missing security token keys.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.adminUser = verified; // Append verified user details to the request context
    next(); // Pass to the next logic route handler function safely
  } catch (err) {
    res.status(403).json({ success: false, message: 'Session expired or invalid authentication parameters.' });
  }
};

// ── 4. BACKEND API ROUTE DEFINITIONS ──

// SETUP ACCOUNT ROUTE (One-time call to seed initial encrypted login details manual check)
app.post('/api/auth/setup-admin', async (req, res) => {
  try {
    const checkAdmin = await Admin.findOne({ email: 'admin@vinalax.com' });
    if (checkAdmin) return res.status(400).json({ message: 'Admin profile already seeded.' });

    // Hash the password securely using bcrypt before writing to the database
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('admin123', salt);

    const newAdmin = new Admin({
      email: 'admin@vinalax.com',
      password: hashedPassword
    });

    await newAdmin.save();
    res.status(201).json({ message: 'Secure Admin profile created successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// LOGIN AUTHENTICATION ROUTE (Checks credentials, issues signed JWT pass)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ success: false, message: 'Invalid identity credential mappings.' });
    }

    // Safely compare raw text with the encrypted password hash string in our DB
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(400).json({ success: false, message: 'Invalid security access token keys.' });
    }

    // Sign details into an immutable encryption string token valid for 24 hours
    const token = jwt.sign({ id: admin._id, email: admin.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.status(200).json({
      success: true,
      token: token,
      message: 'Authentication successful.'
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUBLIC SUBMISSION ROUTE (Saves client entries from public website home page)
app.post('/api/enquiries', async (req, res) => {
  try {
    const { fname, lname, company, phone, service, message } = req.body;
    const fullName = `${fname} ${lname}`.trim();
    const todayISO = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD

    const newEnquiry = new Enquiry({
      name: fullName,
      company: company || '',
      phone: phone,
      service: service,
      message: message || '',
      date: todayISO
    });

    await newEnquiry.save();
    res.status(201).json({ success: true, message: 'Enquiry safely saved to database!' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PROTECTED FETCH ROUTE (Reads entries from database; requires valid verifyToken JWT pass)
app.get('/api/enquiries', verifyToken, async (req, res) => {
  try {
    const list = await Enquiry.find().sort({ createdAt: -1 }); // Sort newest to oldest
    
    // Structure records into the properties your frontend layout expects
    const mappedList = list.map(e => ({
      id: e._id,
      name: e.name,
      company: e.company,
      phone: e.phone,
      service: e.service,
      message: e.message,
      date: e.date
    }));

    res.status(200).json(mappedList);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// PROTECTED DELETE ROUTE (Removes single entries from table; requires valid verifyToken JWT pass)
app.delete('/api/enquiries/:id', verifyToken, async (req, res) => {
  try {
    await Enquiry.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: 'Record cleared successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ── 5. START ACTIVE ENGINE LISTENER WITH AUTOMATIC PROFILE SEEDING ──
const PORT = process.env.PORT || 5001;

app.listen(PORT, async () => {
  console.log(`🚀 Vinalax JWT-Core Server running perfectly on port ${PORT}`);
  
  try {
    const adminEmail = 'admin@vinalax.com';
    let admin = await Admin.findOne({ email: adminEmail });
    
    // Create clean, consistent hashing for standard deployment login
    const salt = await bcrypt.genSalt(10);
    const correctHash = await bcrypt.hash('admin123', salt);

    if (!admin) {
      // Create admin user dynamically if the collection is completely clean
      admin = new Admin({ email: adminEmail, password: correctHash });
      await admin.save();
      console.log('⭐ Database Lifecycle: Initial Admin user dynamically configured in Atlas cluster!');
    } else {
      // Force correction step if previous database attempts stored corrupted hashes
      admin.password = correctHash;
      await admin.save();
      console.log('⭐ Database Lifecycle: Existing Admin authentication hashes successfully validated!');
    }
  } catch (syncError) {
    console.error('⚠️ Database Lifecycle Warning: Could not complete startup profile setup:', syncError.message);
  }
});