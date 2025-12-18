import express from 'express';
import cors from 'cors';
import { MongoClient, ServerApiVersion, ObjectId } from 'mongodb';
import admin from 'firebase-admin';
import Stripe from 'stripe';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 3000;

// Stripe initialization
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
}

// Firebase Admin initialization
let firebaseInitialized = false;
try {
  if (process.env.FB_SERVICE_KEY) {
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
    const serviceAccount = JSON.parse(decoded);
    
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    firebaseInitialized = true;
  }
} catch (error) {
  console.error('Firebase initialization failed:', error.message);
}

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));
app.use(express.json());

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_CLUSTER}/?retryWrites=true&w=majority&appName=citywatch`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Database collections
let usersCollection;
let issuesCollection;
let paymentsCollection;
let commentsCollection;
let upvotesCollection;
let dbConnected = false;

// Connect to MongoDB
async function connectDB() {
  if (dbConnected) return; // Already connected
  
  try {
    console.log('Attempting to connect to MongoDB...');
    console.log('DB_USER exists:', !!process.env.DB_USER);
    console.log('DB_PASS exists:', !!process.env.DB_PASS);
    console.log('DB_CLUSTER exists:', !!process.env.DB_CLUSTER);
    
    await client.connect();
    const db = client.db(process.env.DB_NAME || 'citywatch');
    usersCollection = db.collection('users');
    issuesCollection = db.collection('issues');
    paymentsCollection = db.collection('payments');
    commentsCollection = db.collection('comments');
    upvotesCollection = db.collection('upvotes');
    
    // Create indexes
    await usersCollection.createIndex({ email: 1 }, { unique: true }).catch(() => {});
    await issuesCollection.createIndex({ reportedBy: 1 }).catch(() => {});
    await issuesCollection.createIndex({ status: 1 }).catch(() => {});
    await issuesCollection.createIndex({ assignedTo: 1 }).catch(() => {});
    await paymentsCollection.createIndex({ userId: 1 }).catch(() => {});
    
    dbConnected = true;
    console.log("✅ Connected to MongoDB!");
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
    console.error("Full error:", error);
    throw error;
  }
}

// Middleware to ensure DB connection
async function ensureDB(req, res, next) {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error('ensureDB error:', error.message);
    res.status(500).json({ 
      message: 'Database connection failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}

// Middleware: Verify Firebase Token
async function verifyToken(req, res, next) {
  // Skip verification if Firebase not initialized (local development)
  if (!firebaseInitialized) {
    req.user = { email: 'test@example.com' };
    return next();
  }

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized - No token provided' });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ message: 'Unauthorized - Invalid token' });
  }
}

// Middleware: Verify Admin
async function verifyAdmin(req, res, next) {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden - Admin access required' });
    }
    req.userDoc = user;
    next();
  } catch (error) {
    return res.status(500).json({ message: 'Server error' });
  }
}

// Middleware: Verify Staff
async function verifyStaff(req, res, next) {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user || user.role !== 'staff') {
      return res.status(403).json({ message: 'Forbidden - Staff access required' });
    }
    req.userDoc = user;
    next();
  } catch (error) {
    return res.status(500).json({ message: 'Server error' });
  }
}

// ==================== USER ROUTES ====================

// Create/Update User (Registration)
app.post('/users', ensureDB, async (req, res) => {
  try {
    const { email, name, photoURL, phoneNumber } = req.body;
    
    const existingUser = await usersCollection.findOne({ email });
    
    if (existingUser) {
      return res.status(200).json(existingUser);
    }

    const newUser = {
      email,
      name,
      photoURL: photoURL || null,
      phoneNumber: phoneNumber || null,
      role: 'citizen',
      isPremium: false,
      isBlocked: false,
      issueReportedThisMonth: 0,
      createdAt: new Date(),
      lastResetDate: new Date()
    };

    await usersCollection.insertOne(newUser);
    res.status(201).json(newUser);
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User by Email
app.get('/users/:email', ensureDB, async (req, res) => {
  try {
    const email = req.params.email;
    const user = await usersCollection.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update User Profile
app.patch('/users/:email', ensureDB, verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const { name, phoneNumber, photoURL } = req.body;

    if (req.user.email !== email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (photoURL) updateData.photoURL = photoURL;

    const result = await usersCollection.updateOne(
      { email },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== ISSUE ROUTES ====================

// Create Issue (Report Issue)
app.post('/issues', ensureDB, verifyToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user is blocked
    if (user.isBlocked) {
      return res.status(403).json({ message: 'blocked' });
    }

    // Reset monthly counter if needed
    const now = new Date();
    const lastReset = new Date(user.lastResetDate);
    if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) {
      await usersCollection.updateOne(
        { email: user.email },
        { $set: { issueReportedThisMonth: 0, lastResetDate: now } }
      );
      user.issueReportedThisMonth = 0;
    }

    // Check issue limit for non-premium users
    if (!user.isPremium && user.issueReportedThisMonth >= 3) {
      return res.status(429).json({ message: 'limit exceeded' });
    }

    const { title, description, category, location, image } = req.body;

    const newIssue = {
      title,
      description,
      category,
      location,
      image: image || null,
      reportedBy: user.email,
      reportedByName: user.name,
      status: 'pending',
      priority: 'normal',
      upvotes: 0,
      assignedTo: null,
      assignedToName: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      resolvedAt: null,
      timeline: [
        {
          status: 'pending',
          date: new Date(),
          note: 'Issue reported'
        }
      ]
    };

    const result = await issuesCollection.insertOne(newIssue);

    // Increment user's monthly issue count
    await usersCollection.updateOne(
      { email: user.email },
      { $inc: { issueReportedThisMonth: 1 } }
    );

    res.status(201).json({
      message: 'Issue reported successfully',
      issueId: result.insertedId
    });
  } catch (error) {
    console.error('Issue creation error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Issues (with filters)
app.get('/issues', ensureDB, async (req, res) => {
  try {
    const { status, category, limit } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (category) filter.category = category;

    const limitNum = limit ? parseInt(limit) : 0;

    const issues = await issuesCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .toArray();

    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Single Issue by ID
app.get('/issues/:id', ensureDB, async (req, res) => {
  try {
    const id = req.params.id;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

    if (!issue) {
      return res.status(404).json({ message: 'Issue not found' });
    }

    res.status(200).json(issue);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get My Issues
app.get('/issues/my-issues', ensureDB, verifyToken, async (req, res) => {
  try {
    const { status } = req.query;
    const filter = { reportedBy: req.user.email };
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    const issues = await issuesCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Issue (only pending issues can be edited by reporter)
app.patch('/issues/:id', ensureDB, verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

    if (!issue) {
      return res.status(404).json({ message: 'Issue not found' });
    }

    if (issue.reportedBy !== req.user.email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (issue.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending issues can be edited' });
    }

    const { title, description, category, location, image } = req.body;
    const updateData = {
      updatedAt: new Date()
    };

    if (title) updateData.title = title;
    if (description) updateData.description = description;
    if (category) updateData.category = category;
    if (location) updateData.location = location;
    if (image !== undefined) updateData.image = image;

    await issuesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    res.status(200).json({ message: 'Issue updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Issue (only pending issues can be deleted by reporter)
app.delete('/issues/:id', ensureDB, verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

    if (!issue) {
      return res.status(404).json({ message: 'Issue not found' });
    }

    if (issue.reportedBy !== req.user.email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (issue.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending issues can be deleted' });
    }

    await issuesCollection.deleteOne({ _id: new ObjectId(id) });

    // Decrement user's monthly count
    await usersCollection.updateOne(
      { email: req.user.email },
      { $inc: { issueReportedThisMonth: -1 } }
    );

    res.status(200).json({ message: 'Issue deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Upvote Issue
app.post('/issues/:id/upvote', ensureDB, verifyToken, async (req, res) => {
  try {
    const issueId = req.params.id;
    const userEmail = req.user.email;

    const existingUpvote = await upvotesCollection.findOne({
      issueId,
      userEmail
    });

    if (existingUpvote) {
      return res.status(400).json({ message: 'Already upvoted' });
    }

    await upvotesCollection.insertOne({
      issueId,
      userEmail,
      createdAt: new Date()
    });

    const upvoteCount = await upvotesCollection.countDocuments({ issueId });
    
    // Update priority based on upvotes
    let priority = 'normal';
    if (upvoteCount >= 10) priority = 'high';
    else if (upvoteCount >= 5) priority = 'medium';

    await issuesCollection.updateOne(
      { _id: new ObjectId(issueId) },
      { 
        $set: { upvotes: upvoteCount, priority },
        $inc: { upvotes: 1 }
      }
    );

    res.status(200).json({ message: 'Upvoted successfully', upvotes: upvoteCount });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== COMMENT ROUTES ====================

// Add Comment to Issue
app.post('/issues/:id/comments', ensureDB, verifyToken, async (req, res) => {
  try {
    const issueId = req.params.id;
    const { text } = req.body;
    const user = await usersCollection.findOne({ email: req.user.email });

    const comment = {
      issueId,
      text,
      userEmail: user.email,
      userName: user.name,
      userPhoto: user.photoURL,
      createdAt: new Date()
    };

    await commentsCollection.insertOne(comment);

    res.status(201).json({ message: 'Comment added successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Comments for Issue
app.get('/issues/:id/comments', ensureDB, async (req, res) => {
  try {
    const issueId = req.params.id;
    const comments = await commentsCollection
      .find({ issueId })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(comments);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== DASHBOARD ROUTES ====================

// Get Citizen Dashboard Stats
app.get('/dashboard/stats', ensureDB, verifyToken, async (req, res) => {
  try {
    const email = req.user.email;

    const totalIssues = await issuesCollection.countDocuments({ reportedBy: email });
    const pendingIssues = await issuesCollection.countDocuments({ reportedBy: email, status: 'pending' });
    const inProgressIssues = await issuesCollection.countDocuments({ 
      reportedBy: email, 
      status: { $in: ['in-progress', 'working'] } 
    });
    const resolvedIssues = await issuesCollection.countDocuments({ reportedBy: email, status: 'resolved' });

    res.status(200).json({
      totalIssues,
      pendingIssues,
      inProgressIssues,
      resolvedIssues
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== STAFF ROUTES ====================

// Get Staff Dashboard Stats
app.get('/staff/stats', ensureDB, verifyToken, verifyStaff, async (req, res) => {
  try {
    const email = req.user.email;

    const assignedIssues = await issuesCollection.countDocuments({ assignedTo: email });
    const pendingIssues = await issuesCollection.countDocuments({ assignedTo: email, status: 'pending' });
    const workingIssues = await issuesCollection.countDocuments({ 
      assignedTo: email, 
      status: { $in: ['in-progress', 'working'] } 
    });
    const resolvedIssues = await issuesCollection.countDocuments({ assignedTo: email, status: 'resolved' });

    res.status(200).json({
      assignedIssues,
      pendingIssues,
      workingIssues,
      resolvedIssues
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Staff Assigned Issues
app.get('/staff/issues', ensureDB, verifyToken, verifyStaff, async (req, res) => {
  try {
    const email = req.user.email;
    const { status } = req.query;

    const filter = { assignedTo: email };
    if (status) filter.status = status;

    const issues = await issuesCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Issue Status (Staff)
app.patch('/staff/issues/:id/status', ensureDB, verifyToken, verifyStaff, async (req, res) => {
  try {
    const id = req.params.id;
    const { status, note } = req.body;
    const email = req.user.email;

    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

    if (!issue) {
      return res.status(404).json({ message: 'Issue not found' });
    }

    if (issue.assignedTo !== email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const updateData = {
      status,
      updatedAt: new Date()
    };

    if (status === 'resolved') {
      updateData.resolvedAt = new Date();
    }

    const timelineEntry = {
      status,
      date: new Date(),
      note: note || `Status changed to ${status}`
    };

    await issuesCollection.updateOne(
      { _id: new ObjectId(id) },
      { 
        $set: updateData,
        $push: { timeline: timelineEntry }
      }
    );

    res.status(200).json({ message: 'Status updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Staff Profile
app.patch('/staff/profile', ensureDB, verifyToken, verifyStaff, async (req, res) => {
  try {
    const { name, phoneNumber, photoURL } = req.body;
    const email = req.user.email;

    const updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (photoURL) updateData.photoURL = photoURL;

    await usersCollection.updateOne(
      { email },
      { $set: updateData }
    );

    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get Admin Dashboard Stats
app.get('/admin/stats', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const totalIssues = await issuesCollection.countDocuments();
    const pendingIssues = await issuesCollection.countDocuments({ status: 'pending' });
    const inProgressIssues = await issuesCollection.countDocuments({ 
      status: { $in: ['in-progress', 'working'] } 
    });
    const resolvedIssues = await issuesCollection.countDocuments({ status: 'resolved' });
    const totalUsers = await usersCollection.countDocuments({ role: 'citizen' });
    const premiumUsers = await usersCollection.countDocuments({ isPremium: true });
    const totalStaff = await usersCollection.countDocuments({ role: 'staff' });
    const totalPayments = await paymentsCollection.countDocuments();
    
    // Calculate total revenue
    const paymentsData = await paymentsCollection.find().toArray();
    const totalRevenue = paymentsData.reduce((sum, payment) => sum + (payment.amount || 0), 0);

    // Category-wise issue count
    const categoryStats = await issuesCollection.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]).toArray();

    // Status-wise issue count
    const statusStats = await issuesCollection.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]).toArray();

    res.status(200).json({
      totalIssues,
      pendingIssues,
      inProgressIssues,
      resolvedIssues,
      totalUsers,
      premiumUsers,
      totalStaff,
      totalPayments,
      totalRevenue,
      categoryStats,
      statusStats
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Users (Admin)
app.get('/admin/users', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { limit } = req.query;
    const limitNum = limit ? parseInt(limit) : 0;

    const users = await usersCollection
      .find({ role: 'citizen' })
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .toArray();

    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update User Status (Block/Unblock)
app.patch('/admin/users/:email/status', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const email = req.params.email;
    const { isBlocked } = req.body;

    await usersCollection.updateOne(
      { email },
      { $set: { isBlocked } }
    );

    res.status(200).json({ message: 'User status updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Staff (Admin)
app.get('/admin/staff', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const staff = await usersCollection
      .find({ role: 'staff' })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(staff);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Staff Member (Admin)
app.post('/admin/staff', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email, name, phoneNumber, photoURL } = req.body;

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const newStaff = {
      email,
      name,
      phoneNumber: phoneNumber || null,
      photoURL: photoURL || null,
      role: 'staff',
      isPremium: false,
      isBlocked: false,
      createdAt: new Date()
    };

    await usersCollection.insertOne(newStaff);
    res.status(201).json({ message: 'Staff member created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Staff Member (Admin)
app.put('/admin/staff/:email', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const email = req.params.email;
    const { name, phoneNumber, photoURL } = req.body;

    const updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (photoURL !== undefined) updateData.photoURL = photoURL;

    await usersCollection.updateOne(
      { email },
      { $set: updateData }
    );

    res.status(200).json({ message: 'Staff member updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Staff Member (Admin)
app.delete('/admin/staff/:staffId', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const staffId = req.params.staffId;
    
    await usersCollection.deleteOne({ _id: new ObjectId(staffId) });
    
    res.status(200).json({ message: 'Staff member deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Issues (Admin)
app.get('/admin/issues', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status, category, priority } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (category) filter.category = category;
    if (priority) filter.priority = priority;

    const issues = await issuesCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Assign Issue to Staff (Admin)
app.patch('/admin/issues/:id/assign', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { assignedTo } = req.body;

    const staff = await usersCollection.findOne({ email: assignedTo, role: 'staff' });
    if (!staff) {
      return res.status(404).json({ message: 'Staff member not found' });
    }

    const timelineEntry = {
      status: 'assigned',
      date: new Date(),
      note: `Assigned to ${staff.name}`
    };

    await issuesCollection.updateOne(
      { _id: new ObjectId(id) },
      { 
        $set: { 
          assignedTo: staff.email,
          assignedToName: staff.name,
          status: 'in-progress',
          updatedAt: new Date()
        },
        $push: { timeline: timelineEntry }
      }
    );

    res.status(200).json({ message: 'Issue assigned successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Issue Priority (Admin)
app.patch('/admin/issues/:id/priority', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { priority } = req.body;

    await issuesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { priority, updatedAt: new Date() } }
    );

    res.status(200).json({ message: 'Priority updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Payments (Admin)
app.get('/admin/payments', ensureDB, verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { limit } = req.query;
    const limitNum = limit ? parseInt(limit) : 0;

    const payments = await paymentsCollection
      .find()
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .toArray();

    res.status(200).json(payments);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create Payment Intent (Stripe)
app.post('/create-payment-intent', ensureDB, verifyToken, async (req, res) => {
  try {
    const { amount } = req.body;

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100, // Convert to cents
      currency: 'usd',
      payment_method_types: ['card'],
    });

    res.status(200).json({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error('Payment intent error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update User to Premium
app.patch('/users/:email/premium', ensureDB, verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const { transactionId, amount, paymentMethod } = req.body;

    if (req.user.email !== email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    // Save payment record
    await paymentsCollection.insertOne({
      userId: email,
      amount,
      transactionId,
      paymentMethod,
      status: 'completed',
      createdAt: new Date()
    });

    // Update user to premium
    await usersCollection.updateOne(
      { email },
      { $set: { isPremium: true } }
    );

    res.status(200).json({ message: 'Premium subscription activated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User Payments
app.get('/payments/my-payments', ensureDB, verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const payments = await paymentsCollection
      .find({ userId: email })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json(payments);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== PUBLIC ROUTES ====================

// Get Latest Resolved Issues (Public)
app.get('/public/latest-resolved', ensureDB, async (req, res) => {
  try {
    const issues = await issuesCollection
      .find({ status: 'resolved' })
      .sort({ resolvedAt: -1 })
      .limit(10)
      .toArray();

    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Root Route
app.get('/', (req, res) => {
  res.send('CityWatch API is running!');
});

// Start Server (only in non-production)
if (process.env.NODE_ENV !== 'production') {
  connectDB().then(() => {
    app.listen(port, () => {
      console.log(`🚀 Server is running on port ${port}`);
    });
  }).catch(console.error);
}

// Export for Vercel serverless
export default app;
