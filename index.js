const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

let firebaseInitialized = false;
try {
  if (process.env.FB_SERVICE_KEY) {
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
      "utf8"
    );

    admin.initializeApp({
      credential: admin.credential.cert(JSON.parse(decoded)),
    });
    firebaseInitialized = true;
    console.log("Firebase initialized successfully");
  } else {
    console.warn("Firebase service key not found - authentication disabled");
  }
} catch (error) {
  console.warn(
    "Firebase initialization failed - authentication disabled:",
    error.message
  );
}

const verifyFBToken = async (req, res, next) => {
  if (!firebaseInitialized) {
    console.warn("Firebase not initialized - skipping authentication");
    req.email = "test@example.com";
    return next();
  }

  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "unauthorized" });

  try {
    const idToken = token.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.email = decodedToken.email;
    next();
  } catch {
    res.status(401).send({ message: "unauthorized" });
  }
};

// Role-based middleware
const verifyAdmin = async (req, res, next) => {
  const user = await client
    .db("CityWatch")
    .collection("users")
    .findOne({ email: req.email });
  if (!user || user.role !== "admin") {
    return res.status(403).send({ message: "forbidden: admin only" });
  }
  next();
};

const verifyStaff = async (req, res, next) => {
  const user = await client
    .db("CityWatch")
    .collection("users")
    .findOne({ email: req.email });
  if (!user || user.role !== "staff") {
    return res.status(403).send({ message: "forbidden: staff only" });
  }
  next();
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@citywatch.fc5uov6.mongodb.net/?appName=CityWatch`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    console.log("Connecting to MongoDB...");
    await client.connect();

    await client.db("admin").command({ ping: 1 });
    console.log("✅ Successfully connected to MongoDB!");

    const db = client.db("CityWatch");
    const users = db.collection("users");
    const issues = db.collection("issues");
    const payments = db.collection("payments");

    console.log("Database: CityWatch");
    console.log("Collections: users, issues, payments");

    // ==================== USER ROUTES ====================

    app.post("/users", async (req, res) => {
      const exists = await users.findOne({ email: req.body.email });
      if (exists) return res.send(exists);

      const user = {
        ...req.body,
        role: "citizen",
        isPremium: false,
        isBlocked: false,
        issueCount: 0,
        createdAt: new Date(),
      };

      res.send(await users.insertOne(user));
    });

    app.get("/users/:email", verifyFBToken, async (req, res) => {
      if (req.params.email !== req.email)
        return res.status(403).send({ message: "forbidden" });

      let user = await users.findOne({ email: req.email });

      // Auto-create user in dev mode
      if (!user) {
        const newUser = {
          email: req.email,
          displayName: "Test User",
          role: "citizen",
          isPremium: false,
          isBlocked: false,
          issueCount: 0,
          createdAt: new Date(),
        };
        await users.insertOne(newUser);
        user = newUser;
      }

      res.send(user);
    });

    // ✅ NEW: Update user profile
    app.patch("/users/:email", verifyFBToken, async (req, res) => {
      if (req.params.email !== req.email)
        return res.status(403).send({ message: "forbidden" });

      // Auto-create user in dev mode
      let user = await users.findOne({ email: req.email });
      if (!user) {
        const newUser = {
          email: req.email,
          displayName: "Test User",
          role: "citizen",
          isPremium: false,
          isBlocked: false,
          issueCount: 0,
          createdAt: new Date(),
        };
        await users.insertOne(newUser);
      }

      const { displayName, phoneNumber, photoURL } = req.body;
      const updateData = {};

      if (displayName !== undefined) updateData.displayName = displayName;
      if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
      if (photoURL !== undefined) updateData.photoURL = photoURL;

      const result = await users.updateOne(
        { email: req.email },
        { $set: updateData }
      );

      res.send(result);
    });

    // ✅ NEW: Upgrade to premium
    app.patch("/users/:email/premium", verifyFBToken, async (req, res) => {
      if (req.params.email !== req.email)
        return res.status(403).send({ message: "forbidden" });

      // Auto-create user in dev mode
      let user = await users.findOne({ email: req.email });
      if (!user) {
        const newUser = {
          email: req.email,
          displayName: "Test User",
          role: "citizen",
          isPremium: false,
          isBlocked: false,
          issueCount: 0,
          createdAt: new Date(),
        };
        await users.insertOne(newUser);
      }

      // Save payment record
      const payment = {
        type: "premium",
        amount: 1000,
        userEmail: req.email,
        transactionId: req.body.transactionId || `premium_${Date.now()}`,
        status: "completed",
        createdAt: new Date(),
      };
      await payments.insertOne(payment);

      const result = await users.updateOne(
        { email: req.email },
        {
          $set: {
            isPremium: true,
            upgradedAt: new Date(),
          },
        }
      );

      res.send(result);
    });

    // ==================== ISSUE ROUTES ====================

    app.get("/issues", async (req, res) => {
      const { category, status, priority, search } = req.query;
      const query = {};

      if (category) query.category = category;
      if (status) query.status = status;
      if (priority) query.priority = priority;
      if (search) {
        query.$or = [
          { title: { $regex: search, $options: "i" } },
          { location: { $regex: search, $options: "i" } },
        ];
      }

      const result = await issues
        .find(query)
        .sort({ priority: -1, createdAt: -1 })
        .toArray();

      res.send(result);
    });

    app.get("/issues/latest-resolved", async (req, res) => {
      res.send(
        await issues
          .find({ status: "Resolved" })
          .sort({ updatedAt: -1 })
          .limit(6)
          .toArray()
      );
    });

    app.get("/issues/my-issues", verifyFBToken, async (req, res) => {
      const { status } = req.query;
      const query = { citizenEmail: req.email };

      if (status) query.status = status;

      res.send(await issues.find(query).sort({ createdAt: -1 }).toArray());
    });

    app.get("/issues/:id", async (req, res) => {
      res.send(await issues.findOne({ _id: new ObjectId(req.params.id) }));
    });

    // ✅ FIXED: Single POST /issues endpoint with citizenName
    app.post("/issues", verifyFBToken, async (req, res) => {
      let user = await users.findOne({ email: req.email });

      // Create test user if not exists (dev mode)
      if (!user) {
        const testUser = {
          email: req.email,
          displayName: "Test User",
          role: "citizen",
          isPremium: false,
          isBlocked: false,
          issueCount: 0,
          createdAt: new Date(),
        };
        await users.insertOne(testUser);
        user = testUser;
      }

      if (user.isBlocked) return res.status(403).send({ message: "blocked" });

      if (!user.isPremium && user.issueCount >= 3)
        return res.status(403).send({ message: "limit exceeded" });

      const issue = {
        ...req.body,
        citizenEmail: req.email,
        citizenName: user.displayName || user.email.split("@")[0],
        status: "Pending",
        priority: "Normal",
        upvotes: 0,
        upvotedBy: [],
        isBoosted: false,
        createdAt: new Date(),
        timeline: [
          {
            status: "Pending",
            message: "Issue reported by citizen",
            updatedBy: "Citizen",
            date: new Date(),
          },
        ],
      };

      const result = await issues.insertOne(issue);
      await users.updateOne({ email: req.email }, { $inc: { issueCount: 1 } });

      res.send(result);
    });

    app.patch("/issues/:id", verifyFBToken, async (req, res) => {
      const issue = await issues.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!issue) return res.status(404).send({ message: "not found" });
      if (issue.citizenEmail !== req.email)
        return res.status(403).send({ message: "forbidden" });
      if (issue.status !== "Pending")
        return res.status(400).send({ message: "not editable" });

      res.send(await issues.updateOne({ _id: issue._id }, { $set: req.body }));
    });

    app.delete("/issues/:id", verifyFBToken, async (req, res) => {
      const issue = await issues.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!issue) return res.status(404).send({ message: "not found" });
      if (issue.citizenEmail !== req.email)
        return res.status(403).send({ message: "forbidden" });

      await users.updateOne({ email: req.email }, { $inc: { issueCount: -1 } });

      res.send(await issues.deleteOne({ _id: issue._id }));
    });

    app.post("/issues/:id/upvote", verifyFBToken, async (req, res) => {
      const issue = await issues.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (issue.citizenEmail === req.email)
        return res.status(400).send({ message: "own issue" });

      if (issue.upvotedBy.includes(req.email))
        return res.status(400).send({ message: "already voted" });

      res.send(
        await issues.updateOne(
          { _id: issue._id },
          {
            $inc: { upvotes: 1 },
            $push: { upvotedBy: req.email },
          }
        )
      );
    });

    app.post("/issues/:id/boost", verifyFBToken, async (req, res) => {
      const issue = await issues.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (issue.isBoosted)
        return res.status(400).send({ message: "already boosted" });

      // Save payment record
      const payment = {
        type: "boost",
        amount: 100,
        userEmail: req.email,
        issueId: issue._id,
        issueTitle: issue.title,
        transactionId: req.body.transactionId || `boost_${Date.now()}`,
        status: "completed",
        createdAt: new Date(),
      };
      await payments.insertOne(payment);

      res.send(
        await issues.updateOne(
          { _id: issue._id },
          {
            $set: {
              priority: "High",
              isBoosted: true,
              boostedAt: new Date(),
            },
            $push: {
              timeline: {
                status: issue.status,
                message: "Issue boosted to high priority",
                updatedBy: "Citizen",
                date: new Date(),
              },
            },
          }
        )
      );
    });

    // ==================== DASHBOARD ROUTES ====================

    app.get("/dashboard/stats", verifyFBToken, async (req, res) => {
      const email = req.email;

      res.send({
        totalIssues: await issues.countDocuments({ citizenEmail: email }),
        pendingIssues: await issues.countDocuments({
          citizenEmail: email,
          status: "Pending",
        }),
        inProgressIssues: await issues.countDocuments({
          citizenEmail: email,
          status: "In-Progress",
        }),
        resolvedIssues: await issues.countDocuments({
          citizenEmail: email,
          status: "Resolved",
        }),
      });
    });

    // Get user payments
    app.get("/dashboard/payments", verifyFBToken, async (req, res) => {
      const userPayments = await payments
        .find({ userEmail: req.email })
        .sort({ createdAt: -1 })
        .toArray();

      const totalPayments = userPayments.reduce(
        (sum, payment) => sum + payment.amount,
        0
      );

      res.send({
        payments: userPayments,
        totalPayments,
      });
    });

    // ==================== ADMIN ROUTES ====================

    // Admin Dashboard Stats
    app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
      const totalIssues = await issues.countDocuments();
      const resolvedIssues = await issues.countDocuments({
        status: "Resolved",
      });
      const pendingIssues = await issues.countDocuments({ status: "Pending" });
      const rejectedIssues = await issues.countDocuments({
        status: "Rejected",
      });

      const allPayments = await payments.find().toArray();
      const totalPayments = allPayments.reduce(
        (sum, payment) => sum + payment.amount,
        0
      );

      const latestIssues = await issues
        .find()
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      const latestPayments = await payments
        .find()
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      const latestUsers = await users
        .find({ role: "citizen" })
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      res.send({
        totalIssues,
        resolvedIssues,
        pendingIssues,
        rejectedIssues,
        totalPayments,
        latestIssues,
        latestPayments,
        latestUsers,
      });
    });

    // Get all issues for admin (with pagination)
    app.get("/admin/issues", verifyFBToken, verifyAdmin, async (req, res) => {
      const { page = 1, limit = 10, status, priority, category } = req.query;
      const query = {};

      if (status) query.status = status;
      if (priority) query.priority = priority;
      if (category) query.category = category;

      const skip = (parseInt(page) - 1) * parseInt(limit);

      const allIssues = await issues
        .find(query)
        .sort({ priority: -1, createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray();

      const total = await issues.countDocuments(query);

      res.send({
        issues: allIssues,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
      });
    });

    // Assign staff to issue
    app.patch(
      "/admin/issues/:id/assign",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { staffEmail, staffName } = req.body;

        const issue = await issues.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!issue) return res.status(404).send({ message: "not found" });

        if (issue.assignedStaff) {
          return res.status(400).send({ message: "already assigned" });
        }

        const result = await issues.updateOne(
          { _id: issue._id },
          {
            $set: {
              assignedStaff: staffEmail,
              assignedStaffName: staffName,
              assignedAt: new Date(),
            },
            $push: {
              timeline: {
                status: issue.status,
                message: `Issue assigned to Staff: ${staffName}`,
                updatedBy: "Admin",
                date: new Date(),
              },
            },
          }
        );

        res.send(result);
      }
    );

    // Reject issue (only pending)
    app.patch(
      "/admin/issues/:id/reject",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const issue = await issues.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!issue) return res.status(404).send({ message: "not found" });
        if (issue.status !== "Pending") {
          return res
            .status(400)
            .send({ message: "only pending can be rejected" });
        }

        const result = await issues.updateOne(
          { _id: issue._id },
          {
            $set: {
              status: "Rejected",
              rejectedAt: new Date(),
            },
            $push: {
              timeline: {
                status: "Rejected",
                message: req.body.reason || "Issue rejected by admin",
                updatedBy: "Admin",
                date: new Date(),
              },
            },
          }
        );

        res.send(result);
      }
    );

    // Get all citizens
    app.get("/admin/users", verifyFBToken, verifyAdmin, async (req, res) => {
      const citizens = await users
        .find({ role: "citizen" })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(citizens);
    });

    // Block/Unblock user
    app.patch(
      "/admin/users/:email/block",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { isBlocked } = req.body;

        const result = await users.updateOne(
          { email: req.params.email },
          { $set: { isBlocked } }
        );

        res.send(result);
      }
    );

    // Get all staff
    app.get("/admin/staff", verifyFBToken, verifyAdmin, async (req, res) => {
      const staff = await users
        .find({ role: "staff" })
        .sort({ createdAt: -1 })
        .toArray();

      res.send(staff);
    });

    // Create staff
    app.post("/admin/staff", verifyFBToken, verifyAdmin, async (req, res) => {
      const { email, password, displayName, phoneNumber, photoURL } = req.body;

      try {
        // Create in Firebase Auth (only if Firebase is enabled)
        if (firebaseInitialized) {
          await admin.auth().createUser({
            email,
            password,
            displayName,
            photoURL,
          });
        }

        // Create in database
        const staff = {
          email,
          displayName,
          phoneNumber,
          photoURL,
          role: "staff",
          createdAt: new Date(),
        };

        const result = await users.insertOne(staff);
        res.send(result);
      } catch (error) {
        res.status(400).send({ message: error.message });
      }
    });

    // Update staff
    app.patch(
      "/admin/staff/:email",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { displayName, phoneNumber, photoURL } = req.body;
        const updateData = {};

        if (displayName) updateData.displayName = displayName;
        if (phoneNumber) updateData.phoneNumber = phoneNumber;
        if (photoURL) updateData.photoURL = photoURL;

        const result = await users.updateOne(
          { email: req.params.email, role: "staff" },
          { $set: updateData }
        );

        res.send(result);
      }
    );

    // Delete staff
    app.delete(
      "/admin/staff/:email",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          // Delete from Firebase Auth (only if Firebase is enabled)
          if (firebaseInitialized) {
            const userRecord = await admin
              .auth()
              .getUserByEmail(req.params.email);
            await admin.auth().deleteUser(userRecord.uid);
          }

          // Delete from database
          const result = await users.deleteOne({
            email: req.params.email,
            role: "staff",
          });

          res.send(result);
        } catch (error) {
          res.status(400).send({ message: error.message });
        }
      }
    );

    // Get all payments (admin)
    app.get("/admin/payments", verifyFBToken, verifyAdmin, async (req, res) => {
      const { type, startDate, endDate } = req.query;
      const query = {};

      if (type) query.type = type;
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      const allPayments = await payments
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();

      res.send(allPayments);
    });
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.json({
    message: "CityWatch API running",
    mongodb: "Connected",
    firebase: firebaseInitialized ? "Enabled" : "Disabled (Dev Mode)",
  });
});

app.listen(port, () => {
  console.log("========================================");
  console.log(`🚀 Server running on port ${port}`);
  console.log(
    `🔧 Firebase Auth: ${
      firebaseInitialized ? "Enabled" : "Disabled (Dev Mode)"
    }`
  );
  console.log("========================================");
});
