const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Initialize Stripe only if key exists
let stripe;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
}

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
  }
} catch {}

const verifyFBToken = async (req, res, next) => {
  if (!firebaseInitialized) {
    req.email = "test@example.com";
    return next();
  }

  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "unauthorized" });

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.email = decoded.email;
    next();
  } catch {
    res.status(401).send({ message: "unauthorized" });
  }
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
  await client.connect();

  const db = client.db("CityWatch");
  const users = db.collection("users");
  const issues = db.collection("issues");
  const payments = db.collection("payments");

  const verifyAdmin = async (req, res, next) => {
    const user = await users.findOne({ email: req.email });
    if (!user || user.role !== "admin") {
      return res.status(403).send({ message: "admin only" });
    }
    next();
  };

  const verifyStaff = async (req, res, next) => {
    const user = await users.findOne({ email: req.email });
    if (!user || user.role !== "staff") {
      return res.status(403).send({ message: "staff only" });
    }
    next();
  };

  // USERS
  app.post("/users", async (req, res) => {
    const exists = await users.findOne({ email: req.body.email });
    if (exists) return res.send(exists);

    res.send(
      await users.insertOne({
        ...req.body,
        role: "citizen",
        isPremium: false,
        isBlocked: false,
        issueCount: 0,
        createdAt: new Date(),
      })
    );
  });

  app.get("/users/:email", verifyFBToken, async (req, res) => {
    if (req.params.email !== req.email)
      return res.status(403).send({ message: "forbidden" });

    const user = await users.findOne({ email: req.email });
    res.send(user);
  });

  app.patch("/users/:email", verifyFBToken, async (req, res) => {
    if (req.params.email !== req.email)
      return res.status(403).send({ message: "forbidden" });

    res.send(await users.updateOne({ email: req.email }, { $set: req.body }));
  });


  // Create payment intent for premium subscription
  app.post(
    "/create-payment-intent/premium",
    verifyFBToken,
    async (req, res) => {
      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: 1000, // $10.00 USD
          currency: "usd",
          metadata: {
            userEmail: req.email,
            type: "premium",
          },
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        res.status(400).send({ message: error.message });
      }
    }
  );

  // Create payment intent for boost issue
  app.post("/create-payment-intent/boost", verifyFBToken, async (req, res) => {
    try {
      const { issueId } = req.body;

      const paymentIntent = await stripe.paymentIntents.create({
        amount: 100, 
        currency: "usd",
        metadata: {
          userEmail: req.email,
          type: "boost",
          issueId,
        },
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    } catch (error) {
      res.status(400).send({ message: error.message });
    }
  });

  app.patch("/users/:email/premium", verifyFBToken, async (req, res) => {
    if (req.params.email !== req.email)
      return res.status(403).send({ message: "forbidden" });

    const { transactionId } = req.body;

    await payments.insertOne({
      type: "premium",
      amount: 1000,
      userEmail: req.email,
      transactionId: transactionId || `premium_${Date.now()}`,
      createdAt: new Date(),
    });

    res.send(
      await users.updateOne({ email: req.email }, { $set: { isPremium: true } })
    );
  });

  // ISSUES
  app.get("/issues", async (req, res) => {
    const {
      category,
      status,
      priority,
      search,
      page = 1,
      limit = 10,
    } = req.query;
    const query = {};

    if (category) query.category = category;
    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await issues.countDocuments(query);

    const allIssues = await issues
      .find(query)
      .sort({ priority: -1, createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    res.send({
      issues: allIssues,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
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
    res.send(
      await issues
        .find({ citizenEmail: req.email })
        .sort({ createdAt: -1 })
        .toArray()
    );
  });

  app.get("/issues/:id", async (req, res) => {
    res.send(await issues.findOne({ _id: new ObjectId(req.params.id) }));
  });

  app.post("/issues", verifyFBToken, async (req, res) => {
    const user = await users.findOne({ email: req.email });
    if (!user || user.isBlocked)
      return res.status(403).send({ message: "blocked" });

    if (!user.isPremium && user.issueCount >= 3)
      return res.status(403).send({ message: "limit exceeded" });

    const issue = {
      ...req.body,
      citizenEmail: req.email,
      citizenName: user.displayName || "Citizen",
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

    await users.updateOne({ email: req.email }, { $inc: { issueCount: 1 } });

    res.send(await issues.insertOne(issue));
  });

  app.patch("/issues/:id", verifyFBToken, async (req, res) => {
    const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
    if (
      !issue ||
      issue.citizenEmail !== req.email ||
      issue.status !== "Pending"
    )
      return res.status(403).send({ message: "forbidden" });

    res.send(await issues.updateOne({ _id: issue._id }, { $set: req.body }));
  });

  app.delete("/issues/:id", verifyFBToken, async (req, res) => {
    const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
    if (!issue || issue.citizenEmail !== req.email)
      return res.status(403).send({ message: "forbidden" });

    await users.updateOne({ email: req.email }, { $inc: { issueCount: -1 } });

    res.send(await issues.deleteOne({ _id: issue._id }));
  });

  app.post("/issues/:id/upvote", verifyFBToken, async (req, res) => {
    const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
    if (
      !issue ||
      issue.citizenEmail === req.email ||
      issue.upvotedBy.includes(req.email)
    )
      return res.status(400).send({ message: "invalid upvote" });

    res.send(
      await issues.updateOne(
        { _id: issue._id },
        { $inc: { upvotes: 1 }, $push: { upvotedBy: req.email } }
      )
    );
  });

  app.post("/issues/:id/boost", verifyFBToken, async (req, res) => {
    const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
    if (!issue || issue.isBoosted)
      return res.status(400).send({ message: "invalid boost" });

    const { transactionId } = req.body;

    await payments.insertOne({
      type: "boost",
      amount: 100,
      userEmail: req.email,
      issueId: issue._id,
      issueTitle: issue.title,
      transactionId: transactionId || `boost_${Date.now()}`,
      createdAt: new Date(),
    });

    res.send(
      await issues.updateOne(
        { _id: issue._id },
        {
          $set: { priority: "High", isBoosted: true },
          $push: {
            timeline: {
              status: issue.status,
              message: "Issue boosted",
              updatedBy: "Citizen",
              date: new Date(),
            },
          },
        }
      )
    );
  });

  // DASHBOARD
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

  // STAFF
  app.get("/staff/issues", verifyFBToken, verifyStaff, async (req, res) => {
    res.send(
      await issues
        .find({ assignedStaff: req.email })
        .sort({ priority: -1 })
        .toArray()
    );
  });

  app.patch(
    "/staff/issues/:id/status",
    verifyFBToken,
    verifyStaff,
    async (req, res) => {
      const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
      if (!issue || issue.assignedStaff !== req.email)
        return res.status(403).send({ message: "forbidden" });

      res.send(
        await issues.updateOne(
          { _id: issue._id },
          {
            $set: { status: req.body.status },
            $push: {
              timeline: {
                status: req.body.status,
                message: "Status updated",
                updatedBy: "Staff",
                date: new Date(),
              },
            },
          }
        )
      );
    }
  );

  // ADMIN
  app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
    res.send({
      totalIssues: await issues.countDocuments(),
      pendingIssues: await issues.countDocuments({ status: "Pending" }),
      resolvedIssues: await issues.countDocuments({ status: "Resolved" }),
      totalPayments: (await payments.find().toArray()).reduce(
        (s, p) => s + p.amount,
        0
      ),
    });
  });

  app.get("/admin/issues", verifyFBToken, verifyAdmin, async (req, res) => {
    res.send(await issues.find().sort({ createdAt: -1 }).toArray());
  });

  app.patch(
    "/admin/issues/:id/assign",
    verifyFBToken,
    verifyAdmin,
    async (req, res) => {
      const issue = await issues.findOne({ _id: new ObjectId(req.params.id) });
      if (!issue || issue.assignedStaff)
        return res.status(400).send({ message: "invalid" });

      res.send(
        await issues.updateOne(
          { _id: issue._id },
          {
            $set: {
              assignedStaff: req.body.staffEmail,
              assignedStaffName: req.body.staffName,
            },
            $push: {
              timeline: {
                status: issue.status,
                message: `Assigned to staff ${req.body.staffName}`,
                updatedBy: "Admin",
                date: new Date(),
              },
            },
          }
        )
      );
    }
  );

  app.patch(
    "/admin/issues/:id/reject",
    verifyFBToken,
    verifyAdmin,
    async (req, res) => {
      res.send(
        await issues.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: { status: "Rejected" },
            $push: {
              timeline: {
                status: "Rejected",
                message: req.body.reason || "Rejected by admin",
                updatedBy: "Admin",
                date: new Date(),
              },
            },
          }
        )
      );
    }
  );

  app.get("/admin/users", verifyFBToken, verifyAdmin, async (req, res) => {
    res.send(await users.find({ role: "citizen" }).toArray());
  });

  app.patch(
    "/admin/users/:email/block",
    verifyFBToken,
    verifyAdmin,
    async (req, res) => {
      res.send(
        await users.updateOne(
          { email: req.params.email },
          { $set: { isBlocked: req.body.isBlocked } }
        )
      );
    }
  );

  app.get("/admin/payments", verifyFBToken, verifyAdmin, async (req, res) => {
    res.send(await payments.find().sort({ createdAt: -1 }).toArray());
  });

  // Get all staff
  app.get("/admin/staff", verifyFBToken, verifyAdmin, async (req, res) => {
    res.send(
      await users.find({ role: "staff" }).sort({ createdAt: -1 }).toArray()
    );
  });

  // Create staff
  app.post("/admin/staff", verifyFBToken, verifyAdmin, async (req, res) => {
    const { email, displayName, phoneNumber, photoURL, password } = req.body;

    try {
      // Create in Firebase Auth (if initialized)
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
        // Delete from Firebase Auth
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

  // ==================== STAFF ROUTES ====================

  // Staff Dashboard Stats
  app.get("/staff/stats", verifyFBToken, verifyStaff, async (req, res) => {
    const assignedIssues = await issues.countDocuments({
      assignedStaff: req.email,
    });
    const resolvedIssues = await issues.countDocuments({
      assignedStaff: req.email,
      status: "Resolved",
    });

    // Today's tasks (created today or updated today)
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayTasks = await issues.countDocuments({
      assignedStaff: req.email,
      status: { $in: ["Pending", "In-Progress"] },
      $or: [{ createdAt: { $gte: today } }, { updatedAt: { $gte: today } }],
    });

    res.send({
      assignedIssues,
      resolvedIssues,
      todayTasks,
    });
  });

  // Get staff assigned issues
  app.get("/staff/issues", verifyFBToken, verifyStaff, async (req, res) => {
    const { status, priority, category } = req.query;
    const query = { assignedStaff: req.email };

    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (category) query.category = category;

    const assignedIssues = await issues
      .find(query)
      .sort({ priority: -1, createdAt: -1 })
      .toArray();

    res.send(assignedIssues);
  });

  // Staff change issue status
  app.patch(
    "/staff/issues/:id/status",
    verifyFBToken,
    verifyStaff,
    async (req, res) => {
      const { status, message } = req.body;

      const issue = await issues.findOne({
        _id: new ObjectId(req.params.id),
        assignedStaff: req.email,
      });

      if (!issue) {
        return res
          .status(404)
          .send({ message: "not found or not assigned to you" });
      }

      // Validate status transitions
      const validTransitions = {
        Pending: ["In-Progress"],
        "In-Progress": ["Working"],
        Working: ["Resolved"],
        Resolved: ["Closed"],
      };

      if (!validTransitions[issue.status]?.includes(status)) {
        return res.status(400).send({ message: "invalid status transition" });
      }

      const result = await issues.updateOne(
        { _id: issue._id },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
          $push: {
            timeline: {
              status,
              message: message || `Status changed to ${status}`,
              updatedBy: "Staff",
              date: new Date(),
            },
          },
        }
      );

      res.send(result);
    }
  );

  // Staff update profile
  app.patch("/staff/profile", verifyFBToken, verifyStaff, async (req, res) => {
    const { displayName, phoneNumber, photoURL } = req.body;
    const updateData = {};

    if (displayName) updateData.displayName = displayName;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (photoURL) updateData.photoURL = photoURL;

    const result = await users.updateOne(
      { email: req.email, role: "staff" },
      { $set: updateData }
    );

    res.send(result);
  });
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.json({ message: "CityWatch API running" });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
