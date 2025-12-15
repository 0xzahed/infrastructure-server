const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// CORS configuration - allow requests from your frontend
app.use(cors({
  origin: ['http://localhost:5173', 'https://your-frontend-domain.vercel.app'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Initialize Firebase only if service key is provided
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

    // Test the connection
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Successfully connected to MongoDB!");

    const db = client.db("citywatch_db");
    const users = db.collection("users");
    const issues = db.collection("issues");

    console.log("Database: citywatch_db");
    console.log("Collections: users, issues");

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

      res.send(await users.findOne({ email: req.email }));
    });

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

      if (user.isBlocked) return res.status(403).send({ message: "blocked" });
      if (!user.isPremium && user.issueCount >= 3)
        return res.status(403).send({ message: "limit exceeded" });

      const issue = {
        ...req.body,
        citizenEmail: req.email,
        citizenName: user.displayName || user.email.split("@")[0], // ADD THIS LINE
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
    app.post("/issues", verifyFBToken, async (req, res) => {
      const user = await users.findOne({ email: req.email });

      if (user.isBlocked) return res.status(403).send({ message: "blocked" });

      if (!user.isPremium && user.issueCount >= 3)
        return res.status(403).send({ message: "limit exceeded" });

      const issue = {
        ...req.body,
        citizenEmail: req.email,
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
                message: "Issue boosted",
                updatedBy: "Citizen",
                date: new Date(),
              },
            },
          }
        )
      );
    });

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
