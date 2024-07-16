const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require("mongodb");

// middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());

const uri = process.env.DB_URL;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const database = client.db("Tpay-MFS");
const userCollection = database.collection("userCollection");

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    // Middleware
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // JWT
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    app.post("/register", async (req, res) => {
      const userMail = await userCollection.findOne({ email: req.body.email });
      if (userMail) {
        return res.status(400).json({ error: "Sorry email already exist" });
      }

      const userPhone = await userCollection.findOne({ email: req.body.phone });
      if (userPhone) {
        return res.status(400).json({ error: "Sorry number already exist" });
      }

      const salt = await bcrypt.genSalt(10);
      const securePass = await bcrypt.hash(req.body.password, salt);
      console.log(securePass);

      const user = {
        name: req.body.displayName,
        phone: req.body.phone,
        email: req.body.email,
        password: securePass,
      };

      await userCollection.insertOne(user);

      const token = jwt.sign(
        { email: req.body.email },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn: "1h",
        }
      );
      res.send(token);
    });

    app.post("/login", async (req, res) => {
      const { identifier, password } = req.body;

      // Check if user exists by email or phone number
      const user = await userCollection.findOne({
        $or: [{ email: identifier }, { phone: identifier }],
      });

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Compare passwords
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user._id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn: "1h",
        }
      );

      res.json({ token });
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Tpay server running");
});

app.listen(port, () => {
  console.log("Tpay running on port: ", port);
});
