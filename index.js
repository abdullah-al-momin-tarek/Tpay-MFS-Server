const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
  })
);
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
    // Connect the client to the server (optional starting in v4.7)
    // await client.connect();

    // Middleware
    const verifyToken = (req, res, next) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res.status(401).send({ message: "Unauthorized access" });
      }

      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "Unauthorized access" });
        }
        req.user = decoded;
        next();
      });
    };

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
        role: req.body.role,
        status: req.body.status,
        balance: req.body.balance,
      };

      await userCollection.insertOne(user);

      const token = jwt.sign(
        { email: req.body.email },
        process.env.ACCESS_TOKEN_SECRET
      );
      res.send(token);
    });

    app.post("/login", async (req, res) => {
      const { username, password } = req.body;

      // Check if user exists by email or phone number
      const user = await userCollection.findOne({
        $or: [{ email: username }, { phone: username }],
      });

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Compare passwords
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Generate JWT token upon successful login
      const token = jwt.sign(
        { id: user._id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1h" }
      );

      res.json({ token });
    });

    // Ensure the verifyToken middleware is applied to this route
    app.post("/verify-token", verifyToken, async (req, res) => {
      const userEmail = req.user.email;
      const user = await userCollection.findOne({
        email: userEmail,
      });

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const { password, ...userInfo } = user;
      res.send(userInfo);
    });

    app.post("/send", async (req, res) => {
      const { number, amount, id, password } = req.body;

      let parseAmount = parseInt(amount);

      const data = await userCollection.findOne({ _id: new ObjectId(id) });

      //   TODO: uncomment this after done

      //   if (data.status === "pending" || data.status === "block") {
      //     return res.status(404).json({ error: "user is not verified" });
      //   }

      const passwordMatch = await bcrypt.compare(password, data.password);
      console.log(passwordMatch);

      if (!passwordMatch) {
        return res.status(404).json({ error: "Wrong Password" });
      }

      if (parseAmount < 50) {
        return res.status(404).json({ error: "Minimum sending amount 50 tk" });
      }

      const receiverAmount = parseAmount;

      if (parseAmount > 100) {
        const parseAmount = parseAmount + 5;
      }

      if (data.balance < parseAmount) {
        return res
          .status(404)
          .json({ error: "You Don't have sufficient balance" });
      }

      const senderQuery = {
        $set: {
          balance: balance - parseAmount,
        },
      };

      const receiverQuery = {
        $set: {
          balance: balance + receiverAmount,
        },
      };

      const updateSender = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        senderQuery
      );

      const updateReceiver = await userCollection.updateOne(
        { number: number },
        receiverQuery
      );

      res.send(updateSender, updateReceiver);
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
