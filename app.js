// Import and configure dotenv
import dotenv from "dotenv"; // Store sensitive data in this .env file
dotenv.config(); // Initialize .env

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt";
const saltRounds = 10;

//deixando o DB mais seguro
// Now you can access environment variables
const { DB_USER, DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT } = process.env;
const db = new pg.Client({
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASSWORD,
  port: DB_PORT,
});

const app = express();
const port = 3000;

// Connect to the PostgreSQL database
db.connect((err) => {
  if (err) {
    console.error("Error connecting to PostgreSQL:", err);
  } else {
    console.log("Connected to PostgreSQL");
  }
});

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.get("/", function (req, res) {
  res.render("home.ejs");
});

app.get("/login", function (req, res) {
  res.render("login.ejs");
});

app.get("/register", function (req, res) {
  res.render("register.ejs");
});

app.get("/secrets", function (req, res) {
  res.render("secrets.ejs");
});

// Register user with an MD5-hashed password
app.post("/register", async function (req, res) {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
    const query = `
      INSERT INTO users (username, password)
      VALUES ($1, $2)
      RETURNING user_id
    `;

    const result = await db.query(query, [username, hashedPassword]); // Store the hashed password
    console.log("Username: " + username + " Password :" + hashedPassword);
    res.redirect("/secrets");
  } catch (error) {
    console.error("Error inserting data:", error);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

//checking data base and checking password and username
app.post("/login", async function (req, res) {
  const { username, password } = req.body;

  // Query the database to find a user with the provided username
  const query = "SELECT * FROM users WHERE username = $1";
  const result = await db.query(query, [username]);
  const user = result.rows[0]; // Assuming there is only one user with the provided username

  if (user) {
    const isPasswordValid = await bcrypt.compare(password, user.password); // Verify the password
    if (isPasswordValid) {
      // User with matching credentials found, redirect to the secret page
      res.redirect("/secrets");
    } else {
      console.error("Invalid password");
      res.status(401).json({ success: false, error: "Unauthorized" });
    }
  } else {
    console.error("User not found");
    res.status(401).json({ success: false, error: "Unauthorized" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}.`);
});
//teste
