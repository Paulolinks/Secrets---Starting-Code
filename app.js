// Import and configure dotenv
import dotenv from "dotenv"; // store Password in this file .env
dotenv.config(); // starting
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt"; // ecripting passward before store in database

//deixando o DB mais seguro
// Now you can access environment variables
const { DB_USER, DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT } = process.env;
// Configuring PostgreSQL connection
const db = new pg.Client({
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASSWORD,
  port: DB_PORT,
});
console.log(process.env.API_KEY);

// // Hashing a password - usar na hora de receber passward do usuario e codificar -> colocar dentro de app.post
// const hashedPassword = await bcrypt.hash("password", 10);
// // Verifying a password - descodificar e verificar -> colocar dentro de app.post
// const isPasswordValid = await bcrypt.compare("password", hashedPassword);

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

// Registrar password encryptado para o banco de dados
app.post("/register", async function (req, res) {
  const { username, password } = req.body;
  try {
    // Hashing a password - usar na hora de receber passward do usuario e codificar
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a SQL query to update the data in the "client_contact" table
    const query = `
        INSERT INTO users (username, password)
        VALUES ($1, $2)
        RETURNING user_id
      `;

    // Store the hashed password
    const result = await db.query(query, [username, hashedPassword]);
    res.redirect("/secrets");
    console.log("Username:" + username + "Password:" + password);
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
  // if theres a user than check password
  if (user) {
    //Verifying a password - descodificar e verificar senha in login
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
