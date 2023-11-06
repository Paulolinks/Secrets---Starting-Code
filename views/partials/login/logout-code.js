////////////////////////////////////////////////////////////////////////////////////////////////
//LEVEL 5
//Authentication and Security LEVEL 5
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import session from "express-session"; //save in cookie
import passport from "passport";
import { Sequelize, DataTypes } from "sequelize";
import bcrypt from "bcrypt";
import { Strategy as LocalStrategy } from "passport-local";

const app = express();
const port = 3000;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secret: "YourSessionSecretHere", // Replace with your secret
  })
);

//login
app.use(passport.initialize());
app.use(passport.session());

// Connect to the PostgreSQL database
// Create a Sequelize instance and define your User model
// your table
const sequelize = new Sequelize("your-table ", "postgres", "your-password", {
  host: "localhost",
  dialect: "postgres",
});

const User = sequelize.define("users", {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ where: { username: username } }).then((user) => {
      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          return done(err);
        }
        if (!result) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      });
    });
  })
);

// Your Sequelize User model and Passport setup code...
// inserir na db encriptato
passport.serializeUser((user, done) => {
  done(null, user.id); // Use the user's ID
});
// decript
passport.deserializeUser((id, done) => {
  User.findByPk(id)
    .then((user) => {
      done(null, user); // Pass the user  to done
    })
    .catch((err) => {
      done(err, null);
    });
});

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
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    res.redirect("/");
  });
});

//post register
app.post("/register", function (req, res) {
  const { username, password } = req.body;
  // Check if the username and password are provided
  if (!username || !password) {
    return res.redirect("/register");
  }
  // Create a new user with Sequelize and hash the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.log(err);
      return res.redirect("/register");
    }
    User.create({
      username: username,
      password: hash,
    })
      .then((user) => {
        // Log in the newly registered user
        req.login(user, function (err) {
          if (err) {
            console.log(err);
            return res.redirect("/register");
          }
          return res.redirect("/secrets");
        });
      })
      .catch((err) => {
        console.log(err);
        return res.redirect("/register");
      });
  });
});

// Post to  login with authentication to check database
app.post("/login", function (req, res) {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      console.error(err);
      return res.redirect("/login");
    }
    if (!user) {
      console.error("Authentication failed");
      return res.redirect("/login");
    }
    req.login(user, function (err) {
      if (err) {
        console.error(err);
        return res.redirect("/login");
      }
      console.log("User logged in:", user.username);
      return res.redirect("/secrets");
    });
  })(req, res);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}.`);
});
//teste
////////////////////////////////Authentication and Security LEVEL 4///////////////////////////////////////////////////////////
////Authentication and Security LEVEL 4

// Import and configure dotenv
import dotenv from "dotenv"; // Store sensitive data in this .env file
dotenv.config(); // Initialize .env

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";

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
