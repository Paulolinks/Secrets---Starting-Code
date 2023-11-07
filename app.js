//Authentication and Security LEVEL 6
// Import and configure dotenv - arquivo .env onde fica nossas senhas
import dotenv from "dotenv"; // Store sensitive data in this .env file
dotenv.config(); // Initialize .env

import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import session from "express-session"; //save in cookie
import passport from "passport";
import { Sequelize, DataTypes } from "sequelize";
import bcrypt from "bcrypt";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

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
    secret: "YourSessionSecretHere",
    resave: false, //1
    saveUninitialized: false, //1
  })
);

//login
app.use(passport.initialize());
app.use(passport.session());

// Connect to the PostgreSQL database
// Create a Sequelize instance and define your User model
const sequelize = new Sequelize("User-secret", "postgres", "fl123", {
  host: "localhost",
  dialect: "postgres",
});
//table collun in banco de dados para encryptar e armazenar
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
  googleId: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  secret: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});
// Synchronize the models with the database
sequelize
  .sync()
  .then(() => {
    console.log("PostgreSQL Database synchronized");
  })
  .catch((error) => {
    console.error("Error synchronizing database:", error);
  });

// check password in login
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
// Login with google account - API -google auth 20
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile); // check user
      //create a user in PostgreSQL data base
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);
//home pag
app.get("/", function (req, res) {
  res.render("home.ejs");
});
// login with google account - authentication with google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
//send user to page after authentication with google
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login.ejs");
});

app.get("/register", function (req, res) {
  res.render("register.ejs");
});

// If is authenticated keep in secret pag othewise /loging page
app.get("/secrets", function (req, res) {
  User.findAll({
    where: {
      secret: {
        [Sequelize.Op.not]: null, // Use Sequelize's not operator to find non-null secrets
      },
    },
  })
    .then((foundUsers) => {
      res.render("secrets", { usersWithSecrets: foundUsers });
    })
    .catch((err) => {
      console.log(err);
      // Handle the error appropriately
      res.redirect("/error");
    });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

// submit your secret find the user Id and insert the secret to database - collunm secret in table
app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const userId = req.user.id; // Get the user's ID from the authenticated session

  User.findByPk(userId)
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        return foundUser.save();
      }
    })
    .then(() => {
      res.redirect("/secrets");
    })
    .catch((err) => {
      console.error(err);
      res.redirect("/error"); // Handle the error gracefully
    });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    res.redirect("/");
  });
});

//register
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

    // Use the "User" Sequelize model to create a new user
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
        console.error("Error inserting user:", err);
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
