//Authentication and Security LEVEL 6
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
const sequelize = new Sequelize("your-table ", "postgres", "your-password ", {
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
