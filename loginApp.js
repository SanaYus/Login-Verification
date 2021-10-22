//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

//using express
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//connet to db
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//make a schema for user info
const userSchema = new mongoose.Schema ({
  email: { type: String, unique: true },
  isVerified: { type: Boolean, default: false },
  password: String,
  googleId: String,
  secret: String
});

//token for verification
const tokenSchema = new mongoose.Schema({
  _userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  token: { type: String, required: true },
  expireAt: { type: Date, default: Date.now, index: { expires: 86400000 } }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//model for schema
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//homepage
app.get("/", function(req, res){
  res.render("home");
});

//signin w google 
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

//signin w google (login)
app.get("/auth/google/secret",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secret");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

//if user is found and authenticated, post the secret attached to them
app.get("/secret", function(req, res){
  User.find({"secret": {$ne: null}/*secret field is none*/}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) { //if users dont have a null field
        res.render("secret", {usersWithSecrets: foundUsers});
      }
    }
  });
});

//is user session is ongoing, render submit
app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//post a secret
app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secret");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

//register page
app.post("/register", function(req, res){

  
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secret");
      });
    }
  });
});

//login page
app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secret");
      });
    }
  });
});







app.listen(3000, function() {
  console.log("Server started on port 3000.");
});




