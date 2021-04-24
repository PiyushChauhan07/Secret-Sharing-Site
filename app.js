//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//Passport-Local Mongoose is a Mongoose plugin that simplifies building username and password login with Passport.

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(express.urlencoded({extended:true}));

///////// Session data is not saved in the cookie itself, just the session ID. Session data is stored server-side./////////
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

//////////////////   More info. on passport.js    /////////////////////
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true); //deprication in mongoose

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String
});

userSchema.plugin(passportLocalMongoose);  ///Add plm as plugin to userSchema to use.
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy()); //to authenticate users using their username and password

// passport.serializeUser(User.serializeUser()); //allows passport to enter userdetails(only user ID) to the cookie.
// passport.deserializeUser(User.deserializeUser()); //allows to retreive user details from the cookie to authenticate user on our server.

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
    callbackURL: "http://localhost:3000/auth/google/secrets", ///where to redirect after google authenticates a user
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});
app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] })
);
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});
app.get("/register",function(req,res){
  res.render("register");
});
app.get("/login",function(req,res){
  res.render("login");
});
app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/register",function(req,res){
  User.register({username: req.body.username}, req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
///////////   Authenticate the username/password entered by user using local strategy.   /////////////
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login",function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    }else{
///////////   Authenticate the username/password entered by user using local strategy.   /////////////
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000,function(){
  console.log("This server is running just fine.");
});
