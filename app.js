//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(express.urlencoded({extended:true}));

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email: String,
  password:String
});



const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res){
  res.render("home");
});
app.get("/register",function(req,res){
  res.render("register");
});
app.get("/login",function(req,res){
  res.render("login");
});

app.post("/register",function(req,res){

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });
    newUser.save(function(err){
      if(!err){
        res.render("secrets");
      }else{
        console.log(err);
      }
    });
  });
});

app.post("/login",function(req,res){
  const email = req.body.username;
  const password = req.body.password;
  User.findOne({email: email},function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
          if(result === true){
            res.render("secrets");
          }else{
            res.send("Couldn't find the user.Please verify your details.");
          }
      });
    }
  });
});

app.listen(3000,function(){
  console.log("This server is running just fine.");
});
