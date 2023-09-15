import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";


//*SERVER
const app = express();

//*DATABASE
mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "backendDB",
  })
  .then(() => {
    console.log("Database Connected");
  }) //there are simple arrow functions inside
  .catch((e) => {
    console.log("error");
  });

// defining the schema for users
const UsrSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});
// defining the schema for messages
const msgSchema = new mongoose.Schema({
  name: String,
  email: String,
});

// DataBase models are created
const Users = mongoose.model("Users", UsrSchema);
const msg = mongoose.model("Msg", msgSchema);






//*MIDDLE_WAREs
app.set("view engine", "ejs");
// * all the middle wares are here
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true })); //* middle ware used to access data from form
app.use(cookieParser());






// *AUTHENTICATION
// its a normal handler(middleware)
// used to authenticate using cookie status before accessing any other route queued
// we just need place it before ()=>{} as a handler

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decoded = jwt.verify(token, "ontowgitassnadi");
    console.log(decoded);
    req.usr = await Users.findById(decoded._id); // (Id!=._id) refer app.post("/login")
    //OR req.a_user = await Users.findById(decoded._id);
    console.log(req.usr);
    next(); // if token is present then the next route is accessed
  } else {
    res.render("login"); //else login first
  }
};

app.get("/", isAuthenticated, (req, res) => {
  res.render("logout");
});







//* REGISTER
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {


  //user existance check
  const {name,email,password}=req.body;
  let user = await Users.findOne({ email: req.body.email });
  if (user) {
    return res.redirect("/login");
  }

  //encryption
  const hashedPassword= await bcrypt.hash(password,10);

  //this stores the _id of user entry from database
  const a_user = await Users.create({
    name,email,password:hashedPassword,
  });

  //storing cookies
  const token_key = jwt.sign({ Id: a_user._id }, "ontowgitassnadi"); // bind entry id with a key

  res.cookie("token", token_key, {
    httpOnly: true,
    expires: new Date(Date.now() + 200 * 1000), //expiry time is set as per need
  });
  res.redirect("/contact");
});







//* Login Page

app.get("/login", (req, res) => {
  const { token } = req.cookies;
  if (token) {
    res.redirect("/contact"); //for the time being otherwise we render the profile/main page of website
  } else {
    res.render("login"); //else login first(its render not redirect)
  }
});

//! JWT
//!Flow:
//user response stored in mongodb
//-> token is generated w.r.t _id in DB along with a key(binding) using jwt.sign
//-> that token stored as in cookie and retrieved in auth using req.cookies;
app.post("/login", async (req, res) => {

  // *register?
  // const {email,password}=req.body; -----use these variables
                  // OR
  let user = await Users.findOne({ email: req.body.email });//findOne talks in reference to details of specific entry now stored in `user`
  if (!user) {
    return res.redirect("/register");
  }

  //*match password

  //before using bcrypt for password hashing
      // const MatchIt=req.body.password===user.password;

  //using bcrypt for password hashing
  const MatchIt=await bcrypt.compare(req.body.password,user.password)
  if(!MatchIt){ 
    return res.redirect("/login",{message:"Incorrect Password"});
  }

  const token_key = jwt.sign({ Id: user._id }, "ontowgitassnadi"); 
  // binds entry id with a key as a value to pass in cookie
  //storing cookies
  res.cookie("token", token_key, {
    httpOnly: true,
    expires: new Date(Date.now() + 200 * 1000), //expiry time is set as per need
  });
  res.redirect("/contact");
});






//*CONTACT PAGE
app.get("/contact", isAuthenticated, (req, res) => {
  // console.log(path.join(path.resolve()));
  //*how to render html file
  res.sendFile(path.join(path.resolve(), "./public/contact.html"));
});

app.post("/contact", isAuthenticated, async (req, res) => {
  // console.log(req.body); //req.body is an object which has the responses of form
  await msg.create({ name: req.body.name, email: req.body.email });
  res.redirect("/success");
});







//*Success message
app.get("/success", (req, res) => {
  res.render("logout");
});

//LOGOUT page(no need of post method as we `terminate` all cookies and everything)
app.get("/logout", (req, res) => {
  res.render("logout", () => {
    res.cookie("token", null, {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
  });
  res.render("login");
});

app.listen(5000, () => {
  console.log("server is working");
});
