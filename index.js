import express from "express";
import path from "path";
import mongoose, { Mongoose } from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";


mongoose
    .connect('mongodb://127.0.0.1:27017', {
        dbName: 'backend',
    })
    .then(() => console.log('Database connected'))
    .catch(e => console.log(e))

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password:String,
});
const User = mongoose.model("user", userSchema);

const app = express();

// using middleware 
app.use(express.static(path.join(path.resolve(), 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// setting up engine 
app.set("view engine", "ejs")

app.get("/register",(req,res)=> {
    res.render("register", {msg:"Register Now"})
})
app.post("/register", async (req, res) => {
    const {name,email,password} = req.body
    let useremail = await User.findOne({email})
    if(useremail) {
        return res.redirect("/login")
    }
    const hashedpassword = await bcrypt.hash(password,10)
    const user = await User.create({ 
        name,
        email,
        password:hashedpassword,
    })
    const token = jwt.sign({ _id: user._id },"sachin is great");
    res.cookie("token", token , {
        httpOnly: true, expires: new Date(Date.now() + 60 * 1000)
    })
    res.redirect('/');
})
 
const isAuthonticate = async(req, res, next) => {
    const {token} = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, "sachin is great");
        req.user = await User.findById(decoded._id);
        console.log(req.user)
        next()
    } else {
        res.render("login");
    }
}
app.get("/", isAuthonticate, (req, res) => {
    res.render("logout", {name:req.user.name});
})

app.get("/login", (req,res)=> {
    res.render("login");
})
app.post("/login", async (req, res) => {
    const {password,email} = req.body
    let userdata = await User.findOne({email})
    if(!userdata) {
       return res.redirect("/register")
    }


    const pmatch = await bcrypt.compare(password,userdata.password)

    if(!pmatch) return res.render("login", {email,msg:"Incorrect Password"})
    const user = await User.create({ 
        password,
        email,
    })
    const token = jwt.sign({ _id: user._id },"sachin is great");
    res.cookie("token", token , {
        httpOnly: true, expires: new Date(Date.now() + 60 * 1000)
    })
    res.redirect('/');
})
app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        expires: new Date(Date.now())
    })
    res.redirect('/');
})
app.listen(5000, () => {
    console.log('run');
})