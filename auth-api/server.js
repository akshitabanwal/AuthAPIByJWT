import express from "express"
import  dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import cors from "cors";

const app=express();
app.use(cors({
    origin:"http://localhost:5173",
    credentials:true
}));

dotenv.config();
const Port=5000;

app.use(cookieParser());
app.use(express.json());
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
 
  
  db.connect();
  const JWT_SECRET = process.env.JWT_SECRET;
  //register user route
  app.post("/register",async(req,res)=>{
    const {name,username,password}=req.body;
    if(!name||!username||!password){
      return res.status(400).json({
        message:"All fields are mandatory!"
      });
    }
      try{
        const checkResult=await db.query("SELECT * FROM users WHERE username=$1",[username]);
        if(checkResult.rows.length>0){
          return res.status(400).json({
            message:"This user already exists"
          });
        }
          const hashedPass=await bcrypt.hash(password,10);
          const result=await db.query("INSERT INTO users (name,username,password) VALUES ($1,$2,$3) RETURNING *",[name,username,hashedPass]);

          const user =result.rows[0];
          const webToken=jwt.sign({id:user.id,username:user.username},JWT_SECRET,{
            expiresIn:'3m'
          })
          res.cookie('webToken',webToken,{
            httpOnly:true,
            maxAge:3*60*1000,
            secure:process.env.NODE_ENV==="production"
          });
          res.status(201).json({
            message:"User is registered succesfully",
            webToken
          });
        }catch(err){
          console.error(err);
  res.status(500).json({
    message: "Internal Server Error",
  });
        

        
      }
    
  })
  app.post("/login",async(req,res)=>{
    const {username,password}=req.body;
    try{
      const checkResult=await db.query("SELECT * FROM users WHERE username=$1",[username]);
      if(checkResult.rows.length===0){
        return res.status(400).json({
          message:"Invalid username and password"
        });
      }
      const user=checkResult.rows[0];
      const isValid=await bcrypt.compare(password,user.password);
      if(!isValid){
        return res.status(401).json({
          message:"Invalid username and password"
        })
      }
      const webToken=jwt.sign({id:user.id,username:user.username},JWT_SECRET,{
        expiresIn:'3m'
      })
      res.cookie('webToken',webToken,{
        httpOnly:true,
        maxAge:3*60*1000,
        secure:process.env.NODE_ENV==="production"
      });
      res.status(201).json({
        message:"You have logged in succesfully",
        webToken
      });
    }catch(err){
      console.error(err);
  res.status(500).json({
    message: "Internal Server Error",
  });
    }

    });

    function verifyToken(req,res,next){
      const webToken=req.cookies.webToken;
      if(!webToken){
        return res.status(403).json({
          message:"There is no token"
        })
      }
      jwt.verify(webToken,JWT_SECRET,(err,user)=>{
        if(err){
          return res.status(403).json({message:"The JWT Token is expired,Please  login again"})
        }
        req.user=user;
        next();
      })
    }
    app.get("/secrets",verifyToken,(req,res)=>{
      res.json({message:`Welcome to Secrets Page ${req.user.username}!`,user:req.user})
    })
    app.get("/refresh-token", async (req, res) => {
      const webToken = req.cookies.webToken;
    
      if (!webToken) {
        return res.status(401).json({ message: "There is not any token" });
      }
    
      try {
        jwt.verify(webToken, JWT_SECRET, (err, user) => {
          if (err) {
            return res.status(403).json({ message: "Your Token is expired" });
          }
    
          // Create a new token if old one is valid but about to expire
          const newWebToken = jwt.sign({ id: user.id, username: user.username}, JWT_SECRET, { expiresIn: '3m' });
    
          // Set new token in the response cookie
          res.cookie('webToken', newWebToken, {
            httpOnly: true,
            maxAge: 3 * 60 * 1000,  // 3 minutes
            secure: process.env.NODE_ENV === "production", // Use secure cookies in production (HTTPS)
          });
    
          res.status(200).json({ message: "Token  is refreshed", newWebToken });
        });
      } catch (err) {
        console.error(err);
  res.status(500).json({
    message: "Internal Server Error",
  });
      }
    });
  
app.get("/",(req,res)=>{
    res.send("auth api is working succesfully");
})
app.listen(Port,()=>{
    console.log(`Server started successfully at ${Port}`);
})