import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import{Strategy} from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: "TOPSECRETWORD",   
  resave : false,   // this option forces the session back to the session store even if the session was never modified      
  saveUninitialize: true,
  cookie:{
    maxAge:1000 *60*60*24
  }
}))
app.use (passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Authentication",
  password: "1234",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/logout", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",(req,res)=>{
  // Notice that here the call back cb will be sending the details of the user retireved through the database look up 
  // It uses the cb to pass either the error or the details of the user 
  console.log(req.user)
  if (req.isAuthenticated){
    res.render("secrets.ejs")
  } else {
    res.redirect("/login")
  }
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result =await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING * ",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user,(err)=>{
            console.log(err);
            res.redirect("/secrets")
          })
          res.render("secrets.ejs");
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


// See how we are not implementing the cathcing the request and rendering it back
// Instead we are letting the passport to  initiate the strategy down below as long as we tell it to by indicating that it is a local strategy
app.post("/login",passport.authenticate("local", {
  successRedirect:"/secrets",  // this says that if everything works well and is successful then where do you want to redirect the user
  failureRedirect: "/login"    // failure redirect will be taking it back to the login page
}));

// we are going to use this  to register a strategy
// the fact that it is a local strategy it is trying to establish that the user is trying to
// validate whether if the user has the right password or whether the email exists inside the data  base
// Here is the link for the passport documentation 
// https://www.passportjs.org/docs/
// passport uses different packages to decrypt the passwords 
// they use the crypto to decrypt the password
// Passport gets triggered whenever we are trying to authenticate the user to it falls into 
// the verify function 
passport.use(new Strategy(async function verify(username, password, cb){

   console.log (username);
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      // remember that the password below has been caught by the passport being the middleware looking out to the 
      // form client 
      
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          // instead of using the console.error("Error comparing passwords:", err);
          // we should also use the call back and pass the error here
          return cb(err);
        } else {
          // the result below will be true if the bcrypt compare method returns the result as true meaning that the 
          // pass word matches the actual value

          if (result) {
            // instead of using the res.render("secrets.ejs")
            // we are trying to use the call back to return things
            // the callback will try to use any errors if present 
            // other wise it wil be returning the details of the actual user
            // this means the database look up of the user can be passed using the call back cb

            return cb(null,user)
          } else {
            // Over here is the password was incorrect then  instead of the res.send("Incorrect Password")
            // we use the cb to send the false value to the isAuthenticate fucntion which is there in the get route above
            // In this notice that even though its an error we are actually using null in the parameter of the cb
            // this is becasue we want to send it null becasue its a user error and nothing wrong with the code
            return cb(null, false)
          }
        }
      });
    } else {
      // Here instead of the res.send("User not found")
      // We are trying to use the cb saying that the User is not found
      // Remember that here the error is being set to the USer not found
      return cb("User not found");
    }
  } catch (err) {

    // Here instead of the console.log (err)
    // we are using the cb to justy pass the error incase the data base query goes wrong
    return cb(err)
  }
}))
// serializer takes a function as a parameter
// All it does is it registers the function used to serialize the objects ( User in our case)
// SO that we can save the data of the user who's logged  in to the local storage
// And we are using the call back to pass over any of the details of the user

/*  (method) passport.Authenticator<e.Handler, any, any, passport.AuthenticateOptions>
.serializeUser<any>(fn: (user: Express.User, done: (err: any, id?: any) => void) => 
  void): void (+3 overloads)
Registers a function used to serialize user objects into the session.

Examples:

passport.serializeUser(function(user, done) {
  done(null, user.id);
});            */
passport.serializeUser((user, cb)=> {
  cb (null, user);
})

// Al it does is that it saves the user's information such as their ID their email to the lcoal session 
// and then when you want to get hold of the user it deseerializes it back into the way that you can access 
// the user's information through that session
passport.deserializeUser((user, cb)=> {
  cb (null, user);
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
