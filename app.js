
require('dotenv').config();
const express = require('express')
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"))

// use session and passport initialize and session initialize
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}))

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("Connected to database successfully");
    })
    .catch((err) => {
        console.log(err);
    })

// creating schema and model
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: []
});

// use passportlocalmongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
})

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    })
})

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
// get routes
app.get("/", (req, res) => {
    res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/secrets", (req, res) => {
    User.find({}, (err, result) => {
        res.render("secrets", {resultsec: result});
    })
})

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
    });
    res.redirect("/");

})

app.get("/submit", (req, res) => {
    res.render("submit");
})
// post routes
app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, result) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })
})

app.post("/login", (req, res) => {
    // create new user doucument
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    // check the values and login
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("secrets");
            })
        }
    })
})

app.post("/submit", (req, res) => {
    const subsecret = req.body.secret;
    if(req.isAuthenticated()) {
        req.user.secret.push(subsecret);
        req.user.save();
        res.redirect("/secrets");
    }
    else {
        User.findById(req.user.id, (err, result) => {
            if(err) {
                console.log(err);
            }
            else {
                if(result) {
                    result.secret.push(subsecret);
                    result.save(() => {
                            res.redirect("/secrets");
                    })
                }
            }
        })
    }
    
})

app.listen(process.env.PORT, () => {
    console.log("server is running");
})