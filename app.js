if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const localStrategy = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const secret = process.env.SECRET || 'thisisasecret';
const db_url = process.env.REGISTERLOGIN_DB_URL;
const AppError = require('./errorHandling/AppError');

const app = express();
const sessionOptions = {
    name: 'userSessionCookie',
    secret: secret,
    secure: true,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
};
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    }
});

UserSchema.plugin(passportLocalMongoose);
const User = mongoose.model('User', UserSchema);

app.use(express.json());
app.use(cors());
app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new localStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

async function main() {
   await mongoose.connect(db_url);
}

main().then(()=>conosle.log("Success")).catch((err)=>console.log(err));

const registerUser = async (req, res, next) => {
    let { email, username, password } = req.body;
    username = username.toLowerCase();

    const newUser = new User({ email, username });

    try {
        await User.register(newUser, password);
        next();
    }
    catch (err) {
        if (err.message.includes('email:')) {
            err.message = 'There is already an account registered with this email.';
        }
        next(new AppError(500, err.message));
    }
}

const authenticateAndLogin = (req, res, next) => {
    req.body.username = (req.body.username).toLowerCase();

    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(new AppError(500, "Couldn't authenticate the user."));
        }
        if (info) {
            return next(new AppError(500, info.message));
        }
        req.login(user, err => {
            if (err) {
                return next(new AppError(500, "Couldn't log in."));
            }
            next();
        })
    })(req, res, next);
}

app.post('/signup', registerUser, authenticateAndLogin, (req, res) => {
    res.send("Account created successfully.");
});

app.post('/login', authenticateAndLogin, (req, res) => {
    res.send("Logged in successfully.");
});

app.post('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(new AppError(500, "Couldn't log out."));
        }
        res.send('Logged out successfully.');
    })
});

app.use((err, req, res, next) => {
    let { status = 400, message = "Something went wrong on the server side." } = err;
    res.send(message);
});

app.listen(3000, () => {
    console.log('Listening...')
});