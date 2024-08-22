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
const mongoStore = require('connect-mongo');
const crypto = require('crypto');
const axios = require('axios');
const secret = process.env.SECRET || 'thisisasecret';
const db_url = process.env.REGISTERLOGIN_DB_URL;
const nodemailer_url = process.env.NODEMAILER
const AppError = require('./errorHandling/AppError');

const app = express();

const store = mongoStore.create({
    mongoUrl: db_url,
    secret: secret,
    touchAfter: 24 * 60 * 60
});
const sessionOptions = {
    store: store,
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
    },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
});
const corsOptions = {
    credentials: true,
    origin: ["Domain that you are receiving the requests from: both with www and without www"]
};

UserSchema.plugin(passportLocalMongoose);
const User = mongoose.model('User', UserSchema);

//app.set("trust proxy", 1);
app.use(express.json());
app.use(cors(corsOptions));
app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new localStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

async function main() {
    await mongoose.connect(db_url);
}

main().then(() => console.log("Success")).catch((err) => console.log(err));

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

    try {
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
    } catch (err) {
        return res.status(500).send('Internal Server Error');
    }
}

const sendEmail = async (req, res) => {
    const url = `${nodemailer_url}/sendResetLink`;
    const dataToBeSent = {
        email: req.body.email,
        resetToken: req.resetToken
    }

    const options = {
        method: 'POST',
        url: url,
        data: dataToBeSent
    }

    await axios.request(options)
        .then((response) => {
            return res.status(200).send(response.data);
        })
        .catch((err) => {
            return res.status(500).send(err.response.data);
        });
}

app.post('/signup', registerUser, authenticateAndLogin, (req, res) => {
    res.send("Account created successfully.");
});

app.post('/login', authenticateAndLogin, (req, res) => {
    res.send("Logged in successfully.");
});

app.post('/logout', (req, res, next) => {
    try{
        req.logout((err) => {
            if (err) {
                return next(new AppError(500, "Couldn't log out."));
            }
            res.send('Logged out successfully.');
        })
    }catch (err) {
        return res.status(500).send('Internal Server Error');
    }    
});

app.post('/checkUserExists', async (req, res) => {
    const { email, username } = req.body;

    try {
        const userwithUsernameExists = await User.findOne({ username: username });
        if (userwithUsernameExists) {
            return res.status(409).send('Username already exists');
        }

        const userwithEmailExists = await User.findOne({ email: email });
        if (userwithEmailExists) {
            return res.status(409).send('A user with this email already exists');
        }

        return res.status(200).send("User does not exist.");
    } catch (err) {
        return res.status(500).send('Internal Server Error');
    }
});

app.post('/sendResetLink', async (req, res, next) => {
    const email = req.body.email;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send("No user found with this email");
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000;

        await user.save();

        req.resetToken = hashedToken;
        next();
    } catch (err) {
        return res.status(500).send('Internal Server Error');
    }
}, sendEmail);

app.post('/resetPassword', async (req, res, next) => {
    const { token, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired token');
        }

        user.setPassword(newPassword, async function (err) {
            if (err) {
                return res.status(500).send('Error setting new password.');
            }

            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            await user.save();
            next();
        });
    } catch (err) {
        return res.status(500).send('Internal Server Error');
    }
}, (req, res) => {
    res.send('Password has been successfully reset.');
});

app.post('/isLoggedIn', (req, res)=>{
    if (!req.isAuthenticated()) {
        return res.status(401).send("You must login first");
    }
    return res.send("User is logged in");
});

app.post('/deleteAccount', async (req, res)=>{
    const userId = req.user._id;
    
    try {
        await User.findByIdAndDelete(userId);
        
        req.logout((err) => {
            if (err) {
                return res.status(500).send("Couldn't log out.");
            }
            
            req.session.destroy((err) => {
                if (err) {
                    return res.status(500).send("Error destroying session");
                }
            
                res.clearCookie('userSessionCookie');
                res.send("Account deleted successfully");
            });
        });
    } catch (err) {
        res.status(500).send("Error deleting account");
    }
});

app.use((err, req, res, next) => {
    let { status = 400, message = "Something went wrong on the server side." } = err;
    res.status(status).send(message);
});

app.listen(3001, () => {
    console.log('Listening...')
});