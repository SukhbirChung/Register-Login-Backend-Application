if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const mongoStore = require('connect-mongo');
const {connectToDB} = require('./database/connectToDB');
const userRoutes = require('./routes/users');
const secret = process.env.SECRET || 'thisisasecret';
const db_url = process.env.REGISTERLOGIN_DB_URL;

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
const corsOptions = {
    credentials: true,
    origin: ["Domain that you are receiving the requests from: both with www and without www"]
};

app.use(express.json());
app.use(cors(corsOptions));
app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());

connectToDB().then(() => console.log("Success")).catch((err) => console.log(err));

app.use('/', userRoutes);

app.use((err, req, res, next) => {
    let { status = 400, message = "Something went wrong on the server side." } = err;
    res.status(status).send(message);
});

app.listen(3001, () => {
    console.log('Listening...')
});