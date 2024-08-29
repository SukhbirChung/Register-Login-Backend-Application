const express = require('express');
const users = require('../controllers/users');
const {sendEmail} = require('../middleware');

const router = express.Router();

router.post('/checkUserExists', users.checkUserExists, (req, res) => {
    return res.status(200).send("User does not exist.");
});

router.post('/signup', users.registerUser, users.authenticateAndLogin, (req, res) => {
    res.send("Account created successfully.");
});

router.post('/login', users.authenticateAndLogin, (req, res) => {
    res.send("Logged in successfully.");
});

router.post('/logout', users.logout, (req, res) => {
    res.send('Logged out successfully.');
});

router.post('/deleteAccount', users.deleteAccount, (req, res) => {
    res.send("Account deleted successfully");
});

router.post('/isLoggedIn', (req, res)=>{
    if (!req.isAuthenticated()) {
        return next(new AppError(401, "You must login first"));
    }
    return res.send("User is logged in");
});

router.post('/sendResetLink', users.sendResetLink, sendEmail);

router.post('/resetPassword', users.resetPassword, (req, res) => {
    res.send('Password has been successfully reset.');
});

module.exports = router;