const passport = require('passport');
const localStrategy = require('passport-local');
const crypto = require('crypto');
const User = require('../database/userModel');
const AppError = require('../errorHandling/AppError');

passport.use(new localStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

module.exports.checkUserExists = async (req, res, next) => {
    const { email, username } = req.body;

    try {
        const userwithUsernameExists = await User.findOne({ username: username });
        if (userwithUsernameExists) {
            return next(new AppError(409, "Username already exists"));
        }

        const userwithEmailExists = await User.findOne({ email: email });
        if (userwithEmailExists) {
            return next(new AppError(409, "A user with this email already exists"));
        }

        next();
    } catch (err) {
        return next(new AppError(500, "Internal Server Error"));
    }
}

module.exports.registerUser = async (req, res, next) => {
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

module.exports.authenticateAndLogin = (req, res, next) => {
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
        return next(new AppError(500, "Internal Server Error"));
    }
}

module.exports.logout = (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(new AppError(500, "Couldn't log out."));
        }
        next();
    })
}

module.exports.deleteAccount = async (req, res, next)=>{
    const userId = req.user._id;
    
    try {
        await User.findByIdAndDelete(userId);
        
        req.logout((err) => {
            if (err) {
                return next(new AppError(500, "Couldn't log out."));
            }
            
            req.session.destroy((err) => {
                if (err) {
                    return next(new AppError(500, "Error destroying session"));
                }
            
                res.clearCookie('userSessionCookie');
                next();
            });
        });
    } catch (err) {
        return next(new AppError(500, "Error deleting account"));
    }
}

module.exports.sendResetLink = async (req, res, next) => {
    const email = req.body.email;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return next(new AppError(400, "No user found with this email"));
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000;

        await user.save();

        req.resetToken = hashedToken;
        next();
    } catch (err) {
        return next(new AppError(500, "Internal Server Error"));
    }
}

module.exports.resetPassword = async (req, res, next) => {
    const { token, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return next(new AppError(400, 'Invalid or expired token'));
        }

        user.setPassword(newPassword, async function (err) {
            if (err) {
                return next(new AppError(500, 'Error setting new password.'));
            }

            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            await user.save();
            next();
        });
    } catch (err) {
        return next(new AppError(500, 'Internal Server Error'));
    }
}