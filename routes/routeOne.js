const express = require('express');
const router = express.Router();
const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const Users = require('../DatabaseModel/userModel');

// function for authenticate user afer login

let isAuthenticateUser = (req, res, next)=>{
    if(req.isAuthenticated()){
        return next();
    }
    req.flash('error_msg', 'please login first to access this page');
    res.redirect('/login');
};

// Get request methods starts here

router.get('/login', (req, res)=>{
    res.render('login');
});
router.get('/signUp', (req, res)=>{
    res.render('signUp');
});
router.get('/dashboard', isAuthenticateUser,(req, res)=>{
    res.render('dashboard');
});
router.get('/logOut', isAuthenticateUser, (req, res)=>{
    req.logOut();
    res.redirect('/login');
    req.flash('success_msg', 'You have been logged out successfully');
});
router.get('/forgotPassword', isAuthenticateUser, (req, res)=>{
    res.render('forgotPassword');
});
router.get('/reset/:token', (req, res)=>{
    Users.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt :Date.now()}}).then(user=>{
        if(!user){
            req.flash('error_msg', 'The Username doesnt exist in database');
            res.redirect('/forgotPassword');
        }
        res.render('resetPassword', {token: req.params.token});
    })
    .catch(err=>{
        if(err) {
            req.flash('error_msg', 'Error:'+err);
            res.redirect('/resetPassword');
        }
    });
});

router.get('/changePassword', (req, res)=>{
    res.render('changePassword');
});
// Get request methods ends here

// Post request methods starts here
router.post('/login', passport.authenticate('local', {
    failureRedirect: '/login',
    successRedirect: '/dashboard',
    failureFlash: 'Username Or Password is incorrect'
}));
router.post('/signUp', (req, res)=>{
    let {username, email, password} = req.body;
    let usersData = {
        username: username,
        email: email
    };
    Users.register(usersData, password, (err, users)=>{
        if(err) {
            req.flash('error_msg', 'Error :' + err);
            res.redirect('/signUp');
        }
        passport.authenticate('local', (err, user, info)=>{
            if(err){return res.status(401);}
            req.flash('success_msg', 'User was created successfully');
            res.redirect('/signUp');
        })(req, res);
    });
});

router.post('/forgot', (req, res)=>{
    let recoveryPassword = '';
    async.waterfall([
        (done)=>{
            crypto.randomBytes(30, (err, buf)=>{
                let token = buf.toString('hex');
                done(err, token);
            });
        },
        (token, done)=>{
            Users.findOne({email: req.body.forgotEmail}).then( user=>{
                if(!user){
                    req.flash('error_msg', 'The email that you entered doesnt exist');
                    return res.redirect('/forgotPassword');
                }
                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 1800000;
                user.save( err=>{
                    done(err, token, user);
                });
            })
            .catch( err => {
                req.flash('error_msg', 'Error :'+ err);
                res.redirect('/forgotPassword');
            });
        },
        (token, user)=>{
            let smtp = nodemailer.createTransport({
                service: 'Gmail',
                type: 'smtp',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });
            let mailOptions = {
                to: user.email,
                from: 'Amirhosein Rezai amirhossseinrezai@gmail.com',
                subject: 'Recovery Email From Auth App',
                text: "Please click the following link to recover your password: \n\n " +
                "http://" + req.headers.host + "/reset/" + token + "\n\n" + "If you didnt request this please ignore it"
            };

            smtp.sendMail(mailOptions, err=>{
                if(err){
                    req.flash('error_msg', 'Email doesnt Sent'+err);
                    return res.redirect('/forgotPassword');
                }
                req.flash('success_msg', 'Email send with further instructions. Please check your email'+ err);
                res.redirect('/forgotPassword');
            });
        }
    ], err => {
        if(err) {
            req.flash('error_msg', err);
            res.redirect('/forgotPassword');
        }
    });
});
router.post('/reset/:token', (req, res)=>{
    async.waterfall([
        (done)=>{
            Users.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt : Date.now()}}).then(user=>{
                if(!user){
                    req.flash('error_msg', 'The User doesnt exist');
                    return res.redirect('/forgotPassword');
                }
                if(req.body.newPassword !== req.body.confirmPassword){
                    req.flash('error_msg', 'Please insert both Passwords correctly');
                    return res.redirect('/resetPassword');
                }
                user.setPassword(req.body.newPassword, error=>{
                    if(error) {
                        req.flash('error_msg', 'Error_1: '+error);
                        return res.redirect('/forgotPassword');
                    }
                    user.resetPasswordToken = undefined;
                    user.resetPasswordExpires = undefined;
                    user.save(error=>{
                        if(error) {
                            req.flash('error_msg', 'Error_2: '+error);
                            return res.redirect('/forgotPassword');
                        }
                        req.logIn(user, err=>{
                            if(typeof(user.email) !== undefined || typeof(user.username) !== undefined){
                                if(err) {
                                    req.flash('error_msg', 'Error_3: '+err);
                                    return res.redirect('/forgotPassword');
                                }
                                done(err, user);
                            }
                        });
                    });
                });
            }).catch(err=>{
                if(err){
                    req.flash('error_msg', 'Error:' + err);
                    res.redirect('/resetPassword');
                }
            });
        },
        (user)=>{
            let smtp = nodemailer.createTransport({
                service: 'Gmail',
                type: 'smtp',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });
            let mailOptions = {
                to: user.email,
                from: 'From Auth App amirhossseinrezai@gmail.com',
                subject: 'Changing Password',
                text: 'Congratulation,'+ user.username +' Your Password Had Been Reseted successfully'
            };

            smtp.sendMail(mailOptions, err=>{
                req.flash('success_msg', 'Your Password has been changed successfully');
                res.redirect('/dashboard');
            });
        }], err=>{
            res.redirect('/login');
        }
    );
});

router.post('/change', (req, res)=>{
    if(req.body.passwordChange_new !== req.body.passwordChange_confirm){
        req.flash('error_msg', 'Please enter the same password ');
        return res.redirect('/changePassword');
    }
    Users.findOne({email: req.user.email})
    .then(user=>{
        if(!user){
            req.flash('error_msg', 'The Username doesnt exist');
            return res.redirect('/dashboard');
        }

        user.setPassword(req.body.passwordChange_new, err=>{
            if(err){
                req.flash('error_msg', err);
                return res.redirect('/changePassword');
            }
            user.save().then(user=>{
                req.flash('success_msg', 'The Password has been successfully changed');
                res.redirect('/changePassword');
            }).catch(err=>{
                if(err){
                    req.flash('error_msg', err);
                    return res.redirect('/changePassword');
                }
            });
        });
    })
    .catch(err=>{
        res.redirect('/changePassword');
    });
});
// Post request methods ends here
module.exports = router;