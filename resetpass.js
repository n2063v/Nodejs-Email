// resetpass.js

var User = require('../models/account');

var emailConfig = require('../config/config.js');
//include the nodemailer module
var mailer = require("nodemailer");
var async = require('async');
var crypto = require('crypto');
var url = require('url');

// Set up the email configuration
var smtpTransport = mailer.createTransport(emailConfig.email.email_type, {
    service: emailConfig.email.email_provider,
    auth: {
        user: emailConfig.email.email_id,
        pass: emailConfig.email.email_password
    }
});

module.exports = {

    // Send Email with Accessible Link to Update Password
    sendmail : function (req , res , next) {

        async.waterfall([
            function (done) {
                crypto.randomBytes(20, function (err, buf) {
                    var token = buf.toString('hex');
                    done(err, token);
                });
            },
            function (token, done) {
                User.findOne({ email: req.body.email }, function (err, user) {
                    if (!user) {
                        req.flash('error', 'No account with that email address exists.');
                        return res.redirect('/forgetpassword');
                    }
                    user.resetPasswordToken = token; // Set Token
                    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                    user.save(function (err) {
                        done(err, token, user);
                    });
                });
            },
            function (token, user, done) {

                var parts = url.parse(req.headers.referer, true);
                var protocol = parts.protocol;
                var host = parts.host;

                var mailOptions = {
                    to: "n2063v@wsu.edu",
                    from: emailConfig.email.email_id,
                    subject: 'Password Request',
                    text: 'Dear, Max' + ',\n\n' +
                          'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                          protocol + "//" + host + '/reset/' + token + '\n\n' +
                          'If you did not request this, please ignore this email and your password will remain unchanged.\n\n' +
                          'Message sent from Testing Server \n\n' +
                          '-- Please Do Not Reply To This Email --\n\n'
                };
                smtpTransport.sendMail(mailOptions, function (err) {
                    res.redirect('/password/message');
                });
            }
        ], function (err) {
            res.redirect('/error');
        });
    },

    // Send Email to Confirmation of the Password Changed
    resetpass : function (req , res , next){
        async.waterfall([
            function (done) {
                // Find the user based on the request token
                User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
                    // If the user not found based on the requirements, then return back the message invalide or expired
                    if (!user) {
                        res.redirect('/invalidToken');
                    } else {
                        if (user.password) {
                            // Set up the required information on the user account
                            user.password = user.generateHash(req.body.password);
                            user.resetPasswordToken = "";
                            user.resetPasswordExpires = "";
                            // Save the information
                            user.save(function (err) {
                                req.logIn(user, function (err) {
                                    done(err, user);
                                });
                            });
                        }
                    }
                });
            },
            function (user, done) {

                // Create the mail options for the email
                var mailOptions = {
                    to: "n2063v@wsu.edu",
                    from: emailConfig.email.email_id,
                    subject: 'Successfully Password Changed',
                    text: 'Dear, Max' + '\n\n' +
                          'This is a confirmation that the password for your account has just been changed.\n\n' +
                          'Message sent from Testing Server. \n\n' +
                          '-- Please Do Not Reply To This Email -- \n\n'
                };
                // Send the email and return back the successfully on the updated password
                smtpTransport.sendMail(mailOptions, function (err) {
                    // req.flash('success', 'Success! Your password has been changed.');
                    res.redirect('/password/success');
                    // done(err);
                });
            }
        ], function (err) {
            res.redirect('/error');
        });
    }
}









