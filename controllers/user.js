const { promisify } = require("util");
const passport = require("passport");
const _ = require("lodash");
const User = require("../models/User");
const validator = require("validator");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const mailChecker = require("mailchecker");
const AWS = require("aws-sdk");
AWS.config.loadFromPath(__dirname + "/../config/aws.json");

const randomBytesAsync = promisify(crypto.randomBytes);

const sendMail = settings => {
  let transporter = nodemailer.createTransport({
    SES: new AWS.SES({
      apiVersion: "2010-12-01"
    })
  });

  return transporter.sendMail(settings.mailOptions).catch(err => {
    if (err.message === "self signed certificate in certificate chain") {
      console.log(
        "WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production."
      );
      transportConfig.tls = transportConfig.tls || {};
      transportConfig.tls.rejectUnauthorized = false;
      transporter = nodemailer.createTransport(transportConfig);
      return transporter.sendMail(settings.mailOptions);
    }
    console.log(settings.loggingError, err);
    return err;
  });
};

/**
 * POST /login
 * Sign in using email and password
 */
exports.postLogin = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email))
    validationErrors.push({ msg: "Please enter a valid email address" });
  if (validator.isEmpty(req.body.password))
    validationErrors.push({ msg: "Password cannot be blank" });

  if (validationErrors.length) {
    return next(validationErrors);
  }

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });

  passport.authenticate("local", { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) return next(info);

    const payload = {
      email: user.email,
      expires: Date.now() + parseInt(process.env.JWT_EXPIRATION_MS)
    };

    req.logIn(user, { session: false }, err => {
      if (err) return next(err);
      const token = jwt.sign(JSON.stringify(payload), process.env.JWT_SECRET);
      res.cookie("jwt", token, { httpOnly: true });
      res.status(200).send({ email: user.email });
    });
  })(req, res, next);
};

/**
 * POST /signup
 * Create a new local account
 */
exports.postSignup = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isEmail(req.body.email))
    validationErrors.push({ msg: "Please enter a valid email address" });
  if (!validator.isLength(req.body.password, { min: 8 }))
    validationErrors.push({
      msg: "Password must be at least 8 characters long"
    });
  if (req.body.password !== req.body.confirmPassword)
    validationErrors.push({ msg: "Passwords do not match" });

  if (validationErrors.length) return next(validationErrors);

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) return next(err);
    if (existingUser) return next("user already exist");
    user.save(err => {
      if (err) return next(err);
      res.status(201).send({ email: user.email });
    });
  });
};

/**
 * GET /user
 * Get user data
 */
exports.getUser = (req, res, next) => {
  User.findOne({ email: req.user.email }, (err, user) => {
    if (err) return next(err);
    if (!user) return next("no matching user found");
    res.status(200).send({ email: user.email });
  });
};

/**
 * PUT /user/password
 * Update current password
 */
exports.putUpdatePassword = (req, res, next) => {
  const validationErrors = [];
  if (!validator.isLength(req.body.password, { min: 8 }))
    validationErrors.push({
      msg: "Password must be at least 8 characters long"
    });
  if (req.body.password !== req.body.confirmPassword)
    validationErrors.push({ msg: "Passwords do not match" });

  if (validationErrors.length) return next(validationErrors);

  User.findOne({ email: req.user.email }, (err, user) => {
    if (err) return next(err);
    user.password = req.body.password;
    user.save(err => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
};

/**
 * GET /logout
 * Log out
 */
exports.logout = (req, res) => {
  req.logout();
  res.sendStatus(205);
};

/**
 * GET /user/verify
 * Verify email address
 */
exports.getVerifyEmail = (req, res, next) => {
  User.findOne({ email: req.user.email }).then(user => {
    if (!user) return next("User doesn't exist.");
    if (user.emailVerified) return next("The email address has been verified.");

    if (!mailChecker.isValid(req.user.email))
      return next(
        "The email address is invalid or disposable and can not be verified. Please update your email address and try again."
      );

    const createRandomToken = randomBytesAsync(16).then(buf =>
      buf.toString("hex")
    );

    const setRandomToken = token => {
      user.emailVerificationToken = token;
      user = user.save();
      return token;
    };

    const sendVerifyEmail = token => {
      const mailOptions = {
        to: req.user.email,
        from: "pkpk5087@gmail.com",
        subject: "Please verify your email address",
        text: `Thank you for registering with this app.\n\n
        Please copy below verification code and paste to the app:\n\n
        ${token}\n\n
        \n\n
        Thank you!`
      };
      const mailSettings = {
        successfulType: "info",
        successfulMsg: `An e-mail has been sent to ${req.user.email} with further instructions.`,
        loggingError:
          "ERROR: Could not send verifyEmail email after security downgrade.\n",
        errorType: "errors",
        errorMsg:
          "Error sending the email verification message. Please try again shortly.",
        mailOptions,
        req
      };
      return sendMail(mailSettings);
    };

    createRandomToken
      .then(setRandomToken)
      .then(sendVerifyEmail)
      .then(() => res.sendStatus(200))
      .catch(next);
  });
};

/**
 * GET /user/verify/:token
 * Verify email address
 */
exports.getVerifyEmailToken = (req, res, next) => {
  User.findOne({ email: req.user.email })
    .then(user => {
      if (!user) next("User does not exist.");
      if (user.emailVerified)
        return next("The email address has been verified.");

      const validationErrors = [];
      if (req.params.token && !validator.isHexadecimal(req.params.token))
        validationErrors.push({ msg: "Invalid Token.  Please retry." });
      if (validationErrors.length) next(validationErrors);

      if (req.params.token === user.emailVerificationToken) {
        user.emailVerificationToken = "";
        user.emailVerified = true;
        user = user.save();
        res.sendStatus(200);
      } else
        next(
          "The verification code was invalid, or is for a different account."
        );
    })
    .catch(next);
};
