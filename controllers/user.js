const passport = require("passport");
const _ = require("lodash");
const User = require("../models/User");
const validator = require("validator");
const jwt = require("jsonwebtoken");

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
  passport.authenticate("jwt", { session: false }, (err, payload, info) => {
    if (err) return next(err);
    if (!payload) return next(info);

    User.findOne({ email: payload.email }, (err, user) => {
      if (err) return next(err);
      if (!user) return next("no matching user found");
      res.status(200).send({ email: user.email });
    });
  })(req, res, next);
};
