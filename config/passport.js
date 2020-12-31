const passport = require("passport");
const _ = require("lodash");
const { Strategy: Localstrategy } = require("passport-local");
const { Strategy: JWTstrategy } = require("passport-jwt");

const User = require("../models/User");

/**
 * Sign in using Email and Password
 */
passport.use(
  new Localstrategy(
    { usernameField: "email", passwordField: "password" },
    (email, password, done) => {
      User.findOne({ email: email.toLowerCase() }, (err, user) => {
        if (err) return done(err);
        if (!user)
          return done(null, false, { msg: `Email ${email} not found` });
        /**
         * Add below code after add 3rd party login api
         */
        // if (!user.password) {
        //   return done(null, false, {
        //     msg:
        //       "Your account was registered using a sign-in provider. To  password login, sign in using a provider, and then set a password under your user profile."
        //   });
        // }
        user.comparePassword(password, (err, isMatch) => {
          if (err) return done(err);
          if (isMatch) return done(null, user);
          return done(null, false, { msg: "Invalid email or password" });
        });
      });
    }
  )
);

/**
 * Verify with JWT token
 */
passport.use(
  new JWTstrategy(
    {
      jwtFromRequest: req => req.cookies.jwt,
      secretOrKey: process.env.JWT_SECRET
    },
    (jwtPayload, done) => {
      if (Date.now() > jwtPayload.expires) {
        return done("jwt expired");
      }
      return done(null, jwtPayload);
    }
  )
);

/**
 * Check authentication
 */
exports.checkAuth = (req, res, next) => {
  passport.authenticate("jwt", { session: false }, (err, payload, info) => {
    if (err) return next(err);
    if (!payload) return next(info);
    req.user = payload;
    next();
  })(req, res, next);
};
