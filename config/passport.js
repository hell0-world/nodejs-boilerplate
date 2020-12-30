const passport = require("passport");
const _ = require("lodash");
const { Strategy: Localstrategy } = require("passport-local");
const { Strategy: JWTstrategy } = require("passport-jwt");

const User = require("../models/User");

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

/**
 * Sign in using Email and Password
 */
passport.use(
  new Localstrategy({ usernameField: "email" }, (email, password, done) => {
    User.findOne({ email: email.toLowerCase() }, (err, user) => {
      if (err) return done(err);
      if (!user) return done(null, false, { msg: `Email ${email} not found` });
      if (!user.password) {
        return done(null, false, {
          msg:
            "Your account was registered using a sign-in provider. To  password login, sign in using a provider, and then set a password under your user profile."
        });
      }
      user.comparePassword(password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) return done(null, user);
        return done(null, false, { msg: "Invalid email or password" });
      });
    });
  })
);

/**
 * Verify with JWT token
 */
passport.use(
  new JWTstrategy(
    {
      jwtFromRequest: req.cookies.jwt,
      secretOrKey: process.env.JWT_SECRET
    },
    (jwtPayload, done) => {
      if (Date.now() > jwtPayload.expires) return done("jwt expired");
      return done(null, jwtPayload);
    }
  )
);

/**
 * Login Required middleware
 */
exports.isAuthorized = (req, res, next) => {
  if (req.isAuthorized()) return next();
  res.redirect("/login");
};
