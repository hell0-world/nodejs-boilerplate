/**
 * Module dependencies
 */
const express = require("express");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const chalk = require("chalk");
const path = require("path");
const logger = require("morgan");
const expressStatusMonitor = require("express-status-monitor");
const errorHandler = require("errorhandler");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const compression = require("compression");
const passport = require("passport");

/**
 * Load environment variables from .env
 */
dotenv.config({ path: ".env" });

/**
 * Controllers
 */
const userController = require("./controllers/user");

/**
 * Passport configuration
 */
const passportConfig = require("./config/passport");

/**
 * Create Express server
 */
const app = express();

/**
 * Connect to MongoDB
 */
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);
mongoose.set("useNewUrlParser", true);
mongoose.set("useUnifiedTopology", true);
mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on("error", err => {
  console.error(err);
  console.log(
    "%s MongoDB connection error. Please make sure MongoDB is running.",
    chalk.red("✗")
  );
  process.exit();
});

/**
 * Express configuration
 */
app.set("host", process.env.OPENSHIFT_NODEJS_IP || "0.0.0.0");
app.set("port", process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 3000);
app.disable("x-powered-by");
app.set("views", "./views");
app.set("view engine", "pug");
app.use(expressStatusMonitor());
app.use(compression());
app.use(logger("dev"));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));
app.use(passport.initialize());
/**
 * Primary app routes
 */
app.post("/signup", userController.postSignup);
app.post("/login", userController.postLogin);
app.get("/logout", userController.logout);
app.get("/user", passportConfig.checkAuth, userController.getUser);
app.post("/forgot", userController.postForgot);
app.put(
  "/user/password",
  passportConfig.checkAuth,
  userController.putUpdatePassword
);
app.get(
  "/user/verify",
  passportConfig.checkAuth,
  userController.getVerifyEmail
);
app.get(
  "/user/verify/:token",
  //passportConfig.checkAuth,
  userController.getVerifyEmailToken
);

/**
 * Error handler
 */
if (process.env.NODE_ENV === "development") {
  app.use(errorHandler());
} else {
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send({ err });
  });
}

/**
 * Start Express Server
 */
app.listen(app.get("port"), () => {
  console.log(
    "%s App is running at http://localhost:%d in %s mode",
    chalk.green("✓"),
    app.get("port"),
    app.get("env")
  );
  console.log(" Press CTRL-C to stop\n");
});

module.exports = app;
