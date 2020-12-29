const express = require("express");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const chalk = require("chalk");
const path = require("path");
const logger = require("morgan");
const expressStatusMonitor = require("express-status-monitor");
const errorHandler = require("errorhandler");
const bodyParser = require("body-parser");
const compression = require("compression");
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);
const passport = require("passport");

dotenv.config({ path: ".env" });

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
app.set("view engine", "pug");
app.use(expressStatusMonitor());
app.use(compression());
app.use(logger("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    cookie: { maxAge: 12096000000 },
    store: new MongoStore({
      url: process.env.MONGODB_URI,
      autoReconnect: true
    })
  })
);
app.use(passport.initialize());
app.use(passport.session());

/**
 * Primary app routes
 */
app.get("/", (req, res, next) => {
  res.render("index.html");
});

/**
 * Error handler
 */
if (process.env.NODE_ENV === "development") {
  app.use(errorHandler());
} else {
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send("Internal Error");
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
