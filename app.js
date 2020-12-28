const express = require("express");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const chalk = require("chalk");
const path = require("path");

dotenv.config({ path: ".env" });

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

app.use(express.static(path.join(__dirname, "/public")));

app.get("/", (req, res, next) => {
  res.render("index.html");
});

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
