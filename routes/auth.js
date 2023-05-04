/** Routes for demonstrating authentication in Express. */

const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const jwt = require("jsonwebtoken");
const {ensureLoggedIn} = require("../middleware/auth");
const User = require("../models/user");



router.post("login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("username and password required", 400);
    }
    if ((await User.authenticate(username, password)) === true) {
      let token = jwt.sign({ username }, SECRET_KEY);
      User.updateLoginTimestamp(username);
      return res.json({ message: "Logged in", token });
    }
    throw new ExpressError("Invalid username or password", 400);
  } catch (e) {
    return next(e);
  }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    let { username } = await User.register(req.body);
    let token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);
    return res.json({token})
  } catch (e) {
    return next(e);
  }
});


module.exports = router;