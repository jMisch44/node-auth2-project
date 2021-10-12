const router = require("express").Router();
const bcrypt = require('bcryptjs');
const buildToken = require('./token-builder');
const User = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);
  user.password = hash
  User.add(user)
    .then(saved => {
      res.status(201).json(saved)
    }).catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let { password, user_id } = req.body
  User.findById(user_id)
    .then(user => {
      if(user && bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        res.status(200).json({
          message: `${user.username} is back!`,
          token
        })
      }
    })
});

module.exports = router;
