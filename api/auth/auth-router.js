const router = require("express").Router();
const bcrypt = require('bcryptjs');
const buildToken = require('./token-builder');
const User = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
  let { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username, password: hash, role_name})
    .then(noidea => {
      res.status(200).json(noidea)
    })
    .catch(next)
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
