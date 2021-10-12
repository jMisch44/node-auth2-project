const User = require('../users/users-model');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  const token = req.header.authorization
  if(!token) {
    return next({ status: 401, message: "Token required" })
  }
  jwt.verify(token, JWT_SECRET, ( err, decodedToken ) => {
    if(err) {
      return next({ status:401, message: "Token invalid" })
    } 
    req.decodedToken = decodedToken
    return next()
  })
}

const only = role_name => (req, res, next) => {
  if(role_name === req.decodedToken.role_name){
    next()
  } else {
    next({
      status: 403,
      message: "This is not for you"
    })
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body
    const users = await User.findBy({ username })
    if(users.length > 0) {
      next()
    } else {
      next({
        status: 401,
        message: "Invalid credentials"
      })
    }
  } catch (err) {
    next(err)
  }
}


const validateRoleName = async (req, res, next) => {
    if(!req.body.role_name || req.body.role_name.trim() === '') {
      req.role_name = 'student'
      next()
    } else if(req.body.role_name.trim() === 'admin') {
      next({
        status: 422,
        message: "Role name can not be admin"
      })
    } else if(req.body.role_name.trim().length > 32 ) {
      next({
        status: 422,
        message: "Role name can not be longer than 32 chars"
      })
    } else {
      req.role_name = req.body.role_name.trim()
      next()
    }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
