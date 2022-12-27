const path = require("path");

const passport = require("passport");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;


const DaoUsersMongoose = require("../daos/daoMongooseUsers");
const daoUser = new DaoUsersMongoose();

passport.use(
  "register",
  new LocalStrategy(
    { usernameField: "username", passReqToCallback: true },
    async (req, username, password, callback) => {
      const user = await daoUser.getAll();
      const userFound = user.find((us) => us.username == username);
      if (userFound) {
        return callback(null, false, { message: "USERNAME ALREADY IN USE" });
      }

      const passwordBcrypt = bcrypt.hashSync(password, bcrypt.genSaltSync(10));

      const newUser = {
        name: req.body.name,
        username: username,
        password: passwordBcrypt,
        address: req.body.address,
        phone: req.body.phone,

      };

      await daoUser.save(newUser);
      return callback(null, newUser);
    }
  )
);

passport.use(
  "authenticate",
  new LocalStrategy(async (username, password, done) => {
    const users = await daoUser.getAll();
    const userFound = users.find((us) => us.username == username);
    if (!userFound || !bcrypt.compareSync(password, userFound.password)) {
      return done(null, false, { message: "NOT FOUND" });
    } else {
      return done(null, userFound);
    }
  })
);

passport.serializeUser((newUser, done) => {
  done(null, newUser.username);
});

passport.deserializeUser(async (username, done) => {
  const users = await daoUser.getAll();
  const user = users.find((us) => us.username == username);
  return done(null, user);
});

module.exports = passport;