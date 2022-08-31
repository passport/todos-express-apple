var express = require('express');
var passport = require('passport');
var AppleStrategy = require('@nicokaiser/passport-apple');
var db = require('../db');


//console.log(process.env['APPLE_KEY']);

passport.use(new AppleStrategy({
  clientID: process.env['APPLE_CLIENT_ID'],
  teamID: process.env['APPLE_TEAM_ID'],
  keyID: process.env['APPLE_KEY_ID'],
  callbackURL: 'https://todos-express-passport-apple.onrender.com/oauth2/redirect/apple',
  key: process.env['APPLE_KEY'],
  scope: ['name', 'email'],
  state: true
}, function verify(accessToken, refreshToken, profile, cb) {
  console.log('VERIFY APPLE!');
  console.log(accessToken);
  console.log(refreshToken);
  console.log(profile);
  
  db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
    'https://appleid.apple.com',
    profile.id
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) {
      db.run('INSERT INTO users (name) VALUES (?)', [
        profile.name
      ], function(err) {
        if (err) { return cb(err); }
        var id = this.lastID;
        db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
          id,
          'https://appleid.apple.com',
          profile.id
        ], function(err) {
          if (err) { return cb(err); }
          var user = {
            id: id,
            name: profile.name
          };
          return cb(null, user);
        });
      });
    } else {
      db.get('SELECT * FROM users WHERE id = ?', [ row.user_id ], function(err, row) {
        if (err) { return cb(err); }
        if (!row) { return cb(null, false); }
        return cb(null, row);
      });
    }
  });
}));

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


var router = express.Router();

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.get('/login/federated/apple', passport.authenticate('apple'));

router.get('/oauth2/redirect/apple', passport.authenticate('apple', {
  successReturnToOrRedirect: '/',
  failureRedirect: '/login'
}));

router.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

module.exports = router;
