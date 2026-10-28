'use strict';

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const env = require('../config/env');
const User = require('../models/User');

/**
 * Passport configuration.
 *
 * Only the Google strategy is registered. Email/password login is handled
 * directly by the auth controller because it does not need the multi-strategy
 * abstraction.
 */
const configurePassport = () => {
  if (!env.google.isConfigured) {
    if (!env.isTest) {
      console.warn(
        '[auth] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set. Google OAuth routes will respond 503.'
      );
    }
    return passport;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID: env.google.clientId,
        clientSecret: env.google.clientSecret,
        callbackURL: env.google.callbackUrl,
        scope: ['profile', 'email'],
        // NOTE: `state: true` is deliberately NOT used here. That option
        // selects a session-backed state store, and this API is stateless
        // (no express-session), so it would throw at runtime. CSRF protection
        // is instead provided by a signed, short-lived JWT used as `state`
        // and verified in the callback -- see the auth controller.
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails && profile.emails[0] && profile.emails[0].value;
          const avatar = profile.photos && profile.photos[0] && profile.photos[0].value;

          if (!email) {
            return done(null, false, {
              code: 'GOOGLE_NO_EMAIL',
              message: 'Your Google account did not share an email address.',
            });
          }

          const normalizedEmail = email.toLowerCase();

          // 1. Already linked to this Google account.
          let user = await User.findOne({ googleId: profile.id });
          if (user) return done(null, user);

          // 2. Existing email/password account: link the Google id to it so
          //    the user keeps one identity instead of hitting the unique-email
          //    constraint.
          user = await User.findOne({ email: normalizedEmail });

          if (user) {
            user.googleId = profile.id;
            if (!user.avatar && avatar) user.avatar = avatar;
            await user.save({ validateBeforeSave: false });
            return done(null, user);
          }

          // 3. Brand new user. No password is stored, so password login is
          //    impossible for this account until one is set explicitly.
          user = await User.create({
            name: profile.displayName || normalizedEmail.split('@')[0],
            email: normalizedEmail,
            googleId: profile.id,
            avatar,
          });

          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  return passport;
};

module.exports = { configurePassport, passport };
