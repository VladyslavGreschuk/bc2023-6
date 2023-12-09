const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const db = require('./db.js');
const cookieParser = require('cookie-parser');
const response = require('./response.js');

const options = {
    jwtFromRequest: ExtractJwt.fromExtractors([
        (req, res) => {
            try {
                if (req.cookies.Authorization) {
                    return req.cookies.Authorization;
                } else {
                    return null;
                }
            } catch (error) {
                console.error('Token extraction error:', error);
                return null;
            }
        }
    ]),
    secretOrKey: 'jwt-key'
}

module.exports = passport => {
    passport.use(
        new JwtStrategy(options, (payload, done) => {
            try {
                db.query("SELECT * FROM `users` WHERE `id` = '" + payload.sub + "'", (error, rows, fields) => {
                    if (error) {
                        console.error('Database query error:', error);
                        return done(error, null);
                    } else {
                        const user = rows[0];
                        return done(null, user);
                    }
                });
            } catch (e) {
                console.error('Strategy error:', e);
                return done(e, null);
            }
        })
    );
};
