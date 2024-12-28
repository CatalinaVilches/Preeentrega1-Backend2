import passport from 'passport';
import local from 'passport-local';
import jwt from 'passport-jwt';
import userService from '../models/User.js';
import { createHash, isValidPassword } from '../utils.js';

const LocalStrategy = local.Strategy;

const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['tokenCookie'];
    }
    return token;
};

const initializePassport = (PRIVATE_KEY) => {
    passport.use('register', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' }, 
        async (req, username, password, done) => { 
            const { first_name, last_name, email, age } = req.body; 
            try {
                let user = await userService.findOne({ email: email });
                if (user) {
                    console.log('User already exists');
                    return done(null, false); 
                }
                let newUser = {
                    first_name, 
                    last_name, 
                    email, 
                    age, 
                    password: createHash(password) 
                };

                const userCreated = await userService.create(newUser);
                return done(null, userCreated); 
            } catch (error) {
                return done(error);
            }
        }
    ));

    // Estrategia para login
    passport.use('login', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' }, 
        async (req, username, password, done) => { 
            try {
                const user = await userService.findOne({ email: username }); 
                if (!user) {
                    console.log('User doesnt exist');
                    return done(null, false, { message: 'Usuario no encontrado' });
                }

                if (!isValidPassword(user, password)) {
                    return done(null, false, { message: 'Contraseña incorrecta' });
                }
                return done(null, user); 
            } catch (error) {
                return done(error);
            }
        }
    ));

    passport.use('jwt', new JWTStrategy(
        {
            jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]), 
            secretOrKey: PRIVATE_KEY, 
        },
        async (jwt_payload, done) => {
            try {
            
                const user = await userService.findById(jwt_payload.id); 
                if (!user) {
                    return done(null, false, { message: 'Usuario no encontrado' });
                }
                return done(null, user); 
            } catch (error) {
                done(error);
            }
        }
    ));
    
   
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        let user = await userService.findById(id);
        done(null, user);
    });
};

export default initializePassport;
