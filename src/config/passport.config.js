import passport from 'passport';
import local from 'passport-local';
import jwt from 'passport-jwt';
import userService from '../models/User.js';
import { createHash, isValidPassword } from '../utils.js';

// Estrategias locales
const LocalStrategy = local.Strategy;

// Estrategias JWT
const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;

// Función para extraer el token de las cookies
const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['tokenCookie']; // Asegúrate de que esta sea la cookie que contiene el token
    }
    return token;
};

// Inicializar Passport
const initializePassport = (PRIVATE_KEY) => {
    // Estrategia para registro
    passport.use('register', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' }, 
        async (req, username, password, done) => { // Cambié 'email' a 'username' para evitar conflicto
            const { first_name, last_name, email, age } = req.body; // Desestructuración con 'email'
            try {
                let user = await userService.findOne({ email: email });
                if (user) {
                    console.log('User already exists');
                    return done(null, false); // El usuario ya existe
                }
                let newUser = {
                    first_name, 
                    last_name, 
                    email, 
                    age, 
                    password: createHash(password) // Hash de la contraseña
                };

                const userCreated = await userService.create(newUser);
                return done(null, userCreated); // Registro exitoso, retorno el usuario
            } catch (error) {
                return done(error);
            }
        }
    ));

    // Estrategia para login
    passport.use('login', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' }, 
        async (req, username, password, done) => { // Cambié 'email' a 'username' para evitar conflicto
            try {
                const user = await userService.findOne({ email: username }); // Utilizamos 'username' en lugar de 'email'
                if (!user) {
                    console.log('User doesnt exist');
                    return done(null, false, { message: 'Usuario no encontrado' });
                }

                if (!isValidPassword(user, password)) {
                    return done(null, false, { message: 'Contraseña incorrecta' });
                }
                return done(null, user); // Autenticación exitosa, retorno el usuario
            } catch (error) {
                return done(error);
            }
        }
    ));

    // Estrategia JWT para extraer y validar el token
    passport.use('jwt', new JWTStrategy(
        {
            jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]), // Extrae el token desde las cookies
            secretOrKey: PRIVATE_KEY, // Usamos la clave secreta para verificar el JWT
        },
        async (jwt_payload, done) => {
            try {
                // Aquí, se puede obtener el usuario asociado con el payload del JWT, si es necesario
                const user = await userService.findById(jwt_payload.id); // Asumimos que el ID está en el payload
                if (!user) {
                    return done(null, false, { message: 'Usuario no encontrado' });
                }
                return done(null, user); // Retorno el usuario
            } catch (error) {
                done(error);
            }
        }
    ));
    
    // Serialize y Deserialize para la sesión
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        let user = await userService.findById(id);
        done(null, user);
    });
};

export default initializePassport;
