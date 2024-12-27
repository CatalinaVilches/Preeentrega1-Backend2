import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import jwt from 'jsonwebtoken';

// Crear una constante llamada createHash
// Es una función que recibe un password como argumento y genera:
//   * Genera un salt (una cadena aleatoria de 10 caracteres) 
//   * Genera el hash del password usando el salt
//   * Devuelve el hash del password 
export const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

// Crear una constante llamada isValidPassword
// Compara el password con el password hasheado almacenado en el objeto user
// Devuelve true si el password coincide con el password hasheado, false en caso contrario
export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);

// Passport middleware para la autenticación
export const passportCall = (strategy) => {
  return async (req, res, next) => {
    passport.authenticate(strategy, function(err, user, info) {
      if (err) return next(err);
      if (!user) {
        return res.status(401).send({ error: info.messages ? info.messages : info.toString() });
      }
      req.user = user;
      next();
    })(req, res, next);
  };
};

// Middleware de autorización para roles específicos
export const authorization = (role) => {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).send({ message: 'Unauthorized' });
    if (req.user.role !== role) 
      return res.status(403).send({ error: "No permissions" });
    next();
  };
};

// Estrategia Passport para extraer el token de la cookie y obtener el usuario
export const passportCurrentStrategy = (PRIVATE_KEY) => {
  passport.use('current', new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]), // Función que extrae el token de las cookies
      secretOrKey: PRIVATE_KEY, // El mismo secreto que usas para generar el JWT
    },
    async (jwt_payload, done) => {
      try {
        // Suponiendo que tienes un modelo de usuario, busca el usuario por el ID del payload
        const user = await User.findById(jwt_payload.id); // Asegúrate de que este modelo de usuario existe
        if (!user) {
          return done(null, false, { message: 'User not found' });
        }
        return done(null, user);
      } catch (error) {
        return done(error, false);
      }
    }
  ));
};

// Función para extraer el token de las cookies
const cookieExtractor = (req) => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['token'];  // Asumiendo que el token se guarda en una cookie llamada 'token'
  }
  return token;
};

// Definir __filename y __dirname para obtener la ruta del archivo actual
const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);
