import express from 'express';
import User from '../models/user.models.js';
import { createHash, isValidPassword } from '../utils.js';
import jwt from 'jsonwebtoken';
import passport from 'passport';

const router = express.Router();
const JWT_SECRET = 'coderSecret';  // Clave secreta para firmar el JWT

// **Registración**
router.post('/register', async (req, res) => {
    try {
        const { first_name, last_name, email, age, password } = req.body;

        // Verificar que todos los campos estén presentes
        if (!first_name || !last_name || !email || !age || !password) {
            return res.status(400).send({ status: false, message: 'All fields are required' });
        }

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ status: false, message: 'User already exists' });
        }

        // Crear el nuevo usuario con la contraseña en hash
        let newUser = new User({
            first_name,
            last_name,
            email,
            age,
            password: createHash(password)
        });

        // Guardar en la base de datos
        await newUser.save();

        // Generar un token JWT con el usuario recién creado
        const token = jwt.sign({ id: newUser._id, email: newUser.email, role: 'user' }, JWT_SECRET, { expiresIn: '24h' });

        // Enviar el token al cliente
        res.status(201).send({ status: 'success', access_token: token });

    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).send('Error al registrar usuario');
    }
});

// **Iniciar sesión** (con JWT en cookie)
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).send({ status: "error", message: 'Incomplete values' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).send('Usuario no encontrado');
        }

        if (!isValidPassword(user, password)) {
            return res.status(403).send({ status: "error", message: 'Contraseña incorrecta' });
        }

        // Generar token JWT con la información del usuario
        const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        // Enviar el token en una cookie httpOnly
        res.cookie('tokenCookie', token, { httpOnly: true, maxAge: 60 * 60 * 1000 }).send({ message: 'Login exitoso' });

    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).send('Error al iniciar sesión');
    }
});

// **Iniciar sesión** (con JWT en la respuesta)
router.post('/loginLocalStorage', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).send({ message: 'Usuario no encontrado' });
        }

        if (!isValidPassword(user, password)) {
            return res.status(403).send({ message: 'Contraseña incorrecta' });
        }

        // Generar el token JWT
        const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        // Enviar el token en la respuesta
        res.send({ message: 'Login exitoso', token });

    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).send('Error al iniciar sesión');
    }
});

// **Restauración de contraseña**
router.post('/restore-password', async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ status: 'error', message: 'User not found' });
        }

        // Crear un nuevo hash de la contraseña
        user.password = createHash(newPassword);
        await user.save();

        return res.send({ status: 'success', message: 'Password updated successfully' });

    } catch (error) {
        return res.status(500).send({ status: 'error', message: 'Internal server error' });
    }
});

// **Cerrar sesión** (eliminar cookie JWT)
router.post('/logout', (req, res) => {
    // Eliminar la cookie que contiene el token JWT
    res.clearCookie('tokenCookie').send({ message: 'Logout exitoso' });
});

// **Ruta /current**: Obtener datos del usuario a partir del JWT en las cookies
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
    // Si se autentica correctamente, el usuario estará en req.user
    res.send({ status: 'success', user: req.user });
});

export default router;
