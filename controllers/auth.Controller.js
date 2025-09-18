// controllers/auth.Controller.js  (ESM)
import UserModel from '../models/User.js';   // <-- usa el default export del modelo
import { signJwt } from '../lib/jwt.js';

// POST /auth/register
export const register = async (req, res, next) => {
  try {
    const { nombre, email, password, role = 'user', edad, ...extras } = req.body;

    // ¿ya existe el email?
    const exists = await UserModel.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email ya registrado' });

    // Si usas discriminators, estarán en UserModel.discriminators
    const Discriminators = UserModel.discriminators || {};
    const ModelToUse =
      role === 'admin' && Discriminators.admin ? Discriminators.admin :
      role === 'staff' && Discriminators.staff ? Discriminators.staff :
      Discriminators.user || UserModel;

    const user = await ModelToUse.create({ nombre, email, password, role, edad, ...extras });

    const token = signJwt({ id: user._id.toString(), email: user.email, role: user.role });
    res.status(201).json({ token });
  } catch (e) {
    next(e);
  }
};

// POST /auth/login
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // OJO: password tiene select:false en el modelo, hay que pedirlo explícitamente
    const user = await UserModel.findOne({ email }).select('+password');
    if (!user) return res.status(400).json({ error: 'Credenciales inválidas' });

    const ok = await user.comparePassword(password);
    if (!ok) return res.status(400).json({ error: 'Credenciales inválidas' });

    const token = signJwt({ id: user._id.toString(), email: user.email, role: user.role });
    res.json({ token });
  } catch (e) {
    next(e);
  }
};
