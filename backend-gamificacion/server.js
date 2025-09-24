import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import nodemailer from "nodemailer"
import jwt from "jsonwebtoken"
import bcrypt from  "bcrypt"
import { Pool } from "pg"
import path from 'path';
import { fileURLToPath } from 'url';
  



const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;

// Define el origen exacto de tu frontend sin rutas ni subcarpetas
const FRONTEND_URL = process.env.FRONTEND_URL || "http://127.0.0.1:5500";

// Configuración base de datos PostgreSQL
const pool = new Pool({
  user: process.env.PGUSER || "Ken",
  host: process.env.PGHOST || "localhost",
  database: process.env.PGDATABASE || "mi_base",
  password: process.env.PGPASSWORD || "Ken1229",
  port: Number(process.env.PGPORT) || 5432,
});

// Configuración Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "grupogamificacion54@gmail.com",
    pass: process.env.EMAIL_PASS || "zubtguxppteimpkm",
  },
});

const JWT_SECRET =
  process.env.JWT_SECRET || "una_clave_secreta_muy_segura_y_larga";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// Middleware para validar token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.header("Authorization");
  const token = authHeader 
  console.log("Token recibido:", token); // Depuración del token recibido
  if (!token) return res.status(401).json({ error: "NO_AUTORIZADO" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "TOKEN_INVALIDO" });
    req.user = user;
    next();
  });
}

// Healthcheck
app.get("/health", (_req, res) => res.json({ ok: true }));

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) {
      return res.status(400).json({ error: "EMAIL_Y_PASSWORD_OBLIGATORIOS" });
    }

    // Buscar por correo, usuario o nombre
    const query =
      'SELECT id, nombre, usuario, tipo_usuario, correo, contraseña, monedas FROM usuarios WHERE correo = $1 OR usuario = $1 OR nombre = $1 LIMIT 1';
    const { rows } = await pool.query(query, [usernameOrEmail]);

    if (rows.length === 0) {
      return res.status(401).json({ error: "CREDENCIALES_INVALIDAS" });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.contraseña);
    if (!passwordMatch) {
      return res.status(401).json({ error: "CREDENCIALES_INVALIDAS" });
    }

    const token = jwt.sign(
      { userId: user.id, usuario: user.usuario, correo: user.correo, tipo_usuario: user.tipo_usuario },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({
      message: "Login exitoso",
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        usuario: user.usuario,
        correo: user.correo,
        tipo_usuario: user.tipo_usuario,
        monedas: user.monedas,
      },
    });
  } catch (err) {
    console.error("Error en /login:", err);
    return res.status(500).json({ error: "ERROR_INTERNO" });
  }
});

// REGISTRO
app.post("/register", async (req, res) => {
  try {
    const { nombre, usuario, correo, contraseña, tipo_usuario } = req.body;
    if (!nombre || !usuario || !correo || !contraseña || !tipo_usuario) {
      return res.status(400).json({ error: "DATOS_INCOMPLETOS" });
    }

    // Verificar que correo, usuario o nombre no existan
    const existsQuery =
      'SELECT 1 FROM usuarios WHERE correo = $1 OR usuario = $2 OR nombre = $3 LIMIT 1';
    const existsResult = await pool.query(existsQuery, [correo, usuario, nombre]);
    if (existsResult.rows.length > 0) {
      return res.status(409).json({ error: "USUARIO_O_EMAIL_EXISTE" });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(contraseña, 10);

    // Insertar usuario con monedas iniciales (ejemplo: 0)
    const insertQuery =
      'INSERT INTO usuarios (nombre, usuario, tipo_usuario, correo, contraseña, monedas) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, nombre, usuario, tipo_usuario, correo, monedas';
    const insertResult = await pool.query(insertQuery, [
      nombre,
      usuario,
      tipo_usuario,
      correo,
      hashedPassword,
      0,
    ]);

    const newUser  = insertResult.rows[0];

    return res.status(201).json({
      message: "Usuario registrado correctamente",
      user: newUser ,
    });
  } catch (err) {
    console.error("Error en /register:", err);
    return res.status(500).json({ error: "ERROR_INTERNO" });
  }
});

// RECUPERAR CONTRASEÑA
app.post("/recover", async (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ error: "El email es obligatorio." });

  try {
    const result = await pool.query(
      "SELECT id, nombre FROM usuarios WHERE correo = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({
        message: "Si el email existe, se ha enviado un enlace de recuperación.",
      });
    }

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    const resetLink = `${FRONTEND_URL}/reset-password.html?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER || "grupogamificacion54@gmail.com",
      to: email,
      subject: "Recuperación de contraseña",
      text: `Hola ${user.nombre},\n\nPara restablecer tu contraseña, haz clic en el siguiente enlace:\n\n${resetLink}\n\nSi no solicitaste este cambio, ignora este correo.`,
      html: `<p>Hola <b>${user.nombre}</b>,</p>
             <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
             <p><a href="${resetLink}">${resetLink}</a></p>
             <p>Si no solicitaste este cambio, ignora este correo.</p>`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({
      message: "Si el email existe, se ha enviado un enlace de recuperación.",
    });
  } catch (error) {
    console.error("Error en /recover:", error);
    return res.status(500).json({ error: "ERROR_INTERNO" });
  }
});

// RESET PASSWORD
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "Faltan datos." });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      'UPDATE usuarios SET contraseña = $1 WHERE id = $2',
      [hashedPassword, payload.userId]
    );

    return res.json({ message: "Contraseña actualizada correctamente." });
  } catch (error) {
    console.error("Error en /reset-password:", error);
    return res.status(400).json({ error: "Token inválido o expirado." });
  }
});

// Obtener todos los personajes
app.get("/api/personajes", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM personajes ORDER BY id");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "ERROR_INTERNO" });
  }
});

// Obtener personajes comprados por usuario (protegido)
app.get("/api/usuarios/:id/personajes", authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) return res.status(400).json({ error: "ID_INVALIDO" });

  if (userId !== req.user.userId)
    return res.status(403).json({ error: "ACCESO_DENEGADO" });

  try {
    const query = `
      SELECT p.* FROM personajes p
      JOIN usuarios_personajes up ON p.id = up.id_personaje
      WHERE up.id_usuario = $1
    `;
    const result = await pool.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "ERROR_INTERNO" });
  }
});

// Comprar personaje para usuario (protegido) con transacción y fecha de adquisición
app.post(
  "/api/usuarios/:id/personajes",
  authenticateToken,
  async (req, res) => {
    const userId = parseInt(req.params.id);
    const { id_personaje } = req.body;

    if (isNaN(userId) || !id_personaje) {
      return res.status(400).json({ error: "DATOS_INVALIDOS" });
    }

    if (userId !== req.user.userId) {
      return res.status(403).json({ error: "ACCESO_DENEGADO" });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

     // Obtener monedas del usuario con bloqueo FOR UPDATE para evitar condiciones de carrera
      const userRes = await client.query(
        "SELECT monedas FROM usuarios WHERE id = $1 FOR UPDATE",
        [userId]
      );
      if (userRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "USUARIO_NO_ENCONTRADO" });
      }
      const monedas = userRes.rows[0].monedas;

      // Obtener precio personaje
      const charRes = await client.query(
        "SELECT precio FROM personajes WHERE id = $1",
        [id_personaje]
      );
      if (charRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "PERSONAJE_NO_ENCONTRADO" });
      }
      const precio = charRes.rows[0].precio;

      if (monedas < precio) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "MONEDAS_INSUFICIENTES" });
      }

      // Verificar si ya tiene el personaje
      const ownedRes = await client.query(
        "SELECT 1 FROM usuarios_personajes WHERE id_usuario = $1 AND id_personaje = $2",
        [userId, id_personaje]
      );
      if (ownedRes.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "PERSONAJE_YA_COMPRADO" });
      }

      // Insertar personaje comprado con fecha de adquisición
      await client.query(
        "INSERT INTO usuarios_personajes (id_usuario, id_personaje, fecha_adquisicion) VALUES ($1, $2, $3)",
        [userId, id_personaje, new Date()]
      );

      // Restar monedas al usuario
      await client.query(
        "UPDATE usuarios SET monedas = monedas - $1 WHERE id = $2",
        [precio, userId]
      );

      await client.query("COMMIT");

      res.json({ message: "Compra exitosa" });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Error en compra de personaje:", err);
      res.status(500).json({ error: "ERROR_INTERNO" });
    } finally {
      client.release();
    }
  }
);
      // Ruta para obtener las monedas del usuario
app.get("/monedas", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;  // Obtener el ID del usuario desde el token JWT
    const result = await pool.query('SELECT monedas FROM usuarios WHERE id = $1', [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const monedas = result.rows[0].monedas;  // Obtener las monedas del usuario
    return res.json({ monedas }); // Responder con las monedas
  } catch (err) {
    console.error('Error al obtener monedas:', err);
    return res.status(500).json({ error: 'Error interno al obtener monedas' });
  }
});
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});