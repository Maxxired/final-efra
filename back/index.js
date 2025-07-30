// index.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

const JWT_SECRET       = process.env.JWT_SECRET       || 'secreto123';
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || 'TU_SECRET_KEY';
const DISCORD_WEBHOOK  = process.env.DISCORD_WEBHOOK  || null;

// Conexión a PostgreSQL
const client = new Client({
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 5432,
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME     || 'mydb',
});

client.connect(err => {
  if (err) {
    console.error('Error al conectar con la base de datos', err);
  } else {
    console.log('Conectado a la base de datos PostgreSQL');
    client.query(`
      CREATE TABLE IF NOT EXISTS formulario (
        id SERIAL PRIMARY KEY,
        nombre TEXT,
        correo TEXT,
        telefono TEXT,
        mensaje TEXT,
        estado TEXT DEFAULT 'nuevo',
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        usuario TEXT UNIQUE,
        password TEXT
      );
    `, (err) => {
      if (err) console.error('Error al crear tablas', err);
    });
  }
});

app.use(cors());
app.use(express.json());

// Funcion para sanitizar inputs
function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/<[^>]*>?/gm, '').trim();
}

// Middleware de verificación de JWT
function verificarToken(req, res, next) {
  const auth = req.headers['authorization']?.split(' ')[1];
  if (!auth) return res.status(401).json({ error: 'Token requerido' });
  jwt.verify(auth, JWT_SECRET, (e, user) => {
    if (e) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// — POST /register
app.post('/register', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
        `INSERT INTO usuarios (usuario, password) VALUES ($1, $2) RETURNING id`,
        [usuario, hashedPassword]
    );
    res.status(201).json({
      success: true,
      mensaje: 'Usuario registrado con éxito',
      userId: result.rows[0].id,
    });
  } catch (error) {
    if (error.code === '23505') { // unique_violation
      return res.status(409).json({ error: 'Usuario ya existe' });
    }
    console.error('Error al registrar:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// — POST /login
app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  try {
    const result = await client.query(
        `SELECT * FROM usuarios WHERE usuario = $1`, [usuario]
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Credenciales inválidas' });
    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = jwt.sign(
        { id: row.id, usuario: row.usuario },
        JWT_SECRET,
        { expiresIn: '2h' }
    );
    res.json({ token });
  } catch (err) {
    console.error('Error al consultar la base de datos', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// — POST /formulario
app.post('/formulario', async (req, res) => {
  const { nombre, correo, telefono, mensaje, 'g-recaptcha-response': token } = req.body;
  if (!token) return res.status(400).json({ error: 'Falta el token de reCAPTCHA' });
  try {
    const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${RECAPTCHA_SECRET}&response=${token}`,
    });
    const data = await resp.json();
    if (!data.success) return res.status(400).json({ error: 'Falló reCAPTCHA' });

    const result = await client.query(
        `INSERT INTO formulario (nombre, correo, telefono, mensaje)
       VALUES ($1, $2, $3, $4) RETURNING id`,
        [sanitize(nombre), sanitize(correo), sanitize(telefono), sanitize(mensaje)]
    );
    const newId = result.rows[0].id;

    // Notificación a Discord (opcional)
    if (DISCORD_WEBHOOK) {
      fetch(DISCORD_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'CRM Bot',
          embeds: [{
            title: '📥 Nuevo lead recibido',
            fields: [
              { name: 'Nombre',  value: sanitize(nombre),  inline: true },
              { name: 'Correo',  value: sanitize(correo),  inline: true },
              { name: 'Teléfono', value: sanitize(telefono), inline: true },
              { name: 'Mensaje', value: sanitize(mensaje) }
            ],
            timestamp: new Date().toISOString()
          }]
        })
      }).catch(console.error);
    }

    res.status(201).json({
      success: true,
      lead: { id: newId, nombre, correo, telefono, mensaje }
    });
  } catch (e) {
    console.error('Error de verificación reCAPTCHA o DB', e);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// — GET /leads
app.get('/leads', verificarToken, async (req, res) => {
  const page    = parseInt(req.query.page)    || 1;
  const perPage = parseInt(req.query.perPage) || 10;
  const offset  = (page - 1) * perPage;
  try {
    const countRes = await client.query(`SELECT COUNT(*) AS total FROM formulario`);
    const total = parseInt(countRes.rows[0].total, 10);
    const result = await client.query(
        `SELECT * FROM formulario ORDER BY fecha DESC LIMIT $1 OFFSET $2`,
        [perPage, offset]
    );
    res.json({ total, page, perPage, leads: result.rows });
  } catch (err) {
    console.error('Error al obtener leads', err);
    res.status(500).json({ error: 'Error al obtener leads' });
  }
});

app.put('/leads/:id', verificarToken, async (req, res) => {
  const id     = req.params.id;
  const estado = sanitize(req.body.estado);
  if (!['nuevo','contactado','descartado'].includes(estado))
    return res.status(400).json({ error: 'Estado inválido' });
  try {
    await client.query(
        `UPDATE formulario SET estado = $1 WHERE id = $2`,
        [estado, id]
    );
    res.json({ success: true, mensaje: 'Estado actualizado' });
  } catch (err) {
    console.error('Error al actualizar estado', err);
    res.status(500).json({ error: 'Error al actualizar estado' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
