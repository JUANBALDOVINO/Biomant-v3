const express = require('express');
const mysql2 = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRA = process.env.JWT_EXPIRA || '8h';

if (!JWT_SECRET) {
    console.error('Falta JWT_SECRET en el archivo .env (ver instrucciones de instalación).');
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Configuración de la conexión a MySQL en XAMPP
const db = mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'biomant'
});

db.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        return;
    }
    console.log('¡Conectado exitosamente a la base de datos de XAMPP!');
});

// Panel visual de inventario (el propio index.html redirige al login si no hay sesión)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Vista de login
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Iniciar servidor
const PORT = 3000;

// =============================================================================
// AUTENTICACIÓN Y ROLES
// =============================================================================

const ROLES = ['Administrador', 'Tecnico'];

// Hash de relleno: permite comparar siempre contra un hash, exista o no el
// correo, para que el tiempo de respuesta no revele qué correos están registrados.
const HASH_RELLENO = bcrypt.hashSync('relleno-no-es-una-clave-real', 10);

// Exige una sesión válida (cabecera Authorization: Bearer <token>)
function verificarToken(req, res, next) {
    const cabecera = req.headers.authorization || '';
    const [esquema, token] = cabecera.split(' ');

    if (esquema !== 'Bearer' || !token) {
        res.status(401).json({ error: 'Debes iniciar sesión' });
        return;
    }

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) {
            res.status(401).json({ error: 'Sesión inválida o vencida' });
            return;
        }

        req.usuario = {
            id_usuario: payload.id_usuario,
            nombre: payload.nombre,
            correo: payload.correo,
            rol: payload.rol
        };
        next();
    });
}

// Exige además rol Administrador. Siempre se usa DESPUÉS de verificarToken.
function soloAdministrador(req, res, next) {
    if (!req.usuario || req.usuario.rol !== 'Administrador') {
        res.status(403).json({ error: 'Esta acción es solo para el rol Administrador' });
        return;
    }
    next();
}

// Iniciar sesión: devuelve un token JWT y los datos básicos del usuario
app.post('/api/login', (req, res) => {
    const { correo, password } = req.body || {};

    if (!correo || !password) {
        res.status(400).json({ error: 'Ingresa tu correo y tu contraseña' });
        return;
    }

    const query = 'SELECT id_usuario, nombre, correo, password, rol FROM usuarios WHERE correo = ?';

    db.query(query, [String(correo).trim().toLowerCase()], (err, results) => {
        if (err) {
            console.error('Error al consultar el usuario:', err);
            res.status(500).json({ error: 'Error al iniciar sesión' });
            return;
        }

        const encontrado = results[0];
        const hash = encontrado ? encontrado.password : HASH_RELLENO;

        bcrypt.compare(String(password), hash, (errHash, coincide) => {
            if (errHash) {
                console.error('Error al verificar la contraseña:', errHash);
                res.status(500).json({ error: 'Error al iniciar sesión' });
                return;
            }

            if (!encontrado || !coincide) {
                res.status(401).json({ error: 'Correo o contraseña incorrectos' });
                return;
            }

            const usuario = {
                id_usuario: encontrado.id_usuario,
                nombre: encontrado.nombre,
                correo: encontrado.correo,
                rol: encontrado.rol
            };

            const token = jwt.sign(usuario, JWT_SECRET, { expiresIn: JWT_EXPIRA });
            res.json({ token, usuario });
        });
    });
});

// Listar usuarios (solo Administrador). Nunca devuelve el hash.
app.get('/api/usuarios', verificarToken, soloAdministrador, (req, res) => {
    const query = 'SELECT id_usuario, nombre, correo, rol, creado_en FROM usuarios ORDER BY nombre';

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al listar usuarios:', err);
            res.status(500).json({ error: 'Error al obtener los usuarios' });
            return;
        }
        res.json(results);
    });
});

// Crear un usuario (solo Administrador). La contraseña se guarda con bcrypt.
app.post('/api/usuarios', verificarToken, soloAdministrador, (req, res) => {
    const { nombre, correo, password, rol } = req.body || {};
    const faltantes = ['nombre', 'correo', 'password', 'rol'].filter(
        (campo) => !req.body || !String(req.body[campo] ?? '').trim()
    );

    if (faltantes.length > 0) {
        res.status(400).json({ error: 'Faltan datos requeridos', campos_faltantes: faltantes });
        return;
    }

    if (!ROLES.includes(rol)) {
        res.status(400).json({ error: `El rol debe ser uno de: ${ROLES.join(', ')}` });
        return;
    }

    if (String(password).length < 8) {
        res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
        return;
    }

    bcrypt.hash(String(password), 10, (errHash, hash) => {
        if (errHash) {
            console.error('Error al cifrar la contraseña:', errHash);
            res.status(500).json({ error: 'Error al registrar el usuario' });
            return;
        }

        const query = 'INSERT INTO usuarios (nombre, correo, password, rol) VALUES (?, ?, ?, ?)';
        const valores = [String(nombre).trim(), String(correo).trim().toLowerCase(), hash, rol];

        db.query(query, valores, (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    res.status(409).json({ error: 'Ya existe un usuario con ese correo' });
                    return;
                }
                console.error('Error al crear el usuario:', err);
                res.status(500).json({ error: 'Error al registrar el usuario' });
                return;
            }

            res.status(201).json({
                mensaje: 'Usuario registrado correctamente',
                id_usuario: result.insertId
            });
        });
    });
});

// =============================================================================
// INVENTARIO DE EQUIPOS
// =============================================================================

// Todo /api/equipos requiere sesión iniciada (cualquier rol).
// Las acciones que modifican el inventario además exigen rol Administrador.
app.use('/api/equipos', verificarToken);

// Campos requeridos para crear o actualizar un equipo
const CAMPOS_EQUIPO = [
    'id_equipo',
    'nombre_equipo',
    'marca',
    'modelo',
    'numero_serie',
    'nivel_riesgo',
    'ubicacion',
    'estado',
    'tipo_categoria'
];

const CAMPOS_ACTUALIZACION = CAMPOS_EQUIPO.filter((campo) => campo !== 'id_equipo');

function validarCamposRequeridos(datos, campos) {
    return campos.filter((campo) => {
        const valor = datos[campo];
        return valor === undefined || valor === null || String(valor).trim() === '';
    });
}

// Ruta para obtener todos los equipos del inventario
app.get('/api/equipos', (req, res) => {
    const query = 'SELECT * FROM equipos';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al consultar los equipos:', err);
            res.status(500).json({ error: 'Error al obtener el inventario' });
            return;
        }
        res.json(results);
    });
});

// Filtrar equipos por categoría (Biomédico o Tecnología)
// Se declara antes de /:id para evitar que "buscar" se interprete como identificador
app.get('/api/equipos/buscar/categoria/:tipo', (req, res) => {
    const { tipo } = req.params;
    const query = 'SELECT * FROM equipos WHERE tipo_categoria = ?';

    db.query(query, [tipo], (err, results) => {
        if (err) {
            console.error('Error al filtrar equipos por categoría:', err);
            res.status(500).json({ error: 'Error al buscar equipos por categoría' });
            return;
        }
        res.json(results);
    });
});

// Obtener un equipo específico por id_equipo
app.get('/api/equipos/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM equipos WHERE id_equipo = ?';

    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al consultar el equipo:', err);
            res.status(500).json({ error: 'Error al obtener el equipo' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.json(results[0]);
    });
});

// Crear un nuevo equipo en el inventario (solo Administrador)
app.post('/api/equipos', soloAdministrador, (req, res) => {
    const faltantes = validarCamposRequeridos(req.body, CAMPOS_EQUIPO);

    if (faltantes.length > 0) {
        res.status(400).json({
            error: 'Faltan datos requeridos',
            campos_faltantes: faltantes
        });
        return;
    }

    const valores = CAMPOS_EQUIPO.map((campo) => req.body[campo]);
    const placeholders = CAMPOS_EQUIPO.map(() => '?').join(', ');
    const query = `INSERT INTO equipos (${CAMPOS_EQUIPO.join(', ')}) VALUES (${placeholders})`;

    db.query(query, valores, (err) => {
        if (err) {
            console.error('Error al crear el equipo:', err);
            res.status(500).json({ error: 'Error al registrar el equipo' });
            return;
        }

        res.status(201).json({
            mensaje: 'Equipo registrado correctamente',
            id_equipo: req.body.id_equipo
        });
    });
});

// Actualizar los datos de un equipo existente (solo Administrador)
app.put('/api/equipos/:id', soloAdministrador, (req, res) => {
    const { id } = req.params;
    const faltantes = validarCamposRequeridos(req.body, CAMPOS_ACTUALIZACION);

    if (faltantes.length > 0) {
        res.status(400).json({
            error: 'Faltan datos requeridos',
            campos_faltantes: faltantes
        });
        return;
    }

    const setClause = CAMPOS_ACTUALIZACION.map((campo) => `${campo} = ?`).join(', ');
    const valores = [...CAMPOS_ACTUALIZACION.map((campo) => req.body[campo]), id];
    const query = `UPDATE equipos SET ${setClause} WHERE id_equipo = ?`;

    db.query(query, valores, (err, result) => {
        if (err) {
            console.error('Error al actualizar el equipo:', err);
            res.status(500).json({ error: 'Error al actualizar el equipo' });
            return;
        }

        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.status(200).json({
            mensaje: 'Equipo actualizado correctamente',
            id_equipo: id
        });
    });
});

// Eliminar un equipo por su id_equipo (solo Administrador)
app.delete('/api/equipos/:id', soloAdministrador, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM equipos WHERE id_equipo = ?';

    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Error al eliminar el equipo:', err);
            res.status(500).json({ error: 'Error al eliminar el equipo' });
            return;
        }

        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.status(200).json({
            mensaje: 'Equipo eliminado correctamente',
            id_equipo: id
        });
    });
});

// -----------------------------------------------------------------------------
// ESTADO DEL EQUIPO
// Administrador: cualquier estado. Técnico: solo alterna entre Operativo y
// En mantenimiento; dar de baja o reactivar un equipo fuera de servicio es del Administrador.
// -----------------------------------------------------------------------------
const ESTADOS_EQUIPO = ['Operativo', 'En mantenimiento', 'Fuera de servicio'];

app.patch('/api/equipos/:id/estado', (req, res) => {
    const { id } = req.params;
    const pedido = String((req.body && req.body.estado) ?? '').trim().toLowerCase();
    const nuevo = ESTADOS_EQUIPO.find((estado) => estado.toLowerCase() === pedido);

    if (!nuevo) {
        res.status(400).json({ error: `El estado debe ser uno de: ${ESTADOS_EQUIPO.join(', ')}` });
        return;
    }

    db.query('SELECT estado FROM equipos WHERE id_equipo = ?', [id], (err, results) => {
        if (err) {
            console.error('Error al consultar el estado del equipo:', err);
            res.status(500).json({ error: 'Error al cambiar el estado' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        const actual = String(results[0].estado || '').toLowerCase();
        const afectaBaja = actual === 'fuera de servicio' || nuevo === 'Fuera de servicio';

        if (req.usuario.rol !== 'Administrador' && afectaBaja) {
            res.status(403).json({ error: 'Solo un Administrador puede dar de baja o reactivar un equipo' });
            return;
        }

        db.query('UPDATE equipos SET estado = ? WHERE id_equipo = ?', [nuevo, id], (errUpdate) => {
            if (errUpdate) {
                console.error('Error al cambiar el estado del equipo:', errUpdate);
                res.status(500).json({ error: 'Error al cambiar el estado' });
                return;
            }
            res.json({ mensaje: 'Estado actualizado correctamente', id_equipo: id, estado: nuevo });
        });
    });
});

// =============================================================================
// MANTENIMIENTOS
// Cualquier usuario con sesión consulta y registra. La fecha de un registro la
// edita el Administrador (cualquiera) o el Técnico que lo registró.
// =============================================================================

app.use('/api/mantenimientos', verificarToken);

const TIPOS_MANTENIMIENTO = ['Preventivo', 'Correctivo'];

const SELECT_MANTENIMIENTO = `
    SELECT m.id_mantenimiento, m.id_equipo, e.nombre_equipo, m.tipo,
           DATE_FORMAT(m.fecha, '%Y-%m-%d') AS fecha, m.detalle,
           m.id_usuario, u.nombre AS registrado_por
    FROM mantenimientos m
    JOIN equipos e ON e.id_equipo = m.id_equipo
    LEFT JOIN usuarios u ON u.id_usuario = m.id_usuario`;

function fechaHoy() {
    const ahora = new Date();
    return new Date(ahora.getTime() - ahora.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}

// Devuelve un mensaje de error, o null si la fecha (AAAA-MM-DD) es válida y no es futura
function errorDeFecha(fecha) {
    if (typeof fecha !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
        return 'La fecha debe tener el formato AAAA-MM-DD';
    }
    const parseada = new Date(`${fecha}T00:00:00Z`);
    if (Number.isNaN(parseada.getTime()) || parseada.toISOString().slice(0, 10) !== fecha) {
        return 'La fecha no es válida';
    }
    if (fecha < '2000-01-01') return 'La fecha es demasiado antigua';
    if (fecha > fechaHoy()) return 'La fecha no puede ser futura';
    return null;
}

function obtenerMantenimiento(id, callback) {
    db.query(`${SELECT_MANTENIMIENTO} WHERE m.id_mantenimiento = ?`, [id], (err, results) => {
        callback(err, results && results[0]);
    });
}

// Listar todo el historial, del más reciente al más antiguo
app.get('/api/mantenimientos', (req, res) => {
    db.query(`${SELECT_MANTENIMIENTO} ORDER BY m.fecha DESC, m.id_mantenimiento DESC`, (err, results) => {
        if (err) {
            console.error('Error al listar mantenimientos:', err);
            res.status(500).json({ error: 'Error al obtener el historial' });
            return;
        }
        res.json(results);
    });
});

// Registrar un mantenimiento nuevo; responde con la fila completa para pintarla al instante
app.post('/api/mantenimientos', (req, res) => {
    const { id_equipo, tipo, fecha } = req.body || {};
    const detalle = String((req.body && req.body.detalle) ?? '').trim();

    if (!id_equipo || !tipo || !fecha || !detalle) {
        res.status(400).json({ error: 'Faltan datos requeridos (equipo, tipo, fecha y detalle)' });
        return;
    }
    if (!TIPOS_MANTENIMIENTO.includes(tipo)) {
        res.status(400).json({ error: `El tipo debe ser: ${TIPOS_MANTENIMIENTO.join(' o ')}` });
        return;
    }
    const errorFecha = errorDeFecha(fecha);
    if (errorFecha) {
        res.status(400).json({ error: errorFecha });
        return;
    }
    if (detalle.length < 10 || detalle.length > 2000) {
        res.status(400).json({ error: 'El detalle debe tener entre 10 y 2000 caracteres' });
        return;
    }

    db.query('SELECT 1 FROM equipos WHERE id_equipo = ?', [id_equipo], (err, existe) => {
        if (err) {
            console.error('Error al validar el equipo:', err);
            res.status(500).json({ error: 'Error al registrar el mantenimiento' });
            return;
        }
        if (existe.length === 0) {
            res.status(404).json({ error: 'El equipo no existe' });
            return;
        }

        const insertar = 'INSERT INTO mantenimientos (id_equipo, tipo, fecha, detalle, id_usuario) VALUES (?, ?, ?, ?, ?)';
        db.query(insertar, [id_equipo, tipo, fecha, detalle, req.usuario.id_usuario], (errInsert, result) => {
            if (errInsert) {
                console.error('Error al registrar el mantenimiento:', errInsert);
                res.status(500).json({ error: 'Error al registrar el mantenimiento' });
                return;
            }
            obtenerMantenimiento(result.insertId, (errFila, fila) => {
                if (errFila || !fila) {
                    console.error('Error al leer el mantenimiento creado:', errFila);
                    res.status(500).json({ error: 'El mantenimiento se guardó, pero no se pudo leer' });
                    return;
                }
                res.status(201).json(fila);
            });
        });
    });
});

// Corregir la fecha de un mantenimiento
app.patch('/api/mantenimientos/:id/fecha', (req, res) => {
    const { id } = req.params;
    const fecha = req.body && req.body.fecha;
    const errorFecha = errorDeFecha(fecha);

    if (errorFecha) {
        res.status(400).json({ error: errorFecha });
        return;
    }

    db.query('SELECT id_usuario FROM mantenimientos WHERE id_mantenimiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error al consultar el mantenimiento:', err);
            res.status(500).json({ error: 'Error al actualizar la fecha' });
            return;
        }
        if (results.length === 0) {
            res.status(404).json({ error: 'Mantenimiento no encontrado' });
            return;
        }

        const esAutor = results[0].id_usuario === req.usuario.id_usuario;
        if (req.usuario.rol !== 'Administrador' && !esAutor) {
            res.status(403).json({ error: 'Solo puedes editar la fecha de los mantenimientos que tú registraste' });
            return;
        }

        db.query('UPDATE mantenimientos SET fecha = ? WHERE id_mantenimiento = ?', [fecha, id], (errUpdate) => {
            if (errUpdate) {
                console.error('Error al actualizar la fecha:', errUpdate);
                res.status(500).json({ error: 'Error al actualizar la fecha' });
                return;
            }
            obtenerMantenimiento(id, (errFila, fila) => {
                if (errFila || !fila) {
                    res.status(500).json({ error: 'La fecha se guardó, pero no se pudo leer el registro' });
                    return;
                }
                res.json(fila);
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});