const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Importar el cliente de Supabase
const { createClient } = require('@supabase/supabase-js');
const DATABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
if (!DATABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error("Las variables SUPABASE_URL y SUPABASE_SERVICE_KEY deben estar definidas en el entorno.");
    process.exit(1);
}
const supabase = createClient(DATABASE_URL, SUPABASE_SERVICE_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta_muy_segura';

// Middleware de seguridad
app.use(helmet());
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3001',
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100 // máximo 100 requests por IP cada 15 minutos
});
app.use(limiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configurar multer para subida de archivos (se mantiene guardando en el sistema de archivos)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(uploadsDir, req.user.id.toString());
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB límite
    },
    fileFilter: function (req, file, cb) {
        // Filtrar tipos de archivo peligrosos
        const allowedTypes = /jpeg|jpg|png|gif|pdf|txt|doc|docx|xls|xlsx|zip|rar/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Tipo de archivo no permitido'));
        }
    }
});

// NOTA: La creación de tablas en Supabase se gestiona mediante migraciones o la consola de Supabase.
// Por ello, se elimina el bloque de creación de tablas que usaba SQLite.

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Rutas de autenticación
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password || !email) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insertar usuario en Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([{ username, password: hashedPassword, email }])
            .select();

        if (error) {
            if (error.message.includes('duplicate key value')) {
                return res.status(400).json({ error: 'Usuario o email ya existe' });
            }
            return res.status(500).json({ error: 'Error al crear usuario', details: error.message });
        }
        
        const newUser = data[0];
        const token = jwt.sign(
            { id: newUser.id, username: newUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.status(201).json({
            message: 'Usuario creado exitosamente',
            token: token,
            user: { id: newUser.id, username: newUser.username, email: newUser.email }
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        // Obtener usuario desde Supabase
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (error) {
            return res.status(500).json({ error: 'Error interno del servidor', details: error.message });
        }
        
        if (!data) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        const validPassword = await bcrypt.compare(password, data.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        const token = jwt.sign(
            { id: data.id, username: data.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login exitoso',
            token: token,
            user: { id: data.id, username: data.username, email: data.email }
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Rutas de archivos
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se seleccionó archivo' });
        }
        
        // Insertar información del archivo en Supabase
        const { data, error } = await supabase
            .from('files')
            .insert([{
                user_id: req.user.id,
                filename: req.file.filename,
                original_name: req.file.originalname,
                file_path: req.file.path,
                file_size: req.file.size,
                mime_type: req.file.mimetype
            }])
            .select();
            
        if (error) {
            return res.status(500).json({ error: 'Error al guardar archivo en base de datos', details: error.message });
        }
        
        const fileRecord = data[0];
        res.json({
            message: 'Archivo subido exitosamente',
            file: {
                id: fileRecord.id,
                filename: req.file.originalname,
                size: req.file.size,
                type: req.file.mimetype
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al subir archivo' });
    }
});

app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('files')
            .select('id, filename, original_name, file_size, mime_type, is_shared, uploaded_at')
            .eq('user_id', req.user.id);
            
        if (error) {
            return res.status(500).json({ error: 'Error al obtener archivos', details: error.message });
        }
        
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/files/:id/download', authenticateToken, async (req, res) => {
    try {
        const fileId = req.params.id;
        const { data: file, error } = await supabase
            .from('files')
            .select('*')
            .eq('id', fileId)
            .eq('user_id', req.user.id)
            .single();
            
        if (error) {
            return res.status(500).json({ error: 'Error al buscar archivo', details: error.message });
        }
        
        if (!file) {
            return res.status(404).json({ error: 'Archivo no encontrado' });
        }
        
        if (!fs.existsSync(file.file_path)) {
            return res.status(404).json({ error: 'Archivo físico no encontrado' });
        }
        
        res.download(file.file_path, file.original_name);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/files/:id/share', authenticateToken, async (req, res) => {
    try {
        const fileId = req.params.id;
        const shareToken = jwt.sign({ fileId: fileId }, JWT_SECRET, { expiresIn: '7d' });
        
        const { data, error } = await supabase
            .from('files')
            .update({ is_shared: true, share_token: shareToken })
            .eq('id', fileId)
            .eq('user_id', req.user.id);
            
        if (error) {
            return res.status(500).json({ error: 'Error al compartir archivo', details: error.message });
        }
        
        if (!data || data.length === 0) {
            return res.status(404).json({ error: 'Archivo no encontrado' });
        }
        
        res.json({
            message: 'Archivo compartido exitosamente',
            shareUrl: `${req.protocol}://${req.get('host')}/api/shared/${shareToken}`
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/shared/:token', async (req, res) => {
    const token = req.params.token;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { data: file, error } = await supabase
            .from('files')
            .select('*')
            .eq('id', decoded.fileId)
            .eq('is_shared', true)
            .eq('share_token', token)
            .single();
            
        if (error) {
            return res.status(500).json({ error: 'Error al obtener archivo compartido', details: error.message });
        }
        
        if (!file) {
            return res.status(404).json({ error: 'Archivo no encontrado o no compartido' });
        }
        
        if (!fs.existsSync(file.file_path)) {
            return res.status(404).json({ error: 'Archivo físico no encontrado' });
        }
        
        res.download(file.file_path, file.original_name);
    } catch (error) {
        res.status(500).json({ error: 'Token inválido o error interno', details: error.message });
    }
});

// Agrega esta ruta antes de app.listen() u otro middleware similar.
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'El servidor está funcionando correctamente'
    });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
