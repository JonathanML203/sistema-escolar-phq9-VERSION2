CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    genero TEXT,
    carrera TEXT,
    semestre TEXT,
    dia_nacimiento TEXT,
    mes_nacimiento TEXT,
    anio_nacimiento TEXT,
    colonia TEXT,
    estatus_socioeconomico TEXT,
    rol TEXT DEFAULT 'alumno',
    activo INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS respuestas_rutina (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    q1 INTEGER, q2 INTEGER, q3 INTEGER, q4 INTEGER, q5 INTEGER,
    q6 INTEGER, q7 INTEGER, q8 INTEGER, q9 INTEGER, q10 INTEGER, q11 INTEGER,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);

-- 🧠 Tabla para el control clínico del Psicólogo (4 funciones integradas)
CREATE TABLE IF NOT EXISTS seguimiento_clinico (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER UNIQUE,
    estado TEXT DEFAULT 'Pendiente de Cita',
    notas_clinicas TEXT DEFAULT '',
    alerta_critica INTEGER DEFAULT 0, -- 1 si la pregunta 9 es alta
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS resultados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    puntaje INTEGER,
    nivel TEXT,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);