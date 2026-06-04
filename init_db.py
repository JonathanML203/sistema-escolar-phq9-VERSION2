import sqlite3
from werkzeug.security import generate_password_hash

connection = sqlite3.connect('database.db')

with connection:
    cur = connection.cursor()
    # Borramos por orden para evitar conflictos de llaves foráneas
    cur.execute("DROP TABLE IF EXISTS respuestas_rutina;")
    cur.execute("DROP TABLE IF EXISTS resultados;")
    cur.execute("DROP TABLE IF EXISTS usuarios;")

    # 👥 Tabla de Usuarios (Con campos demográficos extendidos)
    cur.execute("""
    CREATE TABLE usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        nombre TEXT NOT NULL,
        rol TEXT NOT NULL,
        carrera TEXT,
        genero TEXT,
        semestre TEXT,
        dia_nacimiento INTEGER,
        mes_nacimiento TEXT,
        anio_nacimiento INTEGER,
        colonia TEXT,
        estatus_socioeconomico TEXT,
        activo INTEGER DEFAULT 1 
    );
    """)

    # 🧠 Tabla de Respuestas Detalladas de la Rutina (Para auditoría del psicólogo)
    cur.execute("""
    CREATE TABLE respuestas_rutina (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        q1 INTEGER, q2 INTEGER, q3 INTEGER, q4 INTEGER, q5 INTEGER,
        q6 INTEGER, q7 INTEGER, q8 INTEGER, q9 INTEGER, q10 INTEGER, q11 INTEGER,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
    );
    """)

    # 📋 Tabla de Resultados del Diagnóstico Clínico PHQ-9 Final
    cur.execute("""
    CREATE TABLE resultados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        puntaje INTEGER NOT NULL,
        nivel TEXT NOT NULL,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
    );
    """)

    # Usuario Maestro inicial para pruebas
    pass_hash = generate_password_hash('123')
    cur.execute("INSERT INTO usuarios (username, password, nombre, rol) VALUES (?, ?, ?, ?)",
                ('admin', pass_hash, 'Profesor de Prueba', 'maestro'))

connection.commit()
connection.close()
print("¡Base de datos limpia y configurada con éxito con todos los requerimientos!")