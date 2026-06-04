const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'mi_llave_secreta_super_segura_para_phq9';

// 🛠️ CONFIGURACIÓN DEL MOTOR DE VISTAS (Apuntando a tu carpeta 'templates')
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

// MIDDLEWARES DE PROCESAMIENTO GENERAL
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// 💾 CONEXIÓN CENTRAL A LA BASE DE DATOS SQLITE
const db = new sqlite3.Database(path.join(__dirname, 'database.db'), (err) => {
    if (err) console.error('⚠️ Error al conectar con SQLite:', err.message);
    else console.log('💾 Conectado exitosamente a database.db a través de Node.js');
});

// 🗄️ AUTOMATIZACIÓN DEL ESQUEMA (Para Render y entornos limpios)
const schemaPath = path.join(__dirname, 'schema.sql');
if (fs.existsSync(schemaPath)) {
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    db.exec(schemaSql, (err) => {
        if (err) {
            console.error("❌ Error crítico al inyectar el esquema SQL:", err.message);
        } else {
            console.log("🗄️ Tablas de la base de datos estructuradas con éxito desde schema.sql");
        }
    });
} else {
    console.log("⚠️ No se encontró el archivo schema.sql para inicializar las tablas.");
}




// 🔒 MIDDLEWARE DE CONTROL DE ACCESO (Verificación de Sesión vía JWT)
const verificarSesion = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/?error=Debes iniciar sesión para acceder.');

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            res.clearCookie('token');
            return res.redirect('/?error=Sesión expirada o inválida.');
        }
        req.user = decoded; // Inyecta los datos de identidad (id, username, rol, nombre) en la petición
        next();
    });
};

// ==========================================
// 🛣️ CONTROLADORES Y RUTAS DE AUTENTICACIÓN
// ==========================================

// Vista de Inicio de Sesión (Login)
app.get('/', (req, res) => {
    res.render('login', { 
        error: req.query.error || '', 
        success: req.query.success || '' 
    });
});

// Procesar Formulario de Inicio de Sesión
app.post('/login', (req, res) => {
    const { username, password, rol } = req.body;

    db.get('SELECT * FROM usuarios WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.redirect('/?error=Credenciales incorrectas o usuario inexistente.');
        }

        // Bloqueo preventivo si la matrícula del alumno fue dada de baja
        if (user.activo === 0) {
            return res.redirect('/?error=Tu cuenta ha sido dada de baja del sistema. Contacta a orientación.');
        }

        // Validación estricta de coherencia de roles
        if (user.rol !== rol) {
            return res.redirect('/?error=El rol seleccionado no corresponde a tu usuario.');
        }

        try {
            // Comparación segura del Hash criptográfico de la contraseña
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.redirect('/?error=Credenciales incorrectas.');
            }

            // Firma digital del Token de Identidad con expiración de 2 horas
            const token = jwt.sign(
                { id: user.id, username: user.username, rol: user.rol, nombre: user.nombre },
                JWT_SECRET,
                { expiresIn: '2h' }
            );

            // Resguardo del Token en una Cookie HTTP-Only inmune a scripts maliciosos (XSS)
            res.cookie('token', token, {
                httpOnly: true,
                secure: false, // Cambiar a true cuando utilices producción bajo entornos HTTPS
                sameSite: 'Lax'
            });

            // Redirección en cascada según privilegios del usuario
            if (user.rol === 'maestro') {
                return res.redirect('/maestro/dashboard');
            } else {
                return res.redirect('/alumno/dashboard');
            }

        } catch (error) {
            return res.redirect('/?error=Error interno del servidor al verificar credenciales.');
        }
    });
});

// Vista del Formulario de Registro
app.get('/registro', (req, res) => {
    res.render('registro', { 
        error: req.query.error || '', 
        success: req.query.success || '' 
    });
});

// Procesar Creación de Nuevas Cuentas
app.post('/registro', async (req, res) => {
    const f = req.body;
    const { username, password, nombre, rol, carrera, genero, semestre, colonia, estatus } = f;

    // 🛡️ BARRERA DE CONTROL: VALIDACIÓN DE PRIVILEGIOS DOCENTES
    if (rol === 'maestro') {
        const clave_ingresada = f.clave_maestro;
        if (clave_ingresada !== "DOCENTE123") {
            return res.redirect('/registro?error=La clave de validación docente es incorrecta.');
        }
    }

    // Verificar unicidad de la matrícula o número de control
    db.get('SELECT id FROM usuarios WHERE username = ?', [username], async (err, row) => {
        if (row) {
            return res.redirect('/registro?error=Error: Ese Número de Control o Usuario ya está registrado.');
        }

        try {
            // Encriptación asíncrona irreversible con un factor de salteado de 10 rondas
            const passwordHash = await bcrypt.hash(password, 10);

            // Formatear campos condicionales en caso de tratarse de un registro docente
            let dia_n = rol === 'maestro' ? 0 : parseInt(f.dia_nacimiento);
            let mes_n = rol === 'maestro' ? 'N/A' : f.mes_nacimiento;
            let anio_n = rol === 'maestro' ? 0 : parseInt(f.anio_nacimiento);
            let semestre_ajustado = rol === 'maestro' ? 'N/A' : semestre;

            const sql = `INSERT INTO usuarios 
                (username, password, nombre, rol, carrera, genero, semestre, dia_nacimiento, mes_nacimiento, anio_nacimiento, colonia, estatus_socioeconomico) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

            db.run(sql, [username, passwordHash, nombre, rol, carrera, genero, semestre_ajustado, dia_n, mes_n, anio_n, colonia, estatus], function(err) {
                if (err) {
                    return res.redirect('/registro?error=Error al escribir el registro en la base de datos.');
                }
                return res.redirect('/?success=¡Cuenta creada con éxito! Ya puedes iniciar sesión de forma segura.');
            });

        } catch (error) {
            return res.redirect('/registro?error=Error crítico al procesar el cifrado de datos.');
        }
    });
});

// Cierre Seguro de Sesiones (Destrucción de Cookies de Identidad)
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/?success=Sesión cerrada correctamente.');
});

// ==========================================
// 🧠 VISTAS Y LOGICA OPERATIVA DEL ALUMNO
// ==========================================

app.get('/alumno/dashboard', verificarSesion, (req, res) => {
    if (req.user.rol !== 'alumno') return res.redirect('/?error=Acceso denegado.');
    res.render('dashboard_alumno', { nombre: req.user.nombre });
});

app.get('/alumno/prueba', verificarSesion, (req, res) => {
    if (req.user.rol !== 'alumno') return res.redirect('/?error=Acceso denegado.');
    res.render('prueba');
});

// 🚀 ENTRADA EVALUATIVA HÍBRIDA: CONSUMO ASÍNCRONO DEL MICROSERVICIO DE IA
app.post('/alumno/prueba', verificarSesion, async (req, res) => {
    if (req.user.rol !== 'alumno') return res.redirect('/?error=Acceso denegado.');

    try {
        const respuestas = [];
        for (let i = 1; i <= 11; i++) {
            if (!req.body[`q${i}`]) {
                return res.send("<h1>Error: Quedaron preguntas pendientes por responder.</h1>");
            }
            respuestas.push(parseInt(req.body[`q${i}`]));
        }

        // 1. Persistencia de respuestas crudas en SQLite para auditorías del psicólogo
        const sqlInsert = `INSERT INTO respuestas_rutina 
            (usuario_id, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
        db.run(sqlInsert, [req.user.id, ...respuestas], async function(err) {
            if (err) {
                return res.send("<h1>Error local al resguardar las respuestas en la base de datos.</h1>");
            }

            // Configuración elástica de URL: Lee Render en producción o cae a localhost en desarrollo
            const pythonServiceUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:5001';

            // 2. LLAMADA INTERNA AL MICROSERVICIO DE IA (Python Flask)
            try {
                const responseIA = await fetch(`${pythonServiceUrl}/api/predict`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ respuestas: respuestas })
                });

                if (!responseIA.ok) throw new Error('Fallo en la respuesta del motor de IA.');

                const dataIA = await responseIA.json();

                // 🌟 PARCHE DE INGENIERÍA: Quitamos los corchetes y forzamos un entero puro
                // Convierte "[4]" o "4" directamente en el número 4
                const valorLimpio = String(dataIA.prediccion).replace(/[\[\]]/g, '');
                const puntuacionNumero = parseInt(valorLimpio, 10);

                // 3. Renderizar la tarjeta pasando el número limpio a la plantilla
                res.render('resultado_rutina', { prediccion: puntuacionNumero });
            } catch (errorIA) {
                console.error("⚠️ Error de enlace híbrido:", errorIA.message);
                res.send(`
                    <h1>Error de Conexión Híbrida</h1>
                    <p>El servidor central de Node.js no pudo enlazar con el microservicio de IA en Python.</p>
                    <p><b>Dirección enlazada:</b> <code style="background:#f1f5f9; padding:2px 6px; border-radius:4px;">${pythonServiceUrl}/api/predict</code></p>
                    <p><i>Por favor, confirma que el servicio de Python esté activo y operando correctamente.</i></p>
                `);
            }
        });

    } catch (error) {
        res.send("<h1>Error de procesamiento de datos evaluativos.</h1>");
    }
});
app.get('/alumno/test_completo', verificarSesion, (req, res) => {
    if (req.user.rol !== 'alumno') return res.redirect('/?error=Acceso denegado.');
    res.render('test_completo');
});

app.post('/alumno/test_completo', verificarSesion, (req, res) => {
    if (req.user.rol !== 'alumno') return res.redirect('/?error=Acceso denegado.');

    let puntaje_total = 0;
    for (let i = 1; i <= 9; i++) {
        puntaje_total += parseInt(req.body[`p${i}`]);
    }

    // Clasificación clínica estandarizada del instrumento PHQ-9
    let nivel_depresion = "";
    if (puntaje_total <= 4) nivel_depresion = "Depresión Mínima";
    else if (puntaje_total <= 9) nivel_depresion = "Depresión Leve";
    else if (puntaje_total <= 14) nivel_depresion = "Depresión Moderada";
    else if (puntaje_total <= 19) nivel_depresion = "Depresión Moderadamente Grave";
    else nivel_depresion = "Depresión Grave";

    const sqlResult = `INSERT INTO resultados (usuario_id, puntaje, nivel) VALUES (?, ?, ?)`;
    db.run(sqlResult, [req.user.id, puntaje_total, nivel_depresion], function(err) {
        if (err) return res.send("<h1>Error al guardar el diagnóstico en el repositorio central.</h1>");
        res.render('resultado_final', { puntaje: puntaje_total, nivel: nivel_depresion });
    });
});

// ==========================================
// 📊 PANEL DE ADMINISTRACIÓN Y REPORTES (MAESTRO)
// ==========================================

app.get('/maestro/dashboard', verificarSesion, (req, res) => {
    if (req.user.rol !== 'maestro') return res.redirect('/?error=Acceso denegado.');

    const m_filtro = (req.query.matricula || '').trim();
    const c_filtro = (req.query.carrera || '').trim();
    const s_filtro = (req.query.semestre || '').trim();

    let queryResultados = `
        SELECT r.id, u.username, u.nombre, u.carrera, u.semestre, u.dia_nacimiento, u.mes_nacimiento, u.anio_nacimiento, u.colonia, u.estatus_socioeconomico, r.puntaje, r.nivel, datetime(r.fecha, 'localtime') AS fecha
        FROM resultados r
        JOIN usuarios u ON r.usuario_id = u.id
        WHERE 1=1
    `;
    let params = [];

    if (m_filtro) { queryResultados += " AND u.username LIKE ?"; params.push(`%${m_filtro}%`); }
    if (c_filtro) { queryResultados += " AND u.carrera = ?"; params.push(c_filtro); }
    if (s_filtro) { queryResultados += " AND u.semestre = ?"; params.push(s_filtro); }

    queryResultados += " ORDER BY r.fecha DESC";

    // Consulta en cascada para alimentar las listas de control del maestro de forma síncrona
    db.all(queryResultados, params, (err, resultados) => {
        if (err) return res.send("<h1>Error al indexar el historial clínico de alumnos.</h1>");

        db.all("SELECT * FROM usuarios WHERE rol = 'alumno' ORDER BY username ASC", [], (err, alumnos) => {
            if (err) return res.send("<h1>Error al indexar el listado de alumnos matriculados.</h1>");

            res.render('dashboard_maestro', {
                resultados,
                alumnos,
                m_old: m_filtro,
                c_old: c_filtro,
                s_old: s_filtro
            });
        });
    });
});

// Actualización manual e individual de semestres por alumno
app.post('/maestro/cambiar_semestre/:usuario_id', verificarSesion, (req, res) => {
    if (req.user.rol !== 'maestro') return res.redirect('/?error=Acceso denegado.');

    const { semestre } = req.body;
    const { usuario_id } = req.params;

    db.run('UPDATE usuarios SET semestre = ? WHERE id = ?', [semestre, usuario_id], (err) => {
        if (err) return res.send("<h1>Error al modificar la asignación del semestre.</h1>");
        res.redirect('/maestro/dashboard?success=Semestre modificado con éxito.');
    });
});

// Promoción masiva estructurada en bloques secuenciales de semestres (Bulk Promotion)
app.post('/maestro/promover_bulk', verificarSesion, (req, res) => {
    if (req.user.rol !== 'maestro') return res.redirect('/?error=Acceso denegado.');

    const ids_seleccionados = req.body.alumno_ids;
    if (!ids_seleccionados || ids_seleccionados.length === 0) {
        return res.redirect('/maestro/dashboard?error=Selecciona al menos un alumno para efectuar la promoción.');
    }

    const mapeoSiguienteSemestre = {
        "PRIMERO": "SEGUNDO", "SEGUNDO": "TERCERO", "TERCERO": "CUARTO",
        "CUARTO": "QUINTO", "QUINTO": "SEXTO", "SEXTO": "SEPTIMO",
        "SEPTIMO": "OCTAVO", "OCTAVO": "NOVENO", "NOVENO": "DECIMO",
        "DECIMO": "ONCEAVO", "ONCEAVO": "DOCEAVO", "DOCEAVO": "EGRESADO",
        "EGRESADO": "EGRESADO"
    };

    // Conversión de datos a arreglo en caso de recibir un único ID en el String binario
    const listaIds = Array.isArray(ids_seleccionados) ? ids_seleccionados : [ids_seleccionados];
    let completados = 0;

    listaIds.forEach(id => {
        db.get('SELECT semestre FROM usuarios WHERE id = ?', [id], (err, row) => {
            if (row && mapeoSiguienteSemestre[row.semestre]) {
                const nuevoSemestre = mapeoSiguienteSemestre[row.semestre];
                db.run('UPDATE usuarios SET semestre = ? WHERE id = ?', [nuevoSemestre, id], () => {
                    completados++;
                    if (completados === listaIds.length) {
                        res.redirect('/maestro/dashboard?success=Promoción en lote completada exitosamente.');
                    }
                });
            } else {
                completados++;
                if (completados === listaIds.length) res.redirect('/maestro/dashboard');
            }
        });
    });
});

// Alta o Baja administrativa de alumnos en el sistema (Matrícula Activa/Inactiva)
app.get('/maestro/toggle_status/:usuario_id', verificarSesion, (req, res) => {
    if (req.user.rol !== 'maestro') return res.redirect('/?error=Acceso denegado.');

    const { usuario_id } = req.params;

    db.get('SELECT activo FROM usuarios WHERE id = ?', [usuario_id], (err, row) => {
        if (row) {
            const nuevoEstado = row.activo === 1 ? 0 : 1;
            db.run('UPDATE usuarios SET activo = ? WHERE id = ?', [nuevoEstado, usuario_id], (err) => {
                res.redirect('/maestro/dashboard?success=Estado de la matrícula actualizado.');
            });
        } else {
            res.redirect('/maestro/dashboard');
        }
    });
});



// ==========================================
// 📄 GENERACIÓN DE REPORTES EN PDF (MAESTRO)
// ==========================================
app.get('/maestro/exportar_pdf', verificarSesion, (req, res) => {
    if (req.user.rol !== 'maestro') return res.redirect('/?error=Acceso denegado.');

    // Capturar los mismos filtros que tiene el maestro en su pantalla
    const m_filtro = (req.query.matricula || '').trim();
    const c_filtro = (req.query.carrera || '').trim();
    const s_filtro = (req.query.semestre || '').trim();

    let queryResultados = `
        SELECT r.id, u.username, u.nombre, u.carrera, u.semestre, r.puntaje, r.nivel, datetime(r.fecha, 'localtime') AS fecha
        FROM resultados r
        JOIN usuarios u ON r.usuario_id = u.id
        WHERE 1=1
    `;
    let params = [];

    if (m_filtro) { queryResultados += " AND u.username LIKE ?"; params.push(`%${m_filtro}%`); }
    if (c_filtro) { queryResultados += " AND u.carrera = ?"; params.push(c_filtro); }
    if (s_filtro) { queryResultados += " AND u.semestre = ?"; params.push(s_filtro); }

    queryResultados += " ORDER BY r.fecha DESC";

    // Consultar la base de datos con los filtros aplicados
    db.all(queryResultados, params, (err, resultados) => {
        if (err) return res.send("<h1>Error interno al procesar los datos para el reporte.</h1>");

        // Inicializar el documento PDF (Tamaño Carta con márgenes limpios)
        const doc = new PDFDocument({ size: 'LETTER', margin: 40 });
        
        // Configurar las cabeceras del navegador para forzar la descarga del PDF
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Reporte_PHQ9_${Date.now()}.pdf`);
        
        // Conectar el flujo del PDF directamente a la respuesta web del navegador
        doc.pipe(res);

        // ENCABEZADO INSTITUCIONAL DEL REPORTE
        doc.fillColor('#1e293b').fontSize(16).text('INSTITUTO TECNOLÓGICO SUPERIOR DE ALVARADO', { align: 'center', underline: true });
        doc.moveDown(0.3);
        doc.fontSize(12).fillColor('#3f51b5').text('Sistema de Evaluación Emocional - Reporte Clínico PHQ-9', { align: 'center' });
        doc.moveDown(0.5);
        doc.fontSize(9).fillColor('#64748b').text(`Generado por: ${req.user.nombre}  |  Fecha: ${new Date().toLocaleString('es-MX')}`, { align: 'center' });
        doc.moveDown(1.5);

        // CUADRO DE FILTROS APLICADOS
        doc.fillColor('#1e293b').fontSize(10).text('CRITERIOS DE BÚSQUEDA APLICADOS:', { underline: true });
        doc.fontSize(9).fillColor('#334155')
           .text(`• Matrícula/Control: ${m_filtro || 'TODOS'}`)
           .text(`• Programa Educativo / Carrera: ${c_filtro || 'TODAS LAS CARRERAS'}`)
           .text(`• Semestre Escolar: ${s_filtro || 'TODOS LOS SEMESTRES'}`);
        doc.moveDown(1.5);

        doc.fillColor('#cbd5e1').text('____________________________________________________________________________________________________');
        doc.moveDown(1.5);

        // VOLCADO DE DATOS (REPOSITORIO DE ALUMNOS)
        if (resultados.length === 0) {
            doc.fillColor('#64748b').fontSize(12).text('Ningún expediente clínico coincide con los filtros establecidos por la dirección.', { align: 'center' });
        } else {
            resultados.forEach((res, index) => {
                // Nombre completo y Matrícula
                doc.fillColor('#1e293b').fontSize(10).text(`${index + 1}. ALUMNO: ${res.nombre.toUpperCase()} (Control: ${res.username})`);
                
                // Detalles escolares y resultados clínicos
                doc.fillColor('#475569').fontSize(9)
                   .text(`   Carrera: ${res.carrera}   |   Semestre: ${res.semestre}`)
                   .text(`   Evaluación Básica PHQ-9: ${res.puntaje} puntos`)
                   .text(`   Veredicto de Salud Mental: ${res.nivel.toUpperCase()}`)
                   .text(`   Fecha de aplicación del test: ${res.fecha.substring(0, 16)}`);
                doc.moveDown(1);
            });
        }

        // Concluir la escritura física del archivo y enviarlo de vuelta
        doc.end();
    });
});


// ==========================================
// 🚀 INICIALIZACIÓN Y ENTORNO CLOUD (RENDER)
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor central de Node.js operando de forma exitosa en http://localhost:${PORT}`);
});