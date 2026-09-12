// ============================================================
// AUTH.JS — HU-01: inicio de sesión, JWT y rutas protegidas.
// Toda la lógica de autenticación vive aquí; cualquier página
// que necesite sesión solo llama a requerirAutenticacion() al cargar.
// ============================================================

const CLAVE_TOKEN = "pgc_token";

/** Guarda el JWT recibido del backend. */
function guardarToken(token) {
  localStorage.setItem(CLAVE_TOKEN, token);
}

/** Devuelve el JWT guardado, o null si no hay sesión. */
function obtenerToken() {
  return localStorage.getItem(CLAVE_TOKEN);
}

/** Elimina el JWT (cierre de sesión). */
function eliminarToken() {
  localStorage.removeItem(CLAVE_TOKEN);
}

/**
 * true si hay un token guardado y no está vencido.
 * La validación de firma la hace siempre el backend; aquí
 * solo evitamos mandar a la interfaz un token ya caducado.
 */
function estaAutenticado() {
  const token = obtenerToken();
  if (!token) return false;
  const payload = decodificarJWT(token);
  if (!payload || !payload.exp) return false;
  return payload.exp * 1000 > Date.now();
}

/** Devuelve el payload del usuario actual (id, nombre, rol...) o null. */
function obtenerUsuario() {
  const token = obtenerToken();
  return token ? decodificarJWT(token) : null;
}

/**
 * Intenta iniciar sesión contra la API.
 * Devuelve { ok: true, data } o { ok: false, mensaje, campos }
 * — pensado para alimentar directamente mostrarBanner().
 */
async function iniciarSesion(correo, clave) {
  if (!correo || !clave) {
    return { ok: false, mensaje: "Debe completar todos los campos.", campos: ["f-correo", "f-clave"] };
  }

  try {
    const res = await fetch(`${URL_API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ correo, clave }),
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 404 || data.codigo === "CORREO_NO_REGISTRADO") {
      return { ok: false, mensaje: "Correo electrónico no registrado.", campos: ["f-correo"] };
    }
    if (res.status === 401 || data.codigo === "CLAVE_INCORRECTA") {
      return { ok: false, mensaje: "Contraseña incorrecta.", campos: ["f-clave"] };
    }
    if (!res.ok) {
      return { ok: false, mensaje: data.mensaje || "No fue posible iniciar sesión.", campos: [] };
    }

    guardarToken(data.token);
    return { ok: true, data };
  } catch (e) {
    return { ok: false, mensaje: "No fue posible conectar con el servidor.", campos: [] };
  }
}

/**
 * Cierra la sesión y redirige al login.
 * @param {string} [mensaje] - si se pasa, se muestra en index.html
 *   (por ejemplo "Sesión expirada.").
 */
function cerrarSesion(mensaje) {
  eliminarToken();
  const destino = mensaje ? `index.html?msg=${encodeURIComponent(mensaje)}` : "index.html";
  window.location.href = destino;
}

/**
 * "Middleware" de rutas protegidas del lado del frontend.
 * Se llama al inicio de cada página que requiera sesión
 * (dashboard, usuarios, reportes, perfil). Si no hay sesión
 * válida, redirige al login con el mensaje del HU-01.
 */
function requerirAutenticacion() {
  if (!estaAutenticado()) {
    cerrarSesion("Debe iniciar sesión para acceder a esta página.");
  }
}
