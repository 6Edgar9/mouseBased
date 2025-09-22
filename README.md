# MouseBased — Gestor de contraseñas con entropía basada en movimiento del ratón

**MouseBased** es un gestor de contraseñas local que genera contraseñas seguras usando entropía recogida de los movimientos del ratón. Las contraseñas se cifran con AES y se almacenan localmente en `passwords.json`. El acceso está protegido por una clave maestra que se configura la primera vez y se guarda cifrada en `master_key.json`.

> ⚠️ **Advertencia de seguridad:** Este proyecto es un ejemplo educativo. Si planeas usarlo en serio, sigue las recomendaciones de seguridad que se describen más abajo. No compartas tus archivos `passwords.json` ni `master_key.json` y respalda tus datos de forma segura.

## Características principales

- Generación de contraseñas a partir de movimientos del ratón (entropía del usuario).
- Cifrado simétrico (AES-CBC) de las contraseñas guardadas.
- Clave maestra protegida por PBKDF2 para derivar la clave de cifrado.
- Interfaz gráfica básica con Tkinter para generar, copiar y guardar contraseñas.
- Límite de intentos para verificar la clave maestra.

## Requisitos

- Python 3.8+
- Dependencias listadas en `requirements.txt`:
  - `pyperclip`
  - `pycryptodome`
- En Linux, instala el paquete del sistema que provea `tkinter` (ej. `python3-tk` en Debian/Ubuntu).

## Instalación

```bash
git clone https://github.com/6Edgar9/mouseBased.git
cd mouseBased

python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1
# Windows (cmd)
venv\Scripts\activate.bat

pip install -r requirements.txt
```

## Uso

1. Ejecuta el programa:
```bash
python mb.py
```

2. Si es la primera vez se te pedirá crear una **clave maestra**. Guárdala en un gestor seguro — si la pierdes, no podrás descifrar las contraseñas guardadas.
3. Mueve el ratón hasta completar la barra de progreso para generar la contraseña. Podrás copiarla al portapapeles o guardarla con un título.
4. Las contraseñas cifradas se almacenan en `passwords.json`. La clave maestra cifrada se almacena en `master_key.json`.

## Notas de seguridad y recomendaciones (muy importantes)

- **No uses salt estático embebido en el código.** Actualmente el proyecto usa `SALT = b"random_salt_value"`. Para mayor seguridad debes generar y almacenar un salt único con `os.urandom(16)` y asociarlo al `master_key.json` o a cada contraseña. Ejemplo: `salt = os.urandom(16)` y guarda el salt (no es secreto) junto al dato cifrado.
- **No uses AES-CBC sin autenticación.** AES-CBC necesita MAC/AEAD para detectar manipulación (ej. usar AES-GCM o encrypt-then-MAC con HMAC). Considera usar `AES.new(key, AES.MODE_GCM)` o `cryptography` con Fernet/ChaCha20-Poly1305/AEAD.
- **Protege los archivos en disco.** Ajusta permisos `600` en Unix (`chmod 600 passwords.json master_key.json`) y evita respaldos inseguros.
- **Mejora KDF.** PBKDF2 con iteraciones es aceptable, pero para mayor resistencia a GPU/ASIC considera `argon2-cffi` o `scrypt`/`bcrypt` modernos.
- **Evita almacenar la clave maestra en memoria más tiempo del necesario.** Borra variables sensibles después de su uso.
- **Backup y recuperación.** Diseña un plan de recuperación segura para usuarios que pierdan su clave maestra (por ejemplo: exportar una clave de recuperación cifrada por clave hardware).

## Posibles mejoras técnicas

- Reemplazar PBKDF2 por Argon2 para derivación de claves.
- Usar AES-GCM o ChaCha20-Poly1305 (AEAD) para cifrado autenticado.
- Generar y almacenar un `salt` único por usuario/dato y versionar el esquema de cifrado.
- Añadir exportación cifrada y funciones de importación/restore.
- Añadir bloqueo automático tras inactividad y logs de auditoría con protección de integridad.
- Añadir integración con gestores hardware (YubiKey) o con el almacén de claves del sistema (Keychain, Windows DPAPI, libsecret).
- Añadir tests automáticos (pytest) y análisis estático de seguridad.

## Estructura sugerida del repositorio

```
mouseBased/
├── mb.py
├── requirements.txt
├── README.md
├── .gitignore
├── passwords.json          # ignorado por git
├── master_key.json         # ignorado por git
```

## Cómo contribuir

Si mejoras la seguridad o añades features (p.ej. AEAD, Argon2), por favor abre un pull request con pruebas y documentación. Mantén el foco en proteger la confidencialidad e integridad de los datos.

---

#### Dios, Assembly y la Patria
#### Edrem

---

Desarrollado con fines académicos y de práctica en Python.