import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_super_segura_inventario_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

app = FastAPI(title="Sistema de Inventario - Neon Cloud")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_db():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="Falta configurar DATABASE_URL en .env")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def inicializar_bd():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id_usuario SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                rol VARCHAR(20) NOT NULL CHECK (rol IN ('administrador', 'almacenista'))
            );
            CREATE TABLE IF NOT EXISTS categorias (
                id_categoria SERIAL PRIMARY KEY,
                nombre VARCHAR(100) UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proveedores (
                id_proveedor SERIAL PRIMARY KEY,
                nombre_empresa VARCHAR(100) UNIQUE NOT NULL,
                contacto VARCHAR(100),
                telefono VARCHAR(30),
                email VARCHAR(100),
                direccion TEXT
            );
            CREATE TABLE IF NOT EXISTS productos (
                id_producto SERIAL PRIMARY KEY,
                codigo_barras VARCHAR(50) UNIQUE NOT NULL,
                nombre VARCHAR(100) NOT NULL,
                id_categoria INT REFERENCES categorias(id_categoria),
                id_proveedor INT REFERENCES proveedores(id_proveedor),
                precio_compra NUMERIC(10, 2) NOT NULL,
                precio_venta NUMERIC(10, 2) NOT NULL,
                stock_actual INT NOT NULL DEFAULT 0,
                stock_minimo INT NOT NULL DEFAULT 5
            );
            CREATE TABLE IF NOT EXISTS movimientos (
                id_movimiento SERIAL PRIMARY KEY,
                id_producto INT REFERENCES productos(id_producto),
                tipo_movimiento VARCHAR(20) NOT NULL,
                cantidad INT NOT NULL,
                motivo TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            ALTER TABLE proveedores ADD COLUMN IF NOT EXISTS contacto VARCHAR(100);
            ALTER TABLE proveedores ADD COLUMN IF NOT EXISTS telefono VARCHAR(30);
            ALTER TABLE proveedores ADD COLUMN IF NOT EXISTS email VARCHAR(100);
            ALTER TABLE proveedores ADD COLUMN IF NOT EXISTS direccion TEXT;
        """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Error inicializando tablas en Neon:", e)

inicializar_bd()

# --- MODELOS ---
class UsuarioRegistro(BaseModel):
    username: str
    password: str
    rol: str

class CategoriaCreate(BaseModel):
    nombre: str

class ProveedorCreate(BaseModel):
    nombre_empresa: str
    contacto: Optional[str] = None
    telefono: Optional[str] = None
    email: Optional[str] = None
    direccion: Optional[str] = None

class ProductoCreate(BaseModel):
    codigo_barras: str
    nombre: str
    id_categoria: Optional[int] = None
    id_proveedor: Optional[int] = None
    precio_compra: float
    precio_venta: float
    stock_actual: int

class MovimientoCreate(BaseModel):
    id_producto: int
    tipo_movimiento: str
    cantidad: int
    motivo: str

# --- FUNCIONES JWT Y ROLES ---
def crear_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    credenciales_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        rol: str = payload.get("rol")
        if username is None or rol is None:
            raise credenciales_exc
        return {"username": username, "rol": rol}
    except JWTError:
        raise credenciales_exc

def solo_administrador(usuario: dict = Depends(obtener_usuario_actual)):
    if usuario["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado. Se requiere rol: administrador"
        )
    return usuario

# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/auth/registro")
def registrar_usuario(user: UsuarioRegistro):
    if user.rol not in ["administrador", "almacenista"]:
        raise HTTPException(status_code=400, detail="Rol inválido")
    conn = get_db()
    cur = conn.cursor()
    try:
        hashed = pwd_context.hash(user.password)
        cur.execute(
            "INSERT INTO usuarios (username, password_hash, rol) VALUES (%s, %s, %s) RETURNING id_usuario, username, rol",
            (user.username, hashed, user.rol)
        )
        nuevo = cur.fetchone()
        conn.commit()
        return {"mensaje": "Usuario registrado", "usuario": nuevo}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    finally:
        cur.close()
        conn.close()

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuarios WHERE username = %s", (form_data.username,))
    db_user = cur.fetchone()
    cur.close()
    conn.close()

    if not db_user or not pwd_context.verify(form_data.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = crear_token({"sub": db_user["username"], "rol": db_user["rol"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": db_user["username"],
        "rol": db_user["rol"]
    }

# --- ENDPOINTS DE CATEGORÍAS Y PROVEEDORES ---
@app.get("/categorias")
def listar_categorias(usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM categorias ORDER BY nombre ASC")
    categorias = cur.fetchall()
    cur.close()
    conn.close()
    return {"categorias": categorias}

@app.post("/categorias")
def crear_categoria(cat: CategoriaCreate, admin: dict = Depends(solo_administrador)):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO categorias (nombre) VALUES (%s) RETURNING id_categoria", (cat.nombre.strip(),))
        nuevo_id = cur.fetchone()["id_categoria"]
        conn.commit()
        return {"mensaje": "Categoría creada", "id_categoria": nuevo_id}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Esa categoría ya existe")
    finally:
        cur.close()
        conn.close()

@app.get("/proveedores")
def listar_proveedores(usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM proveedores ORDER BY nombre_empresa ASC")
    proveedores = cur.fetchall()
    cur.close()
    conn.close()
    return {"proveedores": proveedores}

@app.post("/proveedores")
def crear_proveedor(prov: ProveedorCreate, admin: dict = Depends(solo_administrador)):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO proveedores (nombre_empresa, contacto, telefono, email, direccion) VALUES (%s, %s, %s, %s, %s) RETURNING id_proveedor",
            (prov.nombre_empresa.strip(), prov.contacto, prov.telefono, prov.email, prov.direccion)
        )
        nuevo_id = cur.fetchone()["id_proveedor"]
        conn.commit()
        return {"mensaje": "Proveedor registrado", "id_proveedor": nuevo_id}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Ese proveedor ya está registrado")
    finally:
        cur.close()
        conn.close()

# --- ENDPOINTS DE INVENTARIO Y MOVIMIENTOS ---
@app.get("/productos")
def listar_productos(usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id_producto, p.codigo_barras, p.nombre AS producto,
               c.nombre AS categoria, pr.nombre_empresa AS proveedor,
               p.precio_compra, p.precio_venta, p.stock_actual, p.stock_minimo
        FROM productos p
        LEFT JOIN categorias c ON p.id_categoria = c.id_categoria
        LEFT JOIN proveedores pr ON p.id_proveedor = pr.id_proveedor
        ORDER BY p.id_producto ASC
    """)
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return {"productos": productos}

@app.get("/productos/alertas")
def alertas_stock(usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM productos WHERE stock_actual <= stock_minimo")
    alertas = cur.fetchall()
    cur.close()
    conn.close()
    return {"alertas_stock": alertas}

@app.post("/productos")
def crear_producto(prod: ProductoCreate, admin: dict = Depends(solo_administrador)):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO productos (codigo_barras, nombre, id_categoria, id_proveedor, precio_compra, precio_venta, stock_actual)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id_producto
        """, (prod.codigo_barras, prod.nombre, prod.id_categoria, prod.id_proveedor, prod.precio_compra, prod.precio_venta, prod.stock_actual))
        nuevo_id = cur.fetchone()["id_producto"]
        conn.commit()
        return {"mensaje": "Producto creado", "id_producto": nuevo_id}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="El código de barras ya existe")
    finally:
        cur.close()
        conn.close()

@app.get("/movimientos")
def listar_movimientos(usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT m.id_movimiento, m.id_producto, p.nombre AS producto, p.codigo_barras,
               m.tipo_movimiento, m.cantidad, m.motivo, m.fecha
        FROM movimientos m
        LEFT JOIN productos p ON m.id_producto = p.id_producto
        ORDER BY m.fecha DESC, m.id_movimiento DESC
    """)
    movimientos = cur.fetchall()
    cur.close()
    conn.close()
    return {"movimientos": movimientos}

@app.post("/movimientos")
def registrar_movimiento(mov: MovimientoCreate, usuario: dict = Depends(obtener_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT stock_actual FROM productos WHERE id_producto = %s", (mov.id_producto,))
    prod = cur.fetchone()
    if not prod:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    stock_nuevo = prod["stock_actual"]
    if mov.tipo_movimiento == "ENTRADA":
        stock_nuevo += mov.cantidad
    elif mov.tipo_movimiento == "SALIDA":
        if prod["stock_actual"] < mov.cantidad:
            cur.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Stock insuficiente")
        stock_nuevo -= mov.cantidad
    elif mov.tipo_movimiento == "AJUSTE":
        stock_nuevo = mov.cantidad

    cur.execute("UPDATE productos SET stock_actual = %s WHERE id_producto = %s", (stock_nuevo, mov.id_producto))
    cur.execute(
        "INSERT INTO movimientos (id_producto, tipo_movimiento, cantidad, motivo) VALUES (%s, %s, %s, %s)",
        (mov.id_producto, mov.tipo_movimiento, mov.cantidad, mov.motivo)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Movimiento registrado", "stock_actual": stock_nuevo}

@app.get("/")
def ir_al_panel():
    return RedirectResponse(url="/app/")

app.mount("/app", StaticFiles(directory=os.path.join(BASE_DIR, "static"), html=True), name="static")