import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

# Получаем URL базы данных из переменных окружения (Render сам её добавит)
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/pigeonmail")

def init_db():
    """Создаёт таблицы, если их нет"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    phone VARCHAR(20) UNIQUE NOT NULL,
                    username VARCHAR(50) UNIQUE,
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    hashed_password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.commit()

@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()