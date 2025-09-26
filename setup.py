import os
import sys

def ask(question, default=None):
    prompt = f"{question} [{default}]" if default else f"{question}"
    answer = input(f"{prompt}: ")
    return answer or default

def main():
    backend_env_path = os.path.join('backend', '.env')
    frontend_env_path = os.path.join('frontend', '.env')

    if os.path.exists(backend_env_path) or os.path.exists(frontend_env_path):
        print("\n Uno o ambos archivos .env ya existen.")
        print("Bórralos manualmente si quieres generar una nueva configuración.")
        sys.exit(1)

    print("\nPor favor, introduce las variables para el backend:")
    mongo_uri = ask("¿Cuál es tu MONGO_URI?")
    secret_key = ask("¿Cuál es tu SECRET_KEY para JWT?")
    local_url = ask("¿Cuál es la URL del frontend local (para CORS)?", default="http://localhost:3000")
    prod_url = ask("¿Cuál es la URL del frontend en producción (para CORS)?", default="")

    print("\nAhora, introduce las variables para el frontend:")
    next_public_api_url = ask("¿Cuál es la URL del backend (API)?", default="http://localhost:5000")
    
    backend_env_content = f"""
MONGO_URI="{mongo_uri}"
SECRET_KEY="{secret_key}"
LOCAL_URL="{local_url}"
PROD_URL="{prod_url}"
"""
    frontend_env_content = f"""
NEXT_PUBLIC_API_URL="{next_public_api_url}"
"""

    # Escribir los archivos
    try:
        with open(backend_env_path, 'w') as f:
            f.write(backend_env_content.strip())
        print(f"\n Archivo creado exitosamente en: {backend_env_path}")

        with open(frontend_env_path, 'w') as f:
            f.write(frontend_env_content.strip())
        print(f" Archivo creado exitosamente en: {frontend_env_path}")
        
        print("\n--- Configuración completada ---")
        
    except IOError as e:
        print(f"\n Error al escribir los archivos: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()