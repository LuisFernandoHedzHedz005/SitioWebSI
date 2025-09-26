Proyecto Full Stack (Flask + Next.js)

Este es un proyecto web full stack que utiliza Flask para el backend y Next.js (React) para el frontend. Para facilitar la instalación y ejecución del proyecto, se han creado tres scripts de shell (.sh).

## Prerrequisitos 

Antes de comenzar, asegúrate de tener instalado lo siguiente en tu sistema:

    Python 3 y pip

    Node.js y npm

## Instalación 

Para instalar todas las dependencias necesarias tanto para el backend como para el frontend, hemos preparado un script que automatiza todo el proceso.

Ejecuta el siguiente comando en la raíz del proyecto:
Bash

install.sh

Este script hará lo siguiente:

    Navegará a la carpeta backend.

    Creará un entorno virtual de Python llamado venv.

    Activará el entorno virtual.

    Instalará todas las dependencias de Python listadas en requirements.txt.

    Navegará a la carpeta frontend.

    Instalará todas las dependencias de Node.js a través de npm.

    Generará la build de producción del frontend.

## Ejecución de la Aplicación 

1. Configura los .env en tu entorno

En la raíz del proyecto, ejecuta el siguiente comando en una terminal 

bash setup.sh

Se te pediran las credenciales y variables de entorno que el proyecto necesita para funcionar correctamente

Para ejecutar la aplicación, necesitas iniciar tanto el servidor del backend como el del frontend. Ambos procesos deben correr en terminales separadas.

2. Iniciar el Backend (Flask)

En una terminal, ejecuta el siguiente comando desde la raíz del proyecto:


bash backend.sh

Este script activará el entorno virtual de Python y arrancará el servidor de Flask. Por defecto, estará disponible en http://127.0.0.1:5000.

3. Iniciar el Frontend (Next.js)

En otra terminal, ejecuta el siguiente comando desde la raíz del proyecto:


bash frontend.sh

Este script iniciará el servidor de desarrollo de Next.js. Por defecto, estará disponible en http://localhost:3000.

¡Y listo! Ahora puedes abrir http://localhost:3000 en tu navegador para ver la aplicación en funcionamiento.
