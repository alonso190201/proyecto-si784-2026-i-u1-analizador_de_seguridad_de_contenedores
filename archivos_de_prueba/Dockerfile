# Imagen base con tag 'latest' no fija (-7 puntos)
FROM ubuntu:latest

# Ejecución de scripts remotos inseguros (-15 puntos)
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://insecure-website.com/install.sh | bash

# Permisos de archivos excesivos (chmod 777) (-15 puntos)
RUN mkdir /app && chmod 777 /app

# NOTA: Se removieron los secretos en ENV para subir el puntaje

# Falta instrucción USER, ejecuta como root por defecto (-15 puntos)
# Falta instrucción HEALTHCHECK (-2 puntos)

CMD ["/app/run.sh"]
