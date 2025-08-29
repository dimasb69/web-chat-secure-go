WEB CHAT SECURE WEBSOCKET

Chat para probar en un Termux como servidor usando proot-distro + ubuntu

Esta configurado para SSL, si quieres correr en local, genera un certificado auto gestionado en la raiz donde se encuentra el main.go

ejecuta y sigue los pasos para generarlo:

   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes