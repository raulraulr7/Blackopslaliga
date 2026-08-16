# BlackOps2Liga - Cloudflare Workers + D1

Preparado para desplegar gratis con Cloudflare Workers y D1.

1. En Cloudflare crea un Worker llamado `blackops2liga`.
2. Crea una base D1 llamada `blackops2liga`.
3. En la consola SQL de D1 pega `schema.sql`.
4. Vincula D1 al Worker con binding `DB`.
5. Configura Assets para la carpeta `public`.
6. Publica `worker.js`.

El archivo `wrangler.jsonc` ya deja preparada la configuración; sustituye el database_id por el que te dé Cloudflare.
