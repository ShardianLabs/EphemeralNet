# EphemeralNet TODO

## Estado actual
- Estructura CMake creada con bibliotecas y ejecutables base.
- Implementación en memoria de `ChunkStore`, `Node`, `KademliaTable` y `SessionManager` simulados.
- Cifrado simétrico ChaCha20 integrado en `Node` y `ChunkStore` con gestión de claves efímeras.
- Prueba de humo que valida la expiración local de chunks y la recuperación tras descifrar.
- Capas de protocolo con mensajes Announce/Request/Chunk/Acknowledge y serialización binaria testeada.
- Tabla Kademlia con buckets LRU, cálculo de distancia XOR y consultas de vecinos cercanos.
- Autenticación de mensajes mediante HMAC-SHA256 y helpers de firma/validación.
- Rotación automática de claves de sesión derivadas mediante HMAC-SHA256 (KeyManager).
- Intercambio inicial de claves basado en Diffie-Hellman y reputación básica por par.
- Compilación y `ctest` funcionando con MinGW-w64.

## Próximos hitos
- Sustituir `SessionManager` simulado por transporte real (TCP/UDP/QUIC) con cifrado extremo a extremo.
- Añadir verificación de cumplimiento del TTL: auditorías cruzadas y pruebas automáticas.
- Crear gestor de limpieza que coordine expiraciones locales y notificaciones DHT.
- Incorporar almacenamiento persistente opcional con borrado seguro (wipe) por TTL.
- Construir CLI/daemon: comandos para anunciar, recuperar, listar y configurar TTLs.
- Integrar configuración en YAML/JSON + perfiles de red.
- Añadir logging estructurado y sistema de métricas para monitorizar expiraciones.
- Desarrollar suite de pruebas unitarias y de integración (simulaciones multi-nodo).
- Documentar protocolo, arquitectura y guías operativas en `docs/`.
- Preparar scripts de despliegue (Docker, empaquetado) y CI para Windows/Linux/macOS.
