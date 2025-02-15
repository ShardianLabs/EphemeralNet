# EphemeralNet TODO

## Estado actual
- Estructura CMake creada con bibliotecas y ejecutables base.
- Implementación en memoria de `ChunkStore`, `Node` y `KademliaTable` con transporte seguro real.
- Cifrado simétrico ChaCha20 integrado en `Node` y `ChunkStore` con gestión de claves efímeras.
- Prueba de humo que valida la expiración local de chunks y la recuperación tras descifrar.
- Capas de protocolo con mensajes Announce/Request/Chunk/Acknowledge y serialización binaria testeada.
- Tabla Kademlia con buckets LRU, cálculo de distancia XOR y consultas de vecinos cercanos.
- Autenticación de mensajes mediante HMAC-SHA256 y helpers de firma/validación.
- Rotación automática de claves de sesión derivadas mediante HMAC-SHA256 (KeyManager).
- Intercambio inicial de claves basado en Diffie-Hellman y reputación básica por par.
- Auditoría de TTL con informes de caducidad cruzados entre almacenamiento y DHT.
- Gestor de limpieza que coordina expiraciones locales y retirada de anuncios en la DHT.
- Transporte TCP cifrado extremo a extremo que sustituye el `SessionManager` simulado.
- Compilación y `ctest` funcionando con MinGW-w64.
- Libreria de comparticion de claves de Shamir n-de-m con pruebas unitarias de reconstruccion.
- Formato de manifiesto `eph://` con codificacion/decodificacion Base64 y prueba de round-trip.
- Tabla Kademlia extendida para publicar y expirar metadatos de shards con TTL.
- Flujo de compartición de claves Shamir integrado: generación de claves por chunk, manifiesto y publicación en la DHT.
- Ingestión y validación de manifiestos `eph://` con reconstrucción de claves y almacenamiento local replicado.
- Flujo de petición/entrega de chunks cifrados entre pares con transporte seguro y acuses firmados.
- Bootstrapping de la DHT con nodos semilla y negociación inicial de llaves.
- Simulación de NAT traversal con coordinación UPnP/STUN/hole punching y telemetría integrada en `Node`.

## Próximos hitos
- Diseñar estrategia de distribución de manifiestos y shards entre múltiples proveedores (swarm coordinado).
- Incorporar almacenamiento persistente opcional con borrado seguro (wipe) por TTL.
- Construir CLI/daemon: comandos para anunciar, recuperar, listar y configurar TTLs.
- Distribuir manifiestos `eph://` con validacion de metadatos y coordinacion de entrega segura entre pares.
- Diseñar capa de intercambio de chunks estilo BitTorrent (programación de envíos, multi-seeding y propagación entre pares).
- Integrar configuración en YAML/JSON + perfiles de red.
- Añadir logging estructurado y sistema de métricas para monitorizar expiraciones.
- Desarrollar suite de pruebas unitarias y de integración (simulaciones multi-nodo).
- Documentar protocolo, arquitectura y guías operativas en `docs/`.
- Preparar scripts de despliegue (Docker, empaquetado) y CI para Windows/Linux/macOS.
- libephemeralnet (lib.so y dll)
- ephemeralnet-cli
- ephemeralnet-GUI