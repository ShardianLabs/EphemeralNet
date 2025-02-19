# EphemeralNet

EphemeralNet es un proyecto de sistema de ficheros P2P efímero escrito en C++ cuyo objetivo es compartir datos con un tiempo de vida limitado. En lugar de replicar ficheros de forma indefinida como en BitTorrent o IPFS, cada nodo respeta un TTL (time-to-live) que obliga al borrado automático de los chunks una vez caducan.

## Características iniciales

- **Kernel de nodo modular**: componentes de almacenamiento, red y tabla DHT desacoplados.
- **TTL configurable**: tiempos de caducidad por defecto y específicos por chunk.
- **Tabla Kademlia con caducidad**: los anuncios incluyen información de expiración.
- **Almacenamiento efímero en memoria**: los chunks se borran tras expirar.
- **Cifrado simétrico**: los chunks se almacenan cifrados mediante ChaCha20 y claves efímeras.
- **Buckets Kademlia**: gestión LRU por distancia XOR y consultas de vecinos más cercanos.
- **Integridad de mensajes**: firma HMAC-SHA256 en los mensajes del protocolo.
- **Rotación de claves**: gestor de sesiones que renueva claves derivadas mediante HMAC-SHA256.
- **Intercambio de claves y reputación**: handshake Diffie-Hellman simplificado con seguimiento de reputación por par.
- **Auditoría de TTL**: informes consistentes que detectan expiraciones pendientes en almacenamiento local y anuncios DHT.
- **Coordinación de limpieza**: sincroniza expiraciones locales con retirada automática de anuncios en la DHT y emite eventos de notificación.
- **Transporte seguro**: sesiones TCP cifradas con ChaCha20 reemplazan el gestor simulado y permiten mensajería punto a punto.
- **Prueba de humo**: verificación básica del borrado tras el TTL.
- **Coordinación de swarm**: replicación de manifiestos y shards entre múltiples proveedores simulados.
- **Almacenamiento persistente opcional**: backend en disco con borrado seguro (wipe) al expirar el TTL.

## Requisitos

- CMake ≥ 3.20
- Compilador con soporte para C++20 (MSVC 19.3+, Clang 13+, GCC 11+)
- Windows con MinGW-w64 o toolchain equivalente (prototipo actual)


## Compilación

```powershell
cmake -S . -B build
cmake --build build
```

Para ejecutar las pruebas de humo:

```powershell
ctest --test-dir build
```

> **Nota:** En la primera configuración `cmake` generará los proyectos y la carpeta `build/`. Añade la opción `-DEPHEMERALNET_BUILD_TESTS=OFF` si no deseas compilar los tests.

## Próximos pasos sugeridos

1. Implementar una capa de red real para intercambio de chunks (UDP/TCP o QUIC).
2. Diseñar reemplazo del `SessionManager` con transporte real y cifrado extremo a extremo.
3. Añadir auditorías de TTL y coordinación de limpieza distribuida.
4. Construir un CLI interactivo para anunciar y recuperar ficheros.
5. Integrar almacenamiento persistente cifrado opcional en disco con borrado seguro.
