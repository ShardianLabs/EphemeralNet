# EphemeralNet TODO

## Estado actual
- Estructura CMake creada con bibliotecas y ejecutables base.
- Implementación en memoria de `ChunkStore`, `Node`, `KademliaTable` y `SessionManager` simulados.
- Cifrado simétrico ChaCha20 integrado en `Node` y `ChunkStore` con gestión de claves efímeras.
- Prueba de humo que valida la expiración local de chunks y la recuperación tras descifrar.
- Compilación y `ctest` funcionando con MinGW-w64.

## Próximos hitos
- Sustituir `SessionManager` simulado por transporte real (TCP/UDP/QUIC) con cifrado extremo a extremo.
- Añadir autenticación/integridad (AEAD o firmas) y rotación de claves compartidas.
- Implementar en `KademliaTable` buckets, ruteo y refresco acorde a Kademlia.
- Diseñar protocolo de mensaje (anuncios, peticiones, confirmaciones) con TTL embebido.
- Añadir verificación de cumplimiento del TTL: auditorías cruzadas y pruebas automáticas.
- Crear gestor de limpieza que coordine expiraciones locales y notificaciones DHT.
- Incorporar almacenamiento persistente opcional con borrado seguro (wipe) por TTL.
- Construir CLI/daemon: comandos para anunciar, recuperar, listar y configurar TTLs.
- Integrar configuración en YAML/JSON + perfiles de red.
- Añadir logging estructurado y sistema de métricas para monitorizar expiraciones.
- Desarrollar suite de pruebas unitarias y de integración (simulaciones multi-nodo).
- Documentar protocolo, arquitectura y guías operativas en `docs/`.
- Preparar scripts de despliegue (Docker, empaquetado) y CI para Windows/Linux/macOS.

## Requisitos finales previstos
- Red P2P tipo BitTorrent orientada a olvido, con chunks y metadatos sujetos a TTL.
- Tabla DHT (Kademlia) distribuida capaz de almacenar localizadores con expiración.
- Protocolos de anuncio, distribución y limpieza que fuerzan la eliminación tras el TTL.
- Mecanismos de detección y sanción de nodos que incumplen la caducidad.
- Soporte para configurar TTL por fichero, así como valores por defecto y límites.
- Herramientas de usuario (CLI o GUI ligera) para compartir archivos de forma efímera.
- Registro y métricas mínimas para auditar expiraciones sin comprometer la privacidad.
