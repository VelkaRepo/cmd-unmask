# Bounded Unpacking DAG with Pruning Gates and Padding-Tolerant Base64

Multi-layered payload decoding is modeled as a bounded Directed Acyclic Graph (Unpacking DAG) deduplicated by SHA-256 node hashes, capped at depth 10, 64 total Payload Nodes, 256 KB per decoded stream (chunk-enforced to defeat gzip/zlib bombs), and a 3.0-second per-command timeout. When an encoded span is carved from a command, the engine creates both a raw decoded child node and a Reconstructed Command node with the decoded payload spliced in-place.

To balance deep recovery against False Positives (Detection Rigidity):
- Base64 carving supports both standard (`+/`) and URL-safe (`-_`) alphabets and automatically repairs missing `=` padding on carved substrings before attempting UTF-16LE, UTF-8, or Gzip/Deflate decoding.
- Standard decoders retain child nodes only when normalized output achieves `printable_ratio >= 0.85` and Shannon entropy `H <= 6.2` bits/byte (or begins with known container magic bytes such as Gzip `1f 8b`).
- Single-byte XOR brute-force (`0x01`..`0xFF`) runs only as a fallback on unresolved high-entropy leaves when no explicit XOR key is present in syntax, accepting a candidate only if `printable_ratio >= 0.92` and at least one high-confidence shell or IOC anchor matches.
