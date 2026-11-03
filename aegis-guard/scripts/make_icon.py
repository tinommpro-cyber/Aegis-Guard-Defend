# Writes a 1024x1024 placeholder icon (stdlib only) so `tauri icon` has a source. Replace icon.png with your own art anytime.
import zlib, struct
w = h = 1024
raw = b"".join(b"\x00" + bytes([52, 224, 161, 255]) * w for _ in range(h))
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
open("icon.png", "wb").write(png)
