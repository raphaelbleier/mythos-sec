/**
 * An evidence bundle as one downloadable file.
 *
 * `scripts/evidence build` writes a directory. A reviewer wants one attachment,
 * and the browser cannot fetch a directory, so the files are packed here.
 *
 * It is a tar, not a zip, for one reason: tar is a byte layout with an additive
 * checksum and node's `zlib` does the compression, so this costs forty lines of
 * stdlib. A zip would need a CRC-32 implementation that node does not export,
 * which is more code to get wrong in exchange for a nicer double-click on
 * Windows. `tar -xzf` is the documented way to open it.
 *
 * Nothing is read that `walk` did not resolve inside the bundle directory, and
 * whatever `scripts/evidence` redacted stays redacted: these are the files on
 * disk, byte for byte.
 */
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const BLOCK = 512;

function header(name: string, size: number, mtime: number): Buffer {
  const h = Buffer.alloc(BLOCK);
  const put = (text: string, at: number, len: number) =>
    h.write(text.slice(0, len - 1), at, len - 1, "utf8");
  const octal = (n: number, at: number, len: number) =>
    h.write(n.toString(8).padStart(len - 1, "0") + "\0", at, len, "ascii");

  // A path over 100 bytes splits into prefix + name; a bundle's paths are
  // `requests/<id>.request.http` and shorter, so the split is a safety net.
  let prefix = "";
  let file = name;
  if (Buffer.byteLength(name) > 100) {
    const cut = name.lastIndexOf("/", name.length - 100);
    if (cut > 0) {
      prefix = name.slice(0, cut);
      file = name.slice(cut + 1);
    }
  }
  put(file, 0, 100);
  octal(0o644, 100, 8);
  octal(0, 108, 8);
  octal(0, 116, 8);
  octal(size, 124, 12);
  octal(Math.floor(mtime / 1000), 136, 12);
  h.write("        ", 148, 8, "ascii"); // checksum field counts as spaces
  h.write("0", 156, 1, "ascii"); // regular file
  h.write("ustar\0" + "00", 257, 8, "ascii");
  put("mythos", 265, 32);
  put("mythos", 297, 32);
  put(prefix, 345, 155);

  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
  return h;
}

const pad = (n: number) => Buffer.alloc((BLOCK - (n % BLOCK)) % BLOCK);

/** `files` carry both halves: the path inside the archive and the resolved
 *  path on disk, which the caller has already proven is inside the bundle. */
export function tarGz(files: Array<{ rel: string; abs: string }>, root: string): Buffer {
  const parts: Buffer[] = [];
  for (const f of files) {
    const body = readFileSync(f.abs);
    parts.push(header(`${root}/${f.rel}`, body.length, Date.now()), body, pad(body.length));
  }
  parts.push(Buffer.alloc(BLOCK * 2));
  return gzipSync(Buffer.concat(parts), { level: 6 });
}
