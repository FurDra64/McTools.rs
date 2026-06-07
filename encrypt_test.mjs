import { readFile, writeFile } from 'fs/promises';
import JSZip from 'jszip';

const wasm = await import('./mctools-wasm/pkg/mctools_wasm.js');

const PERSONA_KEY = 's5s5ejuDru4uchuF2drUFuthaspAbepE';
// Must match C# McCrypt.Marketplace.dontEncrypt exactly
const DONT_ENCRYPT = new Set(['manifest.json', 'contents.json', 'texts', 'pack_icon.png']);

function generateKey() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
  let key = '';
  for (let i = 0; i < 32; i++) key += chars[Math.random() * chars.length | 0];
  return key;
}

function shouldEncrypt(path) {
  for (const p of path.split('/')) {
    if (DONT_ENCRYPT.has(p)) return false;
  }
  return true;
}

const inputPath = process.argv[2] || 'McTools/private.zip';
const outputPath = process.argv[3] || 'McTools/private_encrypted.zip';
const zipData = await readFile(inputPath);
const zip = await JSZip.loadAsync(zipData);

// Collect file entries with raw data (sorted later)
const fileEntries = [];
for (const path of Object.keys(zip.files)) {
  const f = zip.files[path];
  if (!f.dir) fileEntries.push({ path, data: await f.async('uint8array') });
}
fileEntries.sort((a, b) => a.path.localeCompare(b.path));

// Read manifest.json → UUID (path may be "manifest.json" or "private/manifest.json")
const manifestEntry = fileEntries.find(e => e.path === 'manifest.json' || e.path.endsWith('/manifest.json'));
const manifestBuf = manifestEntry.data;
const uuid = JSON.parse(new TextDecoder().decode(manifestBuf)).header.uuid;
const mPath = manifestEntry.path;
const baseDir = mPath.includes('/') ? mPath.slice(0, mPath.lastIndexOf('/') + 1) : '';
console.log(`UUID: ${uuid}, baseDir: "${baseDir}"`);

// ===== Step 1: Create signatures.json FIRST (C# calls SignManifest before EncryptContents) =====
const manifestHash = wasm.sha256_digest(manifestBuf);
const sigJsonStr = JSON.stringify([{ hash: btoa(String.fromCharCode(...manifestHash)), path: 'manifest.json' }]);
const sigBuf = new TextEncoder().encode(sigJsonStr);
console.log(`signatures.json: ${sigJsonStr}`);

// ===== Step 2: Collect directory entries from zip (matches C# GetFileSystemEntries behaviour) =====
const dirPaths = [];
for (const path of Object.keys(zip.files)) {
  const f = zip.files[path];
  if (!f.dir) continue;
  const relPath = path.startsWith(baseDir) ? path.slice(baseDir.length) : path;
  if (relPath !== '') dirPaths.push(relPath);
}
dirPaths.sort();

// ===== Step 3: Build unified sorted content list =====
// Map relPath → entry data, then sort for deterministic order
const entryMap = new Map();

// File entries from zip
for (const { path, data } of fileEntries) {
  const relPath = path.startsWith(baseDir) ? path.slice(baseDir.length) : path;
  entryMap.set(relPath, { plaintext: data });
}

// Signatures.json (generated, NOT in DONT_ENCRYPT)
const sigKey = generateKey();
entryMap.set('signatures.json', { plaintext: sigBuf, sigKey });

// Directory entries
for (const dirRelPath of dirPaths) {
  entryMap.set(dirRelPath, { isDir: true });
}

// Sort
const sortedRelPaths = [...entryMap.keys()].sort();
const contentList = [];
for (const relPath of sortedRelPaths) {
  const entry = entryMap.get(relPath);
  if (entry.isDir) {
    contentList.push({ path: relPath });  // no key, no plaintext
  } else if (shouldEncrypt(relPath)) {
    const key = entry.sigKey || generateKey();
    contentList.push({ path: relPath, key, keyStr: key, plaintext: entry.plaintext });
  } else {
    contentList.push({ path: relPath, plaintext: entry.plaintext });
  }
}

// ===== Step 4: Create minified contents.json =====
const contentsJsonStr = JSON.stringify({
  version: 1,
  content: contentList.map(c => c.key ? { path: c.path, key: c.key } : { path: c.path })
});
console.log(`contents.json (${contentsJsonStr.length} chars): ${contentsJsonStr.substring(0, 200)}...`);

// ===== Step 5: Encrypt contents.json with persona key + binary header =====
const personaKeyBytes = new TextEncoder().encode(PERSONA_KEY);
const encContents = wasm.aes256_cfb8_encrypt(personaKeyBytes, new TextEncoder().encode(contentsJsonStr));
const headerData = wasm.build_encrypted_header(uuid, encContents);

// ===== Step 5: Build output zip (STORE compression, matches C#) =====
const outZip = new JSZip();
for (const c of contentList) {
  const fpath = baseDir + c.path;
  if (c.key) {
    const keyBytes = new TextEncoder().encode(c.keyStr);
    outZip.file(fpath, wasm.aes256_cfb8_encrypt(keyBytes, c.plaintext));
  } else if (c.plaintext) {
    outZip.file(fpath, c.plaintext);
  } // else: directory entry (no plaintext) → JSZip auto-creates parent dirs
}
outZip.file((baseDir || '') + 'contents.json', headerData);

const outData = await outZip.generateAsync({ type: 'uint8array', compression: 'STORE' });
await writeFile(outputPath, outData);
console.log(`\nWritten: ${outputPath} (${outData.length} bytes)`);
