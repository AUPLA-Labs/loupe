// Proof-of-execution runtime shared by pulse.html and challenge.html.
// Inlined into both pages via
// {{.ProofJS}}; the per-challenge data arrives separately, so this file is
// static. Mirrors internal/proof and internal/lumen — keep them in sync.
var LoupeProof = (function () {
  'use strict';

  // Lays out the challenge's boxes in a hidden container and reports each
  // one's bounding rect relative to it, plus the computed colour. Only a
  // real layout engine produces these; DOM emulators report zeros.
  function measure(spec) {
    var out = { rects: [], color: '' };
    var root = document.body || document.documentElement;
    var box = document.createElement('div');
    box.style.cssText = 'position:absolute;left:-10000px;top:0;margin:0;padding:0;border:0;' +
      'width:' + spec.w + 'px;height:600px;visibility:hidden;pointer-events:none';
    try {
      root.appendChild(box);
      var els = [];
      for (var i = 0; i < spec.x.length; i++) {
        var el = document.createElement('div');
        el.style.cssText = spec.x[i];
        box.appendChild(el);
        els.push(el);
      }
      var c = document.createElement('span');
      c.style.color = spec.c;
      box.appendChild(c);

      var base = box.getBoundingClientRect();
      for (var j = 0; j < els.length; j++) {
        var r = els[j].getBoundingClientRect();
        out.rects.push([r.left - base.left, r.top - base.top, r.width, r.height]);
      }
      out.color = getComputedStyle(c).color;
    } catch (_) {
    } finally {
      if (box.parentNode) box.parentNode.removeChild(box);
    }
    return out;
  }

  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    var bin = unescape(encodeURIComponent(str));
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  // Renames each field to this challenge's obfuscated name, then XORs the
  // JSON with an xorshift32 keystream seeded from the split key. Fields the
  // challenge did not issue a name for are dropped, exactly as the server
  // drops them.
  function seal(spec, signals) {
    var obf = {};
    for (var k in signals) {
      if (Object.prototype.hasOwnProperty.call(signals, k) &&
          Object.prototype.hasOwnProperty.call(spec.f, k)) {
        obf[spec.f[k]] = signals[k];
      }
    }
    var bytes = utf8(JSON.stringify(obf));
    var x = (spec.a ^ spec.b) | 0;
    if (x === 0) x = 0x9e3779b9 | 0;
    var bin = '';
    for (var i = 0; i < bytes.length; i++) {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      bin += String.fromCharCode(bytes[i] ^ (x & 255));
    }
    return btoa(bin);
  }

  // Lumen: the proof-of-work + proof-of-space check (internal/lumen). Kept
  // as source text so it can run in a Blob Worker, or on the main thread
  // where Workers are unavailable. SHA-256 and scrypt are hand-written
  // because WebCrypto is async (far too slow per hash) and has no scrypt;
  // internal/lumen's tests check both against Go byte for byte.
  var LUMEN_SRC = `
const K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const W=new Uint32Array(64);
function rr(v,b){return(v>>>b)|(v<<(32-b));}
// Pads an n-byte message held in a fresh buffer and returns the buffer.
function shaPad(n,fill){
  const pad=((55-n%64+64)%64);
  const buf=new Uint8Array(n+1+pad+8);
  fill(buf);
  buf[n]=0x80;
  const dv=new DataView(buf.buffer);
  dv.setUint32(buf.length-8,Math.floor(n/0x20000000),false);
  dv.setUint32(buf.length-4,(n*8)>>>0,false);
  return buf;
}
// Compresses a padded buffer, returning the eight state words.
function shaCore(buf){
  const dv=new DataView(buf.buffer);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  for(let off=0;off<buf.length;off+=64){
    for(let i=0;i<16;i++)W[i]=dv.getUint32(off+i*4,false);
    for(let i=16;i<64;i++){
      const s0=rr(W[i-15],7)^rr(W[i-15],18)^(W[i-15]>>>3);
      const s1=rr(W[i-2],17)^rr(W[i-2],19)^(W[i-2]>>>10);
      W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for(let i=0;i<64;i++){
      const S1=rr(e,6)^rr(e,11)^rr(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K[i]+W[i])>>>0;
      const S0=rr(a,2)^rr(a,13)^rr(a,22);
      const mj=(a&b)^(a&c)^(b&c);
      const t2=(S0+mj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
    h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
  }
  return[h0,h1,h2,h3,h4,h5,h6,h7];
}
// SHA-256 of a byte string (char codes < 256), as hex.
function sha256hex(msg){
  const n=msg.length;
  return shaCore(shaPad(n,function(b){for(let i=0;i<n;i++)b[i]=msg.charCodeAt(i);}))
    .map(function(w){return w.toString(16).padStart(8,'0');}).join('');
}
// SHA-256 of a Uint8Array, as bytes.
function sha256(m){
  const h=shaCore(shaPad(m.length,function(b){b.set(m);}));
  const out=new Uint8Array(32),dv=new DataView(out.buffer);
  for(let i=0;i<8;i++)dv.setUint32(i*4,h[i],false);
  return out;
}
function hmac(key,msg){
  if(key.length>64)key=sha256(key);
  const ip=new Uint8Array(64+msg.length),op=new Uint8Array(96);
  for(let i=0;i<64;i++){const k=i<key.length?key[i]:0;ip[i]=k^0x36;op[i]=k^0x5c;}
  ip.set(msg,64);
  op.set(sha256(ip),64);
  return sha256(op);
}
// PBKDF2-HMAC-SHA256 with one iteration, the only count scrypt uses.
function pbkdf2(pw,salt,dkLen){
  const out=new Uint8Array(dkLen),blk=new Uint8Array(salt.length+4);
  blk.set(salt);
  for(let i=1,off=0;off<dkLen;i++,off+=32){
    const n=salt.length;
    blk[n]=i>>>24;blk[n+1]=i>>>16;blk[n+2]=i>>>8;blk[n+3]=i;
    out.set(hmac(pw,blk).subarray(0,Math.min(32,dkLen-off)),off);
  }
  return out;
}
function salsa8(B){
  let x00=B[0],x01=B[1],x02=B[2],x03=B[3],x04=B[4],x05=B[5],x06=B[6],x07=B[7],
      x08=B[8],x09=B[9],x10=B[10],x11=B[11],x12=B[12],x13=B[13],x14=B[14],x15=B[15],u;
  for(let i=0;i<8;i+=2){
    u=x00+x12|0;x04^=u<<7|u>>>25;  u=x04+x00|0;x08^=u<<9|u>>>23;
    u=x08+x04|0;x12^=u<<13|u>>>19; u=x12+x08|0;x00^=u<<18|u>>>14;
    u=x05+x01|0;x09^=u<<7|u>>>25;  u=x09+x05|0;x13^=u<<9|u>>>23;
    u=x13+x09|0;x01^=u<<13|u>>>19; u=x01+x13|0;x05^=u<<18|u>>>14;
    u=x10+x06|0;x14^=u<<7|u>>>25;  u=x14+x10|0;x02^=u<<9|u>>>23;
    u=x02+x14|0;x06^=u<<13|u>>>19; u=x06+x02|0;x10^=u<<18|u>>>14;
    u=x15+x11|0;x03^=u<<7|u>>>25;  u=x03+x15|0;x07^=u<<9|u>>>23;
    u=x07+x03|0;x11^=u<<13|u>>>19; u=x11+x07|0;x15^=u<<18|u>>>14;
    u=x00+x03|0;x01^=u<<7|u>>>25;  u=x01+x00|0;x02^=u<<9|u>>>23;
    u=x02+x01|0;x03^=u<<13|u>>>19; u=x03+x02|0;x00^=u<<18|u>>>14;
    u=x05+x04|0;x06^=u<<7|u>>>25;  u=x06+x05|0;x07^=u<<9|u>>>23;
    u=x07+x06|0;x04^=u<<13|u>>>19; u=x04+x07|0;x05^=u<<18|u>>>14;
    u=x10+x09|0;x11^=u<<7|u>>>25;  u=x11+x10|0;x08^=u<<9|u>>>23;
    u=x08+x11|0;x09^=u<<13|u>>>19; u=x09+x08|0;x10^=u<<18|u>>>14;
    u=x15+x14|0;x12^=u<<7|u>>>25;  u=x12+x15|0;x13^=u<<9|u>>>23;
    u=x13+x12|0;x14^=u<<13|u>>>19; u=x14+x13|0;x15^=u<<18|u>>>14;
  }
  B[0]+=x00;B[1]+=x01;B[2]+=x02;B[3]+=x03;B[4]+=x04;B[5]+=x05;B[6]+=x06;B[7]+=x07;
  B[8]+=x08;B[9]+=x09;B[10]+=x10;B[11]+=x11;B[12]+=x12;B[13]+=x13;B[14]+=x14;B[15]+=x15;
}
// scrypt's BlockMix: B is 2r 16-word blocks, Y the same size, T 16 words.
function blockMix(B,Y,T,r){
  const n=2*r;
  T.set(B.subarray((n-1)*16,n*16));
  for(let i=0;i<n;i++){
    for(let k=0;k<16;k++)T[k]^=B[i*16+k];
    salsa8(T);
    Y.set(T,((i&1)*r+(i>>1))*16);
  }
  B.set(Y);
}
// scrypt with p = 1, matching golang.org/x/crypto/scrypt.
function scrypt(pw,salt,logN,r,dkLen){
  const N=1<<logN,L=32*r,b=pbkdf2(pw,salt,128*r);
  const X=new Uint32Array(L),Y=new Uint32Array(L),T=new Uint32Array(16),V=new Uint32Array(L*N);
  for(let i=0;i<L;i++)X[i]=b[4*i]|b[4*i+1]<<8|b[4*i+2]<<16|b[4*i+3]<<24;
  for(let i=0;i<N;i++){V.set(X,i*L);blockMix(X,Y,T,r);}
  for(let i=0;i<N;i++){
    const off=(X[L-16]&(N-1))*L;
    for(let k=0;k<L;k++)X[k]^=V[off+k];
    blockMix(X,Y,T,r);
  }
  for(let i=0;i<L;i++){const w=X[i];b[4*i]=w;b[4*i+1]=w>>>8;b[4*i+2]=w>>>16;b[4*i+3]=w>>>24;}
  return pbkdf2(pw,b,dkLen);
}
function ascii(s){const b=new Uint8Array(s.length);for(let i=0;i<s.length;i++)b[i]=s.charCodeAt(i);return b;}
function toHex(b){let s='';for(let i=0;i<b.length;i++)s+=(b[i]<16?'0':'')+b[i].toString(16);return s;}
// Solves challenge ch ({p: puzzles, n: logN, r, s: space salt}), calling
// progress(fraction) as it goes. Returns the answer the server parses
// (lumen.ParseAnswer), or null if a puzzle has no solution. A failed
// space step (say, the memory can't be allocated) leaves the digest empty
// rather than losing the work.
function lumenSolve(ch,progress){
  const t0=Date.now(),nums=[];
  for(let k=0;k<ch.p.length;k++){
    const p=ch.p[k];
    let found=-1;
    for(let i=0;i<p.m;i++){if(sha256hex(p.s+i)===p.h){found=i;break;}}
    if(found<0)return null;
    nums.push(found);
    progress((k+1)/(ch.p.length+1));
  }
  const t1=Date.now();
  let d='';
  try{d=toHex(scrypt(ascii(nums.join(',')),ascii(ch.s),ch.n,ch.r,32));}catch(_){}
  return{n:nums,d:d,w:t1-t0,s:Date.now()-t1};
}
`;
  // The worker also reports its own navigator: stealth patches applied to
  // the page's window rarely reach worker realms, so a disagreement with the
  // main thread is a fingerprint contradiction (fingerprint.go).
  var WORKER_SRC = LUMEN_SRC +
    'function wnav(){try{var n=self.navigator;return{ua:n.userAgent,platform:n.platform,' +
    'hc:n.hardwareConcurrency===undefined?null:n.hardwareConcurrency,' +
    'langs:Array.prototype.join.call(n.languages||[],",")};}catch(_){return null;}}' +
    'self.onmessage=function(e){' +
    'var a=lumenSolve(e.data,function(f){self.postMessage({progress:f});});' +
    'self.postMessage(a?{answer:a,nav:wnav()}:{fail:true});};';

  function solveSync(ch, progress) {
    var a = new Function(LUMEN_SRC + 'return lumenSolve;')()(ch, progress);
    if (!a) throw new Error('exhausted');
    return { answer: a, ms: a.w + a.s };
  }

  // Solves a Lumen challenge (a proof spec's "l"), resolving to
  // { answer, ms, nav }: answer goes in the sealed signals as "lumen", ms is
  // the solve's own time, nav the worker's navigator (absent on the
  // main-thread fallback). onProgress, if given, is called with the
  // fraction done.
  function solve(ch, onProgress) {
    var progress = typeof onProgress === 'function' ? onProgress : function () {};
    return new Promise(function (resolve, reject) {
      var w, url;
      try {
        url = URL.createObjectURL(new Blob([WORKER_SRC], { type: 'application/javascript' }));
        w = new Worker(url);
      } catch (_) {
        if (url) URL.revokeObjectURL(url);
        try { resolve(solveSync(ch, progress)); } catch (err) { reject(err); }
        return;
      }
      function done() { URL.revokeObjectURL(url); w.terminate(); }
      w.onmessage = function (e) {
        var d = e.data;
        if (d.progress !== undefined) { progress(d.progress); return; }
        done();
        if (d.answer) resolve({ answer: d.answer, ms: d.answer.w + d.answer.s, nav: d.nav });
        else reject(new Error('exhausted'));
      };
      w.onerror = function (e) {
        done();
        if (e && e.preventDefault) e.preventDefault();
        try { resolve(solveSync(ch, progress)); } catch (err) { reject(err); }
      };
      w.postMessage(ch);
    });
  }

  return { measure: measure, seal: seal, solve: solve };
}());
