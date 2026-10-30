// Browser fingerprint collection, inlined
// into pulse.html and challenge.html after proof.js. The raw values are sent
// sealed with the page's proof answer and scored server-side for internal
// contradictions (fingerprint.go); they are used for bot detection and the
// cluster keys only, and only component hashes are ever stored.
//
// Contract with the server: every synchronous section below is always
// present as a key (its value may be null where the API is unsupported), so
// a missing key means the page's script did not run. Asynchronous sections
// are raced against a deadline and sent as null when late — absent is never
// scored.
var LoupeFP = (function () {
  'use strict';

  function safe(fn, dflt) {
    try { var v = fn(); return v === undefined ? dflt : v; } catch (_) { return dflt; }
  }

  function delay(ms, v) {
    return new Promise(function (res) { setTimeout(function () { res(v); }, ms); });
  }

  // Resolves to the promise's value, or null if it rejects or misses ms.
  function within(fn, ms) {
    var p;
    try { p = Promise.resolve(fn()); } catch (_) { return Promise.resolve(null); }
    return Promise.race([p.then(null, function () { return null; }), delay(ms, null)]);
  }

  // cyrb53 over a string or byte array: fast, non-cryptographic. Only used
  // to shrink large values (data URLs, pixel buffers) before sending.
  function hash(input) {
    var h1 = 0xdeadbeef, h2 = 0x41c6ce57, isStr = typeof input === 'string';
    for (var i = 0; i < input.length; i++) {
      var ch = isStr ? input.charCodeAt(i) : input[i];
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h2 >>> 0).toString(16) + (h1 >>> 0).toString(16);
  }

  function root() { return document.body || document.documentElement; }

  // ── Canvas 2D ─────────────────────────────────────────────────────────────
  function canvasOnce() {
    var c = document.createElement('canvas');
    c.width = 240; c.height = 60;
    var x = c.getContext('2d');
    if (!x) return null;
    var g = x.createLinearGradient(0, 0, 240, 0);
    g.addColorStop(0, '#f60'); g.addColorStop(1, '#069');
    x.fillStyle = g; x.fillRect(0, 0, 240, 60);
    x.globalCompositeOperation = 'multiply';
    x.fillStyle = 'rgba(102, 204, 0, 0.7)';
    x.beginPath(); x.arc(50, 30, 25, 0, Math.PI * 2); x.fill();
    x.globalCompositeOperation = 'source-over';
    x.font = '16px Arial'; x.fillStyle = '#000';
    x.fillText('Loupe 😃 éß中', 10, 40);
    return hash(c.toDataURL());
  }

  // Rendered twice: a real engine is deterministic within a page, so two
  // different results mean per-readback noise (anti-detect browsers).
  function canvas() { return [safe(canvasOnce, null), safe(canvasOnce, null)]; }

  // One pixel of a solid fill, read back directly. A blocker that hides
  // canvas contents returns it transparent, white or grey instead of the
  // orange that was drawn.
  function canvasPx() {
    var c = document.createElement('canvas');
    c.width = 4; c.height = 4;
    var x = c.getContext('2d');
    if (!x) return null;
    x.fillStyle = '#f60'; x.fillRect(0, 0, 4, 4);
    return Array.prototype.slice.call(x.getImageData(1, 1, 1, 1).data);
  }

  // ── WebGL ─────────────────────────────────────────────────────────────────
  var GL_PARAMS = ['MAX_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE', 'MAX_VIEWPORT_DIMS',
    'MAX_VERTEX_ATTRIBS', 'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_FRAGMENT_UNIFORM_VECTORS',
    'MAX_VARYING_VECTORS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS', 'MAX_TEXTURE_IMAGE_UNITS',
    'MAX_VERTEX_TEXTURE_IMAGE_UNITS', 'MAX_CUBE_MAP_TEXTURE_SIZE', 'ALIASED_LINE_WIDTH_RANGE',
    'ALIASED_POINT_SIZE_RANGE', 'RED_BITS', 'GREEN_BITS', 'BLUE_BITS', 'ALPHA_BITS',
    'DEPTH_BITS', 'STENCIL_BITS', 'SUBPIXEL_BITS', 'SHADING_LANGUAGE_VERSION', 'VERSION',
    'VENDOR', 'RENDERER'];

  function glRender(gl) {
    var vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vs, 'attribute vec2 p;varying vec2 v;void main(){v=p;gl_Position=vec4(p,0.0,1.0);}');
    gl.compileShader(vs);
    var fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fs, 'precision mediump float;varying vec2 v;void main(){' +
      'gl_FragColor=vec4(fract(sin(dot(v,vec2(12.9898,78.233)))*43758.5453),v.x*0.5+0.5,v.y*0.5+0.5,1.0);}');
    gl.compileShader(fs);
    var prog = gl.createProgram();
    gl.attachShader(prog, vs); gl.attachShader(prog, fs);
    gl.linkProgram(prog); gl.useProgram(prog);
    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.9, -0.8, 0.85, -0.6, 0.1, 0.95]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.clearColor(0, 0, 0, 1); gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    var px = new Uint8Array(64 * 64 * 4);
    gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
    return hash(px);
  }

  function webgl() {
    var c = document.createElement('canvas');
    c.width = 64; c.height = 64;
    var gl = c.getContext('webgl', { preserveDrawingBuffer: true }) ||
             c.getContext('experimental-webgl', { preserveDrawingBuffer: true });
    if (!gl) return null;
    var out = { vendor: null, renderer: null, params: {}, ext: null, prec: [], render: null };
    var dbg = safe(function () { return gl.getExtension('WEBGL_debug_renderer_info'); }, null);
    if (dbg) {
      out.vendor = safe(function () { return gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); }, null);
      out.renderer = safe(function () { return gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); }, null);
    }
    GL_PARAMS.forEach(function (name) {
      out.params[name] = safe(function () {
        var v = gl.getParameter(gl[name]);
        return (v && typeof v === 'object' && v.length !== undefined) ? Array.prototype.slice.call(v) : v;
      }, null);
    });
    out.ext = safe(function () { return (gl.getSupportedExtensions() || []).slice().sort(); }, null);
    [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER].forEach(function (sh) {
      [gl.HIGH_FLOAT, gl.MEDIUM_FLOAT, gl.HIGH_INT].forEach(function (pt) {
        out.prec.push(safe(function () {
          var f = gl.getShaderPrecisionFormat(sh, pt);
          return [f.rangeMin, f.rangeMax, f.precision];
        }, null));
      });
    });
    out.render = safe(function () { return glRender(gl); }, null);
    safe(function () { gl.getExtension('WEBGL_lose_context').loseContext(); });
    return out;
  }

  // ── WebGPU (async) ────────────────────────────────────────────────────────
  function webgpu() {
    if (!navigator.gpu || !navigator.gpu.requestAdapter) return null;
    return navigator.gpu.requestAdapter().then(function (a) {
      if (!a) return { vendor: '', architecture: '', none: true };
      if (a.info) return { vendor: a.info.vendor || '', architecture: a.info.architecture || '' };
      if (a.requestAdapterInfo) {
        return a.requestAdapterInfo().then(function (i) {
          return { vendor: i.vendor || '', architecture: i.architecture || '' };
        });
      }
      return null;
    });
  }

  // ── Audio (async) ─────────────────────────────────────────────────────────
  function audioOnce() {
    var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!Ctx) return Promise.resolve(null);
    var ctx = new Ctx(1, 5000, 44100);
    var osc = ctx.createOscillator();
    osc.type = 'triangle'; osc.frequency.value = 10000;
    var comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
    comp.attack.value = 0; comp.release.value = 0.25;
    osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
    return new Promise(function (resolve, reject) {
      function done(buf) {
        var d = buf.getChannelData(0), s = 0;
        for (var i = 4500; i < 5000; i++) s += Math.abs(d[i]);
        resolve(String(s));
      }
      var p = ctx.startRendering();
      if (p && p.then) p.then(done, reject);
      else ctx.oncomplete = function (e) { done(e.renderedBuffer); };
    });
  }

  function audio() {
    return audioOnce().then(function (a) {
      return audioOnce().then(function (b) { return [a, b]; });
    });
  }

  // ── Fonts ─────────────────────────────────────────────────────────────────
  var FONTS = [
    // Windows
    'Segoe UI', 'Calibri', 'Consolas', 'Cambria', 'Tahoma', 'Segoe UI Emoji',
    'Microsoft YaHei', 'Malgun Gothic', 'MS Gothic', 'Ebrima', 'Gadugi',
    // macOS
    'Helvetica Neue', 'Menlo', 'Apple SD Gothic Neo', 'Avenir', 'Geneva',
    'Hiragino Sans', 'PingFang SC', 'Apple Color Emoji', 'Lucida Grande', 'Monaco',
    // Linux
    'DejaVu Sans', 'Liberation Sans', 'Noto Sans', 'Ubuntu', 'Cantarell',
    'Noto Color Emoji', 'FreeSans',
    // Widespread
    'Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia',
    'Trebuchet MS', 'Comic Sans MS', 'Impact', 'Palatino', 'Garamond',
  ];

  // A font is present when text in it measures differently from the
  // generic fallback for at least one of three bases. Three bases cover the
  // case where a font *is* one base's default.
  function fonts() {
    var x = document.createElement('canvas').getContext('2d');
    if (!x) return null;
    var s = 'mmmmmmmmmmlli1WwQ@#', bases = ['monospace', 'sans-serif', 'serif'], base = {};
    bases.forEach(function (b) { x.font = '72px ' + b; base[b] = x.measureText(s).width; });
    return FONTS.filter(function (f) {
      return bases.some(function (b) {
        x.font = '72px "' + f + '", ' + b;
        return x.measureText(s).width !== base[b];
      });
    });
  }

  // ── JS engine ─────────────────────────────────────────────────────────────
  // Error-message wording, stack format and a Gecko-only property identify
  // V8, SpiderMonkey and JavaScriptCore regardless of the claimed UA.
  function engine() {
    var msg = '';
    try { var o = null; o.x; } catch (e) { msg = String(e && e.message).slice(0, 120); }
    var stack = safe(function () { return String(new Error('x').stack).slice(0, 40); }, '');
    return {
      err: msg,
      v8stack: /^Error: x\n\s+at /.test(stack),
      moz: 'mozInnerScreenX' in window,
      evalLen: safe(function () { return eval.toString().length; }, 0),
    };
  }

  // ── Feature matrix ────────────────────────────────────────────────────────
  // Each id maps to the version that shipped it in fingerprint.go.
  function features() {
    var cs = function (q) { return safe(function () { return CSS.supports(q); }, false); };
    return {
      findLast: typeof [].findLast === 'function',
      hasOwn: typeof Object.hasOwn === 'function',
      structuredClone: typeof window.structuredClone === 'function',
      at: typeof [].at === 'function',
      toSorted: typeof [].toSorted === 'function',
      fromAsync: typeof Array.fromAsync === 'function',
      withResolvers: typeof Promise.withResolvers === 'function',
      groupBy: typeof Object.groupBy === 'function',
      setUnion: safe(function () { return typeof new Set().union === 'function'; }, false),
      iterHelpers: typeof window.Iterator !== 'undefined' &&
        safe(function () { return typeof window.Iterator.prototype.map === 'function'; }, false),
      regexpEscape: typeof RegExp.escape === 'function',
      promiseTry: typeof Promise['try'] === 'function',
      cssHas: cs('selector(:has(a))'),
      cssContainer: cs('container-type: inline-size'),
      cssOklch: cs('color: oklch(0 0 0)'),
      cssTextWrapBalance: cs('text-wrap: balance'),
    };
  }

  // ── UA Client Hints (async) ───────────────────────────────────────────────
  function uach() {
    var d = navigator.userAgentData;
    if (!d || !d.getHighEntropyValues) return null;
    return d.getHighEntropyValues(['platform', 'platformVersion', 'architecture', 'bitness',
      'model', 'mobile', 'fullVersionList']).then(function (v) {
      return {
        platform: v.platform, platformVersion: v.platformVersion, architecture: v.architecture,
        bitness: v.bitness, model: v.model, mobile: v.mobile,
        fullVersionList: (v.fullVersionList || []).map(function (b) { return b.brand + '/' + b.version; }),
      };
    });
  }

  function intl() {
    var o = safe(function () { return Intl.DateTimeFormat().resolvedOptions(); }, {});
    return {
      languages: safe(function () { return Array.prototype.slice.call(navigator.languages || []); }, []),
      locale: o.locale || null, calendar: o.calendar || null,
      numberingSystem: o.numberingSystem || null, timeZone: o.timeZone || null,
    };
  }

  function mq() {
    var m = function (q) { return safe(function () { return matchMedia(q).matches; }, null); };
    return {
      pointerCoarse: m('(pointer: coarse)'), pointerFine: m('(pointer: fine)'),
      anyCoarse: m('(any-pointer: coarse)'), anyFine: m('(any-pointer: fine)'),
      hover: m('(hover: hover)'), anyHover: m('(any-hover: hover)'),
      gamutP3: m('(color-gamut: p3)'), hdr: m('(dynamic-range: high)'),
      dark: m('(prefers-color-scheme: dark)'), reducedMotion: m('(prefers-reduced-motion: reduce)'),
      forcedColors: m('(forced-colors: active)'),
    };
  }

  var CODECS = ['video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="hev1.1.6.L93.B0"',
    'video/webm; codecs="vp8"', 'video/webm; codecs="vp9"', 'video/webm; codecs="av01.0.05M.08"',
    'video/mp4; codecs="av01.0.05M.08"', 'video/ogg; codecs="theora"', 'audio/mp4; codecs="mp4a.40.2"',
    'audio/mpeg', 'audio/ogg; codecs="vorbis"', 'audio/ogg; codecs="opus"', 'audio/webm; codecs="opus"',
    'audio/flac', 'audio/wav; codecs="1"', 'application/vnd.apple.mpegurl'];

  function codecs() {
    var v = document.createElement('video');
    var ms = window.MediaSource;
    return CODECS.map(function (c) {
      return [safe(function () { return v.canPlayType(c); }, ''),
              safe(function () { return ms ? ms.isTypeSupported(c) : null; }, null)];
    });
  }

  // Voices load lazily: null means "not known by the deadline", never zero.
  function voices(ms) {
    if (!window.speechSynthesis) return Promise.resolve(null);
    return new Promise(function (resolve) {
      function take() {
        var v = speechSynthesis.getVoices();
        if (!v.length) return false;
        resolve(v.slice(0, 60).map(function (x) { return [x.name, x.voiceURI, x.localService, x.lang]; }));
        return true;
      }
      if (take()) return;
      safe(function () {
        speechSynthesis.addEventListener('voiceschanged', function () { if (!take()) resolve([]); }, { once: true });
      });
      setTimeout(function () { resolve(null); }, ms);
    });
  }

  function devices() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return null;
    return navigator.mediaDevices.enumerateDevices().then(function (list) {
      var n = { audioinput: 0, audiooutput: 0, videoinput: 0 };
      list.forEach(function (d) { if (n[d.kind] !== undefined) n[d.kind]++; });
      return n;
    });
  }

  function nav() {
    var n = navigator;
    return {
      ua: n.userAgent, platform: n.platform,
      hc: n.hardwareConcurrency === undefined ? null : n.hardwareConcurrency,
      dm: n.deviceMemory === undefined ? null : n.deviceMemory,
      maxTouchPoints: n.maxTouchPoints || 0,
      langs: safe(function () { return Array.prototype.join.call(n.languages || [], ','); }, ''),
      plugins: safe(function () { return n.plugins.length; }, null),
      mimeTypes: safe(function () { return n.mimeTypes.length; }, null),
      pdfViewer: n.pdfViewerEnabled === undefined ? null : n.pdfViewerEnabled,
      brave: !!n.brave,
      conn: safe(function () {
        var c = n.connection;
        return c ? { type: c.effectiveType, rtt: c.rtt, downlink: c.downlink, saveData: c.saveData } : null;
      }, null),
      heapLimit: safe(function () { return performance.memory.jsHeapSizeLimit; }, null),
    };
  }

  function navAsync() {
    var k = navigator.keyboard && navigator.keyboard.getLayoutMap
      ? navigator.keyboard.getLayoutMap().then(function (m) { return m.size; }) : null;
    var q = navigator.storage && navigator.storage.estimate
      ? navigator.storage.estimate().then(function (e) { return e.quota; }) : null;
    return Promise.all([Promise.resolve(k).then(null, function () { return null; }),
                        Promise.resolve(q).then(null, function () { return null; })])
      .then(function (r) { return { keyboardSize: r[0], quota: r[1] }; });
  }

  function scr() {
    var s = screen;
    return {
      w: s.width, h: s.height, aw: s.availWidth, ah: s.availHeight,
      al: s.availLeft === undefined ? null : s.availLeft,
      at: s.availTop === undefined ? null : s.availTop,
      cd: s.colorDepth, pd: s.pixelDepth, dpr: window.devicePixelRatio || 0,
      orient: safe(function () { return s.orientation.type; }, null),
    };
  }

  // Navigator as seen from a fresh same-origin iframe. Stealth patches
  // applied to the top window's navigator commonly miss child realms.
  function iframeNav() {
    var f = document.createElement('iframe');
    f.style.display = 'none';
    f.srcdoc = '';
    root().appendChild(f);
    try {
      var n = f.contentWindow.navigator;
      return { ua: n.userAgent, platform: n.platform,
               hc: n.hardwareConcurrency === undefined ? null : n.hardwareConcurrency,
               webdriver: !!n.webdriver };
    } finally {
      f.parentNode.removeChild(f);
    }
  }

  // Native getters throw a TypeError when called on the wrong receiver;
  // JS replacements usually don't. Real browsers keep navigator's
  // properties on the prototype; patches often define own properties.
  function integrity() {
    var noThrow = [];
    ['webdriver', 'hardwareConcurrency', 'languages', 'platform', 'userAgent'].forEach(function (k) {
      var d = safe(function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, k); }, null);
      if (!d || typeof d.get !== 'function') return;
      try { d.get.call({}); noThrow.push(k); } catch (e) { if (!(e instanceof TypeError)) noThrow.push(k); }
    });
    var ts = safe(function () { return Function.prototype.toString.call(Function.prototype.toString); }, '');
    return {
      getterNoThrow: noThrow,
      navOwnProps: safe(function () { return Object.getOwnPropertyNames(navigator).slice(0, 20); }, []),
      toStringNative: /^function toString\(\)\s*\{\s*\[native code\]\s*\}$/.test(ts),
    };
  }

  // Chrome DevTools Protocol: with Runtime.enable active, console arguments
  // are serialised for the protocol, which reads the stack getter. Partly
  // patched in V8 (2025) and tripped by a human with DevTools open, so the
  // server only logs it.
  function cdp() {
    var hit = false;
    try {
      var e = new Error('');
      Object.defineProperty(e, 'stack', { get: function () { hit = true; return ''; } });
      console.debug(e);
    } catch (_) {}
    return hit;
  }

  // collect resolves within roughly ms. Synchronous sections run at once;
  // asynchronous ones get whatever time is left.
  function collect(ms) {
    var t0 = Date.now();
    var fp = {
      v: 1,
      canvas: canvas(),
      canvasPx: safe(canvasPx, null),
      webgl: safe(webgl, null),
      fonts: safe(fonts, null),
      engine: safe(engine, null),
      features: safe(features, null),
      intl: safe(intl, null),
      mq: safe(mq, null),
      codecs: safe(codecs, null),
      nav: safe(nav, null),
      screen: safe(scr, null),
      iframe: safe(iframeNav, null),
      integrity: safe(integrity, null),
      cdp: safe(cdp, false),
      gpu: null, audio: null, uach: null, voices: null, devices: null, navAsync: null,
      worker: null,
    };
    var left = Math.max(50, ms - (Date.now() - t0));
    return Promise.all([
      within(webgpu, left), within(audio, left), within(uach, left),
      voices(left), within(devices, left), within(navAsync, left),
    ]).then(function (r) {
      fp.gpu = r[0]; fp.audio = r[1]; fp.uach = r[2];
      fp.voices = r[3]; fp.devices = r[4]; fp.navAsync = r[5];
      return fp;
    });
  }

  return { collect: collect };
}());
