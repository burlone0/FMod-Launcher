const fs = require('fs');
const path = require('path');
const cp = require('child_process');
let obfuscator;

function log(step, msg) {
  const t = new Date().toISOString().replace('T', ' ').replace('Z', '');
  console.log(`[${t}] [${step}] ${msg}`);
}

function rmrf(p) {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch (_) {}
}
function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
}
function copyFileSync(src, dest) {
  mkdirp(path.dirname(dest));
  fs.copyFileSync(src, dest);
}
function copyDirSync(src, dest, filter = () => true) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    mkdirp(dest);
    for (const entry of fs.readdirSync(src)) {
      const s = path.join(src, entry);
      const d = path.join(dest, entry);
      if (!filter(s, d)) continue;
      const st2 = fs.statSync(s);
      if (st2.isDirectory()) copyDirSync(s, d, filter);
      else copyFileSync(s, d);
    }
  } else {
    copyFileSync(src, dest);
  }
}
function walkFiles(dir, matcher) {
  const out = [];
  for (const entry of fs.readdirSync(dir)) {
    const p = path.join(dir, entry);
    const st = fs.statSync(p);
    if (st.isDirectory()) out.push(...walkFiles(p, matcher));
    else if (matcher(p)) out.push(p);
  }
  return out;
}

const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const APPDIR = path.join(DIST, 'app');

(async () => {
  try {
    log('INIT', 'Preparing build environment');
    rmrf(DIST);
    mkdirp(APPDIR);

    const rootPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

    log('COPY', 'Copying source files');
    copyDirSync(path.join(ROOT, 'src'), path.join(APPDIR, 'src'));

    const appPkg = {
      name: rootPkg.name || 'fmod-launcher',
      productName: rootPkg.productName || 'FMod Launcher',
      version: rootPkg.version || '0.1.0',
      description: rootPkg.description || 'FMod Launcher made by burlone413.',
      main: 'src/main/main.js',
      author: rootPkg.author || '',
      license: rootPkg.license || 'MIT',
      dependencies: rootPkg.dependencies || {}
    };
    fs.writeFileSync(path.join(APPDIR, 'package.json'), JSON.stringify(appPkg, null, 2));

    log('OBF', 'Obfuscating JavaScript sources');
    try {
      obfuscator = require('javascript-obfuscator');
    } catch (e) {
      console.error('javascript-obfuscator is not installed. Run: npm i -D javascript-obfuscator');
      process.exit(1);
    }
    const jsFiles = walkFiles(path.join(APPDIR, 'src'), (p) => p.toLowerCase().endsWith('.js'));
    const obfOptions = {
      compact: true,
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.75,
      deadCodeInjection: true,
      deadCodeInjectionThreshold: 0.2,
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayWrappersCount: 2,
      stringArrayWrappersType: 'function',
      stringArrayWrappersChainedCalls: true,
      stringArrayRotate: true,
      transformObjectKeys: true,
      numbersToExpressions: true,
      simplify: true,
      splitStrings: true,
      splitStringsChunkLength: 6,
      unicodeEscapeSequence: true,
      selfDefending: true,
      renameGlobals: false
    };
    for (const file of jsFiles) {
      const srcCode = fs.readFileSync(file, 'utf8');
      const res = obfuscator.obfuscate(srcCode, obfOptions);
      fs.writeFileSync(file, res.getObfuscatedCode(), 'utf8');
    }

    log('NPM', 'Installing production dependencies in app bundle');
    try {
      cp.execSync('npm install --omit=dev --no-audit --no-fund', { cwd: APPDIR, stdio: 'inherit' });
    } catch (e) {
      log('NPM', 'npm install failed, continuing without installing additional prod deps');
    }

    log('BUILD', 'Building Windows installer with electron-builder');
    cp.execSync('npx electron-builder --win --config=electron-builder.yml', { cwd: ROOT, stdio: 'inherit' });

    log('DONE', 'Build completed. Output in dist/build');
  } catch (e) {
    console.error('\nBuild failed:', e?.message || e);
    process.exit(1);
  }
})();
