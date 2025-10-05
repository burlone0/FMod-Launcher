const { app, BrowserWindow, ipcMain, shell, Menu, dialog, safeStorage } = require('electron');
const rpc = require('discord-rich-presence');
const path = require('path');
const fs = require('fs');
const https = require('https');
const appVersion = "1.0.0"
const { spawn } = require('child_process');
const isDev = process.env.FMOD_DEV === '1' || process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

if (!app.requestSingleInstanceLock()) {
  app.quit();
}

let mainWindow;

let sessionSecrets = { email: undefined, password: undefined, token: undefined };

async function isProcessElevated() {
  if (process.platform !== 'win32') return true;
  return await new Promise((resolve) => {
    try {
      const child = spawn('powershell', [
        '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',
        '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
      ], { windowsHide: true });
      let out = '';
      child.stdout.on('data', (d) => { out += d.toString(); });
      child.on('exit', () => {
        try {
          const t = (out || '').trim().toLowerCase();
          resolve(t === 'true');
        } catch (_) {
          resolve(false);
        }
      });
      child.on('error', () => resolve(false));
    } catch (_) {
      resolve(false);
    }
  });
}

function escapeForPSDoubleQuotes(s) {
  try { return String(s).replace(/"/g, '`"'); } catch (_) { return String(s || ''); }
}



const getAuthFilePath = () => path.join(app.getPath('userData'), 'auth.json');

function readAuth() {
  try {
    const raw = fs.readFileSync(getAuthFilePath(), 'utf-8');
    const json = JSON.parse(raw);

    const out = {
      isLoggedIn: !!json.isLoggedIn,
      rememberMe: !!json.rememberMe,
      email: json.email || null,
      displayName: json.displayName || null,
      skinUrl: json.skinUrl || null
    };

    try {
      if (json.passwordEnc && safeStorage?.isEncryptionAvailable?.()) {
        out.password = safeStorage.decryptString(Buffer.from(json.passwordEnc, 'base64'));
      }
    } catch (_) {}
    try {
      if (json.tokenEnc && safeStorage?.isEncryptionAvailable?.()) {
        out.token = safeStorage.decryptString(Buffer.from(json.tokenEnc, 'base64'));
      }
    } catch (_) {}

    if (typeof sessionSecrets.email !== 'undefined') out.email = sessionSecrets.email;
    if (typeof sessionSecrets.password !== 'undefined') out.password = sessionSecrets.password;
    if (typeof sessionSecrets.token !== 'undefined') out.token = sessionSecrets.token;

    if (typeof out.isLoggedIn !== 'boolean') out.isLoggedIn = !!out.token;
    return out;
  } catch (_) {
    return { isLoggedIn: false };
  }
}

function writeAuth(patch) {
  try {
    fs.mkdirSync(path.dirname(getAuthFilePath()), { recursive: true });
    const current = readAuth();
    const next = Object.assign({}, current, patch);

    const persist = {
      isLoggedIn: !!next.isLoggedIn,
      rememberMe: !!next.rememberMe,
      email: next.email || null,
      displayName: next.displayName || null,
      skinUrl: next.skinUrl || null
    };

    const canEnc = !!safeStorage?.isEncryptionAvailable?.();
    if (next.rememberMe && canEnc) {
      if (typeof next.password === 'string' && next.password.length > 0) {
        try { persist.passwordEnc = safeStorage.encryptString(next.password).toString('base64'); } catch (_) {}
      } else if (current?.password) {
        try { persist.passwordEnc = safeStorage.encryptString(current.password).toString('base64'); } catch (_) {}
      }
      if (typeof next.token === 'string' && next.token.length > 0) {
        try { persist.tokenEnc = safeStorage.encryptString(next.token).toString('base64'); } catch (_) {}
      } else if (current?.token) {
        try { persist.tokenEnc = safeStorage.encryptString(current.token).toString('base64'); } catch (_) {}
      }
    }

    fs.writeFileSync(getAuthFilePath(), JSON.stringify(persist, null, 2), 'utf-8');
  } catch (_) {}
}

function loadPage(fileName) {
  if (!mainWindow) return;
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', fileName));
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 680,
    minWidth: 820,
    minHeight: 560,
    title: 'FMod Launcher',
    backgroundColor: '#1b222c',
    icon: path.join(process.resourcesPath || __dirname, '..', 'build', 'fmod.ico'),
    frame: false,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      devTools: isDev
    }
  });

  Menu.setApplicationMenu(null);
  try { mainWindow.removeMenu(); } catch (_) {}
  try { mainWindow.setMenuBarVisibility(false); } catch (_) {}

  try { mainWindow.webContents.setVisualZoomLevelLimits(1, 1); } catch (_) {}
  mainWindow.on('will-resize', (e) => e.preventDefault());

  mainWindow.on('system-context-menu', (e) => e.preventDefault());
  mainWindow.webContents.on('context-menu', (e) => e.preventDefault());

  try { mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' })); } catch (_) {}
  mainWindow.webContents.on('will-navigate', (e, url) => { e.preventDefault(); });
  try {
    mainWindow.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  } catch (_) {}

  mainWindow.webContents.on('before-input-event', (event, input) => {
    const k = (input.key || '').toLowerCase();
    const code = (input.code || '').toLowerCase();
    const isDevTools = (k === 'f12') || (k === 'i' && input.control && input.shift);
    const isReload = (k === 'f5') || (k === 'r' && (input.control || input.meta));
    const isZoomIn = (input.control || input.meta) && (k === '+' || k === '=' || code === 'equal' || code === 'numpadadd');
    const isZoomOut = (input.control || input.meta) && (k === '-' || code === 'minus' || code === 'numpadsubtract');
    const isZoomReset = (input.control || input.meta) && (k === '0' || code === 'digit0' || code === 'numpad0');
    if (input.type === 'keyDown' && (isDevTools || isReload || isZoomIn || isZoomOut || isZoomReset)) {
      event.preventDefault();
    }
  });

  loadPage('login.html');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function fetchText(url) {
  return new Promise((resolve) => {
    try {
      const req = https.request(url, { method: 'GET', timeout: 8000 }, (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, text: data }));
      });
      req.on('error', () => resolve({ status: 0, text: '' }));
      req.on('timeout', () => { try { req.destroy(); } catch (_) {} resolve({ status: 0, text: '' }); });
      req.end();
    } catch (_) {
      resolve({ status: 0, text: '' });
    }
  });
}

const DOWNLOAD_URLS = {
  eacZip: 'https://cdn2.fmod.dev/launcher/eac.zip',
  redirectDll: 'https://cdn.fmod.dev/Redir.dll'
};

function downloadFile(url, dest) {
  return new Promise((resolve) => {
    try {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const file = fs.createWriteStream(dest);
      const doReq = (u, redirectsLeft = 3) => {
        const req = https.get(u, (res) => {
          const status = res.statusCode || 0;
          if (status >= 300 && status < 400 && res.headers.location && redirectsLeft > 0) {
            try { req.destroy(); } catch (_) {}
            doReq(res.headers.location, redirectsLeft - 1);
            return;
          }
          if (status !== 200) {
            try { file.close(); } catch (_) {}
            try { fs.unlinkSync(dest); } catch (_) {}
            resolve(false);
            return;
          }
          res.on('error', () => { try { file.close(); } catch (_) {} resolve(false); });
          file.on('error', () => { try { file.close(); } catch (_) {} resolve(false); });
          file.on('finish', () => { try { file.close(() => resolve(true)); } catch (_) { resolve(true); } });
          res.pipe(file);
        });
        req.on('error', () => { try { file.close(); } catch (_) {} resolve(false); });
        req.setTimeout(30000, () => { try { req.destroy(); } catch (_) {} resolve(false); });
      };
      doReq(url);
    } catch (_) {
      resolve(false);
    }
  });
}

function extractZipWithPowerShell(zipPath, destDir) {
  return new Promise((resolve) => {
    try {
      const zipEsc = zipPath.replace(/'/g, "''");
      const destEsc = destDir.replace(/'/g, "''");
      const args = [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command',
        `Try { Expand-Archive -LiteralPath '${zipEsc}' -DestinationPath '${destEsc}' -Force; exit 0 } Catch { exit 1 }`
      ];
      const child = spawn('powershell', args, { windowsHide: true, stdio: 'ignore' });
      child.on('exit', (code) => resolve(code === 0));
      child.on('error', () => resolve(false));
    } catch (_) {
      resolve(false);
    }
  });
}

async function prepareGameFiles(root) {
  try {
    const tmpDir = path.join(app.getPath('temp'), 'fmod_launcher');
    fs.mkdirSync(tmpDir, { recursive: true });

    const zipPath = path.join(tmpDir, 'eac.zip');
    try { fs.unlinkSync(zipPath); } catch (_) {}
    const okZip = await downloadFile(DOWNLOAD_URLS.eacZip, zipPath);
    if (!okZip) return { ok: false, error: 'Failed to download eac.zip.' };
    const extracted = await extractZipWithPowerShell(zipPath, root);
    if (!extracted) return { ok: false, error: 'Failed to extract eac.zip.' };

    const tmpDll = path.join(tmpDir, 'redirect.dll');
    try { fs.unlinkSync(tmpDll); } catch (_) {}
    const okDll = await downloadFile(DOWNLOAD_URLS.redirectDll, tmpDll);
    if (!okDll) return { ok: false, error: 'Failed to download redirect.dll.' };
    const nvDir = path.join(root, 'Engine', 'Binaries', 'ThirdParty', 'NVIDIA', 'NVaftermath', 'Win64');
    fs.mkdirSync(nvDir, { recursive: true });
    const targetDll = path.join(nvDir, 'GFSDK_Aftermath_Lib.x64.dll');
    try { fs.unlinkSync(targetDll); } catch (_) {}
    try {
      fs.copyFileSync(tmpDll, targetDll);
    } catch (_) {
      return { ok: false, error: 'Failed to install redirect.dll.' };
    }

    return { ok: true };
  } catch (_) {
    return { ok: false, error: 'Unexpected error while preparing game files.' };
  }
}

async function checkLauncherVersion() {
  try {
    const { status, text } = await fetchText(new URL('https://api.fmod.dev/api/v1/launcher/versioninfo'));
    if (status < 200 || status >= 300) return;
    let remoteVersion = null;
    try {
      const j = JSON.parse(text);
      remoteVersion = j?.Version || j?.version || null;
    } catch (_) {
      const m = String(text).match(/"?Version"?\s*[:=]\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?/i);
      if (m) remoteVersion = m[1];
    }
    if (remoteVersion && String(remoteVersion).trim() !== String(appVersion).trim()) {
      try {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('update:available', {
            current: String(appVersion).trim(),
            latest: String(remoteVersion).trim(),
            discordUrl: 'https://discord.gg/xw5R7Tp2Xe'
          });
        }
      } catch (_) {}
    }
  } catch (_) {}
}

let injMonitor = { timer: null, strikes: 0 };
function normalizePath(p) {
  try { return String(p || '').replace(/\\+/g, '\\').replace(/\//g, '\\').toLowerCase(); } catch (_) { return ''; }
}
function deriveGameRootFromExe(exePath) {
  const p = normalizePath(exePath);
  if (!p) return null;
  const marker = '\\fortnitegame\\';
  const idx = p.indexOf(marker);
  if (idx > 0) {
    return p.slice(0, idx);
  }
  const parts = p.split('\\').filter(Boolean);
  if (parts.length >= 5) {
    return parts.slice(0, parts.length - 5).join('\\');
  }
  return null;
}
function isSuspiciousModule(modPath, gameRoot) {
  try {
    const m = normalizePath(modPath);
    if (!m) return true;
    if (m.startsWith('c:\\windows\\')) return false;
    if (gameRoot) {
      const root = gameRoot.endsWith('\\') ? gameRoot : (gameRoot + '\\');
      if (m.startsWith(root)) return false;
    }
    return true;
  } catch (_) {
    return true;
  }
}
function terminateAndQuit() {
  try {
    Promise.resolve(killAllGameProcesses()).finally(() => {
      try { app.quit(); } catch (_) {}
    });
  } catch (_) {
    try { app.quit(); } catch (_) {}
  }
}
function startInjectionMonitor() {
  if (injMonitor.timer) return;

  const psArgs = [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
    `Try {
      $procs = Get-CimInstance Win32_Process -Filter "Name='FortniteClient-Win64-Shipping.exe'";
      if (-not $procs) { Write-Output '{"found":false}'; exit 0 }
      foreach ($p in $procs) {
        $pid = $p.ProcessId; $exe = $p.ExecutablePath;
        Try {
          $proc = Get-Process -Id $pid -ErrorAction Stop;
          $mods = $proc.Modules | ForEach-Object { $_.FileName }
        } Catch { $mods = @() }
        $out = [pscustomobject]@{ pid = $pid; exe = $exe; modules = $mods }
        $out | ConvertTo-Json -Depth 3
        break
      }
    } Catch { Write-Output '{"found":false}' }`
  ];

  let running = false;
  const scheduleNext = (delay) => {
    try { clearTimeout(injMonitor.timer); } catch (_) {}
    injMonitor.timer = setTimeout(tick, delay);
  };

  const tick = () => {
    if (running) { scheduleNext(3000); return; }
    running = true;
    let child;
    try {
      child = spawn('powershell', psArgs, { windowsHide: true });
    } catch (_) {
      running = false;
      scheduleNext(5000);
      return;
    }
    let out = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    const finalize = () => {
      running = false;
      try {
        const raw = out.trim();
        if (!raw) { scheduleNext(5000); return; }
        if (raw === '{"found":false}') { injMonitor.strikes = 0; scheduleNext(6000); return; }
        let item = null;
        try { item = JSON.parse(raw); } catch (_) { item = null; }
        if (!item) { scheduleNext(5000); return; }
        const exe = (item && item.exe) || '';
        const gameRoot = deriveGameRootFromExe(exe);
        const mods = Array.isArray(item && item.modules) ? item.modules : [];
        for (const m of mods) {
          const mPath = (m && (m.FileName || m.fileName)) || (typeof m === 'string' ? m : '');
          if (isSuspiciousModule(mPath, gameRoot)) {
            terminateAndQuit();
            return;
          }
        }
        scheduleNext(2500);
      } catch (_) {
        scheduleNext(6000);
      }
    };
    child.on('exit', finalize);
    child.on('error', () => { running = false; scheduleNext(6000); });
  };

  scheduleNext(2000);
}

app.whenReady().then(async () => {
  if (!isDev) {
    try {
      const clientId = '1422257338613760170';
      const client = rpc(clientId);
      client.updatePresence({
        details: 'Playing OG Fortnite',
        state: 'Playing FMod!',
        startTimestamp: Math.floor(Date.now() / 1000),
        largeImageKey: 'big',
        largeImageText: 'FMod',
        smallImageKey: 'small',
        smallImageText: 'Made by burlone413',
        instance: false,
        buttons: [
          { label: 'Official Discord', url: 'https://discord.gg/xw5R7Tp2Xe' }
        ]
      });
    } catch (e) {}
  }

  createWindow();
  checkLauncherVersion();
  startInjectionMonitor();

  try {
    const elevated = await isProcessElevated();
    if (!elevated && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('elevation:prompt');
    }
  } catch (_) {}
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (injMonitor && injMonitor.timer) { try { clearInterval(injMonitor.timer); } catch (_) {} injMonitor.timer = null; }
  try { killAllGameProcesses(); } catch (_) {}
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('open-external', async (_event, url) => {
  try {
    const u = new URL(String(url));
    if (u.protocol !== 'https:') return;
    await shell.openExternal(u.toString());
  } catch (_) {}
});

ipcMain.handle('auth:get', async () => readAuth());
ipcMain.handle('auth:set', async (_event, data) => {
  const patch = (typeof data === 'boolean') ? { isLoggedIn: !!data } : (data || {});
  if (patch && typeof patch === 'object') {
    if ('email' in patch) sessionSecrets.email = patch.email;
    if ('password' in patch) sessionSecrets.password = patch.password;
    if ('token' in patch) sessionSecrets.token = patch.token;
  }
  writeAuth(patch);
  return readAuth();
});

ipcMain.handle('nav:to-main', async () => {
  loadPage('home.html');
});

ipcMain.handle('nav:to-login', async () => {
  loadPage('login.html');
});


ipcMain.handle('api:login', async (_event, { email, password }) => {
  try {
    const elevated = await isProcessElevated();
    if (!elevated) {
      return { status: 403, body: { error: 'elevation_required' } };
    }
    if (isDev) {
      return { status: 200, body: { display_name: 'Developer', account_id: 'dev', character: null } };
    }
    const url = new URL('https://api.fmod.dev/api/v1/launcher/login');
    const payload = `email=${encodeURIComponent(email || '')}&password=${encodeURIComponent(password || '')}`;
    return await new Promise((resolve) => {
      const req = https.request(
        url,
        {
          method: 'POST',
          timeout: 10000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(payload)
          }
        },
        (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (c) => (data += c));
          res.on('end', () => {
            try {
              const json = data ? JSON.parse(data) : null;
              resolve({ status: res.statusCode || 0, body: json });
            } catch (_) {
              resolve({ status: res.statusCode || 0, body: null });
            }
          });
        }
      );
      req.on('error', () => resolve({ status: 0, body: null }));
      req.on('timeout', () => {
        try { req.destroy(); } catch (_) {}
        resolve({ status: 0, body: null });
      });
      try { req.write(payload); } catch (_) {}
      req.end();
    });
  } catch (_) {
    return { status: 0, body: null };
  }
});

function resolveFirstExisting(paths) {
  for (const p of paths) {
    try { if (fs.existsSync(p)) return p; } catch (_) {}
  }
  return null;
}
function forceStartAndFreezeTargets(root) {
  const launcherPaths = [
    path.join(root, 'FortniteLauncher.exe'),
    path.join(root, 'FortniteGame', 'Binaries', 'Win64', 'FortniteLauncher.exe')
  ];
  const eacClientPaths = [
    path.join(root, 'FortniteGame', 'Binaries', 'Win64', 'FortniteClient-Win64-Shipping_EAC.exe')
  ];
  const launcher = resolveFirstExisting(launcherPaths);
  const eacClient = resolveFirstExisting(eacClientPaths);
  return { launcher, eacClient };
}
async function launchEAC(root, args) {
  const eacSetup = path.join(root, 'EasyAntiCheat', 'EasyAntiCheat_EOS_Setup.exe');
  if (!fs.existsSync(eacSetup)) return { ok: false, error: 'EAC setup executable not found.' };
  await new Promise((resolve) => {
    try {
      const child = spawn(eacSetup, ['install', '38af59a283b34cdebb257311cef14c43'], {
        cwd: root,
        windowsHide: true,
        stdio: 'ignore'
      });
      let done = false;
      const to = setTimeout(() => {
        if (done) return; done = true;
        try { child.kill(); } catch (_) {}
        resolve();
      }, 10000);
      child.on('exit', () => { if (done) return; done = true; clearTimeout(to); resolve(); });
      child.on('error', () => { if (done) return; done = true; clearTimeout(to); resolve(); });
    } catch (_) {
      resolve();
    }
  });

  const exe = path.join(root, 'FModEAC.exe');
  if (!fs.existsSync(exe)) return { ok: false, error: 'FModEAC.exe not found.' };
  try {
    const proc = spawn(exe, args, { cwd: root, windowsHide: true, stdio: 'ignore', detached: true });
    proc.unref();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Failed to start FModEAC.exe.' };
  }
}
ipcMain.handle('game:launch', async (_event, { root, email, password }) => {
  try {
    if (typeof root !== 'string' || !root || !fs.existsSync(root)) {
      return { ok: false, error: 'Invalid or missing 8.51 path.' };
    }
    if (!email || !password) {
      return { ok: false, error: 'Missing account credentials.' };
    }
    const prep = await prepareGameFiles(root);
    if (!prep.ok) return prep;
    const targets = forceStartAndFreezeTargets(root);
    const argsStr = `-AUTH_TYPE=epic -auth_login=${email} -auth_password=${password} -epicapp=Fortnite -epicenv=Prod -epiclocale=en-us -epicportal -skippatchcheck -nobe -fromfl=eac -fltoken=3db3ba5dcbd2e16703f3978d`;
    const args = argsStr.match(/\S+/g) || [];
    const res = await launchEAC(root, args);
    if (!res.ok) return res;
    return { ok: true, resolved: targets };
  } catch (_) {
    return { ok: false, error: 'Launch failed due to an unexpected error.' };
  }
});

ipcMain.handle('game:prepare', async (_event, root) => {
  try {
    if (typeof root !== 'string' || !root || !fs.existsSync(root)) {
      return { ok: false, error: 'Invalid or missing 8.51 path.' };
    }
    return await prepareGameFiles(root);
  } catch (_) {
    return { ok: false, error: 'Unexpected error during preparation.' };
  }
});

ipcMain.handle('game:start', async (_event, { root, email, password }) => {
  try {
    if (typeof root !== 'string' || !root || !fs.existsSync(root)) {
      return { ok: false, error: 'Invalid or missing 8.51 path.' };
    }
    if (!email || !password) {
      return { ok: false, error: 'Missing account credentials.' };
    }
    const targets = forceStartAndFreezeTargets(root);
    const argsStr = `-AUTH_TYPE=epic -auth_login=${email} -auth_password=${password} -epicapp=Fortnite -epicenv=Prod -epiclocale=en-us -epicportal -skippatchcheck -nobe -fromfl=eac -fltoken=3db3ba5dcbd2e16703f3978d`;
    const args = argsStr.match(/\S+/g) || [];
    const res = await launchEAC(root, args);
    if (!res.ok) return res;
    return { ok: true, resolved: targets };
  } catch (_) {
    return { ok: false, error: 'Launch failed due to an unexpected error.' };
  }
});

const GAME_PROCESSES = [
  'FortniteClient-Win64-Shipping',
  'FortniteClient-Win64-Shipping_BE',
  'FModEAC',
  'FortniteClient-Win64-Shipping_EAC',
  'FortniteLauncher'
];
function killProcessByName(imageBase) {
  return new Promise((resolve) => {
    try {
      const image = imageBase.toLowerCase().endsWith('.exe') ? imageBase : `${imageBase}.exe`;
      const child = spawn('taskkill', ['/IM', image, '/F', '/T'], { windowsHide: true });
      child.on('exit', () => resolve());
      child.on('error', () => resolve());
    } catch (_) {
      resolve();
    }
  });
}
async function killAllGameProcesses() {
  for (const name of GAME_PROCESSES) {
    await killProcessByName(name);
  }
}
ipcMain.handle('game:kill', async () => {
  try {
    await killAllGameProcesses();
    return { ok: true };
  } catch (_) {
    return { ok: false };
  }
});
app.on('before-quit', () => { try { killAllGameProcesses(); } catch (_) {} });
app.on('will-quit', () => { try { killAllGameProcesses(); } catch (_) {} });

ipcMain.handle('dialog:select-folder', async () => {
  if (!mainWindow) return null;
  const res = await dialog.showOpenDialog(mainWindow, {
    title: 'Select 8.51 Build Folder',
    properties: ['openDirectory', 'createDirectory']
  });
  if (res.canceled || !res.filePaths || res.filePaths.length === 0) return null;
  return res.filePaths[0];
});

const REQUIRED_PAKS = [
  'pakchunk0-WindowsClient.pak',
  'pakchunk0-WindowsClient.sig',
  'pakchunk1-WindowsClient.pak',
  'pakchunk1-WindowsClient.sig',
  'pakchunk2-WindowsClient.pak',
  'pakchunk2-WindowsClient.sig',
  'pakchunk5-WindowsClient.pak',
  'pakchunk5-WindowsClient.sig',
  'pakchunk7-WindowsClient.pak',
  'pakchunk7-WindowsClient.sig',
  'pakchunk8-WindowsClient.pak',
  'pakchunk8-WindowsClient.sig',
  'pakchunk9-WindowsClient.pak',
  'pakchunk9-WindowsClient.sig',
  'pakchunk10_s1-WindowsClient.pak',
  'pakchunk10_s1-WindowsClient.sig',
  'pakchunk10_s2-WindowsClient.pak',
  'pakchunk10_s2-WindowsClient.sig',
  'pakchunk10_s3-WindowsClient.pak',
  'pakchunk10_s3-WindowsClient.sig',
  'pakchunk10_s4-WindowsClient.pak',
  'pakchunk10_s4-WindowsClient.sig',
  'pakchunk10_s5-WindowsClient.pak',
  'pakchunk10_s5-WindowsClient.sig',
  'pakchunk10_s6-WindowsClient.pak',
  'pakchunk10_s6-WindowsClient.sig',
  'pakchunk10_s7-WindowsClient.pak',
  'pakchunk10_s7-WindowsClient.sig',
  'pakchunk10_s8-WindowsClient.pak',
  'pakchunk10_s8-WindowsClient.sig',
  'pakchunk10-WindowsClient.pak',
  'pakchunk10-WindowsClient.sig',
  'pakchunk11_s1-WindowsClient.pak',
  'pakchunk11_s1-WindowsClient.sig',
  'pakchunk11-WindowsClient.pak',
  'pakchunk11-WindowsClient.sig',
  'pakchunk1000-WindowsClient.pak',
  'pakchunk1000-WindowsClient.sig',
  'pakchunk1001-WindowsClient.pak',
  'pakchunk1001-WindowsClient.sig',
  'pakchunk1002-WindowsClient.pak',
  'pakchunk1002-WindowsClient.sig',
  'pakchunk1003-WindowsClient.pak',
  'pakchunk1003-WindowsClient.sig',
  'pakchunk1004-WindowsClient.pak',
  'pakchunk1004-WindowsClient.sig',
  'pakchunk1005-WindowsClient.pak',
  'pakchunk1005-WindowsClient.sig',
  'pakchunk1006-WindowsClient.pak',
  'pakchunk1006-WindowsClient.sig',
  'pakchunk1007-WindowsClient.pak',
  'pakchunk1007-WindowsClient.sig',
  'pakchunk1008-WindowsClient.pak',
  'pakchunk1008-WindowsClient.sig',
  'pakchunk1009-WindowsClient.pak',
  'pakchunk1009-WindowsClient.sig'
];

ipcMain.handle('validate:build-folder', async (_event, baseDir) => {
  try {
    if (typeof baseDir !== 'string' || !baseDir) {
      return { ok: false, missing: ['<invalid selection>'] };
    }
    const paksDir = path.join(baseDir, 'FortniteGame', 'Content', 'Paks');
    const missing = REQUIRED_PAKS.filter(name => !fs.existsSync(path.join(paksDir, name)));
    return { ok: missing.length === 0, missing, paksPath: paksDir };
  } catch (_) {
    return { ok: false, missing: ['<error>'] };
  }
});

ipcMain.handle('elevate:relaunch', async () => {
  try {
    const exe = process.execPath;
    const args = (process.argv || []).slice(1);
    const exeEsc = escapeForPSDoubleQuotes(exe);
    const argsList = args.map(a => `"${escapeForPSDoubleQuotes(a)}"`).join(', ');
    const psCmd = `Start-Process -FilePath \"${exeEsc}\" -ArgumentList @(${argsList}) -Verb RunAs`;
    try {
      const pr = spawn('powershell', ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command', psCmd], { windowsHide: true, stdio: 'ignore', detached: true });
      try { pr.unref(); } catch (_) {}
    } catch (_) {}
    setTimeout(() => { try { app.quit(); } catch (_) {} }, 100);
    return { ok: true };
  } catch (_) {
    return { ok: false };
  }
});

ipcMain.handle('elevate:status', async () => {
  try {
    return await isProcessElevated();
  } catch (_) {
    return false;
  }
});

ipcMain.handle('win:minimize', async () => {
  if (mainWindow) mainWindow.minimize();
});
ipcMain.handle('win:close', async () => {
  if (mainWindow) mainWindow.close();
});
