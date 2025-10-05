const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('fmod', {
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  auth: {
    get: () => ipcRenderer.invoke('auth:get'),
    set: (isLoggedIn) => ipcRenderer.invoke('auth:set', isLoggedIn)
  },
  nav: {
    toMain: () => ipcRenderer.invoke('nav:to-main'),
    toLogin: () => ipcRenderer.invoke('nav:to-login')
  },
  api: {
    login: (email, password) => ipcRenderer.invoke('api:login', { email, password })
  },
  dialog: {
    selectFolder: () => ipcRenderer.invoke('dialog:select-folder')
  },
  validate: {
    buildFolder: (baseDir) => ipcRenderer.invoke('validate:build-folder', baseDir)
  },
  game: {
    prepare: (root) => ipcRenderer.invoke('game:prepare', root),
    start: (root, email, password) => ipcRenderer.invoke('game:start', { root, email, password }),
    launch: (root, email, password) => ipcRenderer.invoke('game:launch', { root, email, password }),
    kill: () => ipcRenderer.invoke('game:kill')
  },
  elevate: {
    relaunch: () => ipcRenderer.invoke('elevate:relaunch'),
    status: () => ipcRenderer.invoke('elevate:status')
  },
  win: {
    minimize: () => ipcRenderer.invoke('win:minimize'),
    close: () => ipcRenderer.invoke('win:close')
  }
});

(() => {
  let modalOpen = false;
  let unblock = null;
  function blockInteractions(overlay) {
    const handler = (e) => {
      try {
        if (overlay && (overlay === e.target || (overlay.contains && overlay.contains(e.target)))) {
          return;
        }
      } catch (_) {}
      e.preventDefault();
      e.stopImmediatePropagation();
    };
    const types = ['click','pointerdown','mousedown','mouseup','keydown','keypress','keyup','wheel','contextmenu','touchstart','touchend'];
    types.forEach(t => window.addEventListener(t, handler, true));
    return () => types.forEach(t => window.removeEventListener(t, handler, true));
  }
  function showUpdateModal(payload) {
    if (modalOpen) return;
    modalOpen = true;
    const { current, latest, discordUrl } = payload || {};

    const overlay = document.createElement('div');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.display = 'grid';
    overlay.style.placeItems = 'center';
    overlay.style.background = 'rgba(0,0,0,0.45)';
    overlay.style.zIndex = '99999';
    overlay.style.backdropFilter = 'blur(2px)';

    const modal = document.createElement('div');
    modal.style.width = 'min(520px, 92vw)';
    modal.style.borderRadius = '16px';
    modal.style.border = '1px solid rgba(255,255,255,0.10)';
    modal.style.background = 'linear-gradient(180deg, rgba(27,34,44,0.96), rgba(21,26,34,0.96))';
    modal.style.boxShadow = '0 18px 48px rgba(0,0,0,0.38), inset 0 1px 0 rgba(255,255,255,0.06)';
    modal.style.color = '#e6e8f0';
    modal.style.padding = '18px 18px 14px';
    modal.style.display = 'grid';
    modal.style.gap = '10px';

    const title = document.createElement('h3');
    title.textContent = 'Update Available';
    title.style.margin = '0';
    title.style.fontSize = '18px';
    title.style.fontWeight = '800';

    const msg = document.createElement('p');
    msg.style.margin = '0';
    msg.style.opacity = '0.95';
    msg.style.whiteSpace = 'pre-line';
    msg.textContent = `A new version of FMod Launcher is available.\nCurrent: ${current || '-'}\nLatest: ${latest || '-'}\n\nPlease download the latest version from our Discord.`;

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.justifyContent = 'flex-end';
    actions.style.gap = '10px';
    actions.style.marginTop = '6px';

    const btnClose = document.createElement('button');
    btnClose.textContent = 'Exit';
    btnClose.style.border = '1px solid rgba(255,255,255,0.12)';
    btnClose.style.background = 'rgba(255,255,255,0.06)';
    btnClose.style.color = '#ffffff';
    btnClose.style.borderRadius = '10px';
    btnClose.style.padding = '8px 12px';
    btnClose.style.cursor = 'pointer';
    btnClose.style.fontWeight = '800';
    btnClose.style.boxShadow = '0 10px 24px rgba(255,255,255,0.12)';

    const btnOpen = document.createElement('button');
    btnOpen.textContent = 'Open Discord';
    btnOpen.style.border = 'none';
    btnOpen.style.background = 'linear-gradient(135deg, #6ee7ff, #3aa8ff)';
    btnOpen.style.color = '#ffffff';
    btnOpen.style.fontWeight = '800';
    btnOpen.style.borderRadius = '10px';
    btnOpen.style.padding = '8px 14px';
    btnOpen.style.cursor = 'pointer';
    btnOpen.style.boxShadow = '0 10px 24px rgba(110,231,255,0.35)';

    const cleanup = () => {
      try { overlay.remove(); } catch (_) {}
      if (unblock) { try { unblock(); } catch (_) {} unblock = null; }
      modalOpen = false;
    };

    btnClose.addEventListener('click', async () => {
      try { await ipcRenderer.invoke('win:close'); } catch (_) {}
    });
    btnOpen.addEventListener('click', async () => {
      try { if (discordUrl) await ipcRenderer.invoke('open-external', discordUrl); } catch (_) {}
      try { await ipcRenderer.invoke('win:close'); } catch (_) {}
    });

    actions.appendChild(btnClose);
    actions.appendChild(btnOpen);

    modal.appendChild(title);
    modal.appendChild(msg);
    modal.appendChild(actions);

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    try { unblock = blockInteractions(overlay); } catch (_) {}
  }

  function showElevationModal() {
    if (modalOpen) return;
    modalOpen = true;

    const overlay = document.createElement('div');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.position = 'fixed';
    overlay.style.inset = '0';
    overlay.style.display = 'grid';
    overlay.style.placeItems = 'center';
    overlay.style.background = 'rgba(0,0,0,0.45)';
    overlay.style.zIndex = '99999';
    overlay.style.backdropFilter = 'blur(2px)';

    const modal = document.createElement('div');
    modal.style.width = 'min(520px, 92vw)';
    modal.style.borderRadius = '16px';
    modal.style.border = '1px solid rgba(255,255,255,0.10)';
    modal.style.background = 'linear-gradient(180deg, rgba(27,34,44,0.96), rgba(21,26,34,0.96))';
    modal.style.boxShadow = '0 18px 48px rgba(0,0,0,0.38), inset 0 1px 0 rgba(255,255,255,0.06)';
    modal.style.color = '#e6e8f0';
    modal.style.padding = '18px 18px 14px';
    modal.style.display = 'grid';
    modal.style.gap = '10px';

    const title = document.createElement('h3');
    title.textContent = 'Administrator Privileges Recommended';
    title.style.margin = '0';
    title.style.fontSize = '18px';
    title.style.fontWeight = '800';

    const msg = document.createElement('p');
    msg.style.margin = '0';
    msg.style.opacity = '0.95';
    msg.style.whiteSpace = 'pre-line';
    msg.textContent = 'FMod Launcher needs administrator privileges to properly manage game files and anti-cheat components.';

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.justifyContent = 'flex-end';
    actions.style.gap = '10px';
    actions.style.marginTop = '6px';

    const btnClose = document.createElement('button');
    btnClose.textContent = 'Exit';
    btnClose.style.border = '1px solid rgba(255,255,255,0.12)';
    btnClose.style.background = 'rgba(255,255,255,0.06)';
    btnClose.style.color = '#ffffff';
    btnClose.style.borderRadius = '10px';
    btnClose.style.padding = '8px 12px';
    btnClose.style.cursor = 'pointer';
    btnClose.style.fontWeight = '800';
    btnClose.style.boxShadow = '0 10px 24px rgba(255,255,255,0.12)';

    
    const cleanup = () => {
      try { overlay.remove(); } catch (_) {}
      if (unblock) { try { unblock(); } catch (_) {} unblock = null; }
      modalOpen = false;
    };

    btnClose.addEventListener('click', async () => {
      try { await ipcRenderer.invoke('win:close'); } catch (_) {}
      cleanup();
    });
    
    actions.appendChild(btnClose);

    modal.appendChild(title);
    modal.appendChild(msg);
    modal.appendChild(actions);

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    try { unblock = blockInteractions(overlay); } catch (_) {}
  }

  ipcRenderer.on('elevation:prompt', () => {
    try { showElevationModal(); } catch (_) {}
  });

  ipcRenderer.on('update:available', (_e, data) => {
    try { showUpdateModal(data); } catch (_) {}
  });
})();
