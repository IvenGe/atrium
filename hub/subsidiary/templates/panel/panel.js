/* Atrium bridge panel widget - contract atrium-bridge/1. VENDORED FILE: served byte-identical (its SHA-256 is pinned
 * in the bridge core); do not edit. "Ask the team": a floating button and a non-modal drawer in a Shadow DOM, for
 * the signed-in tool user. Answers are plain text (textContent, pre-wrap): never HTML, never links. No inline
 * script, so it works under script-src 'self'. Context: data-atrium-context="ticket:42" on any element, or
 * window.AtriumTeam.setContext({type: "ticket", id: 42}). */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.AtriumTeam) return;

  var script = document.currentScript;
  var base = '';
  if (script && script.src) {
    var at = script.src.indexOf('/.atrium/panel.js');
    base = at >= 0 ? script.src.slice(0, at) : '';
  }
  var API = base + '/.atrium/v1/panel';
  var STORE = 'atrium-team-questions';
  var MAX_TEXT = 2000;
  var POLL_MS = 4000;
  var BANNER = 'AI team supervised by Atrium. It can look things up and draft; changes need approval in Atrium.';
  var LABELS = {
    waiting: 'Waiting for the team',
    answering: 'The team is answering',
    answered: 'Answered',
    escalated: 'Passed on to a person',
    declined: 'Declined',
    unavailable: 'The team is not available right now',
    lost: 'Your question was lost, ask again'
  };
  var ERRORS = {
    401: 'Sign in to ask the team.',
    404: 'The team is not available here.',
    413: 'Your question is too long.',
    422: 'Your question is too long or empty.',
    429: 'You have asked many questions this hour; try again later.',
    503: 'The team has too many open questions; try again later.'
  };
  var CSS = [
    ':host{all:initial;--at-bg:#fff;--at-fg:#1d2433;--at-muted:#5b6475;--at-line:#d7dce5;--at-accent:#3557d4;',
    '--at-accent-fg:#fff;--at-soft:#f3f5f9;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}',
    '@media (prefers-color-scheme:dark){:host{--at-bg:#1b1f27;--at-fg:#e6e9ef;--at-muted:#a3abba;--at-line:#353b47;',
    '--at-accent:#7b96ff;--at-accent-fg:#0d1020;--at-soft:#242a35}}',
    '.button{position:fixed;right:20px;bottom:20px;z-index:2147483000;border:0;border-radius:999px;padding:10px 16px;',
    'background:var(--at-accent);color:var(--at-accent-fg);font:inherit;font-weight:600;cursor:pointer;',
    'box-shadow:0 4px 14px rgba(0,0,0,.25)}',
    '.button:focus-visible,.close:focus-visible,.send:focus-visible,textarea:focus-visible{outline:3px solid var(--at-accent);',
    'outline-offset:2px}',
    '.drawer{position:fixed;right:20px;bottom:72px;z-index:2147483001;width:min(380px,calc(100vw - 40px));',
    'max-height:min(560px,calc(100vh - 100px));display:flex;flex-direction:column;background:var(--at-bg);',
    'color:var(--at-fg);border:1px solid var(--at-line);border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.3)}',
    '.drawer[hidden]{display:none}',
    '.head{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;',
    'border-bottom:1px solid var(--at-line)}',
    '.title{margin:0;font-size:15px;font-weight:600}',
    '.close{border:0;background:transparent;color:var(--at-muted);font:inherit;font-size:18px;cursor:pointer;',
    'padding:2px 8px;border-radius:6px}',
    '.banner{margin:0;padding:8px 12px;background:var(--at-soft);color:var(--at-muted);font-size:12px}',
    '.list{list-style:none;margin:0;padding:8px 12px;overflow:auto;flex:1 1 auto}',
    '.item{padding:8px 0;border-bottom:1px solid var(--at-line)}',
    '.item:last-child{border-bottom:0}',
    '.question,.answer{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}',
    '.question{font-weight:600}',
    '.status{margin:4px 0 0;font-size:12px;color:var(--at-muted)}',
    '.answer{margin-top:6px}',
    '.by{margin:2px 0 0;font-size:12px;color:var(--at-muted)}',
    '.empty{color:var(--at-muted);margin:4px 0}',
    'form{display:flex;flex-direction:column;gap:8px;padding:10px 12px;border-top:1px solid var(--at-line)}',
    'textarea{font:inherit;color:var(--at-fg);background:var(--at-bg);border:1px solid var(--at-line);',
    'border-radius:8px;padding:8px;min-height:64px;resize:vertical}',
    '.row{display:flex;align-items:center;justify-content:space-between;gap:8px}',
    '.note{font-size:12px;color:var(--at-muted);margin:0}',
    '.send{border:0;border-radius:8px;padding:7px 14px;background:var(--at-accent);color:var(--at-accent-fg);',
    'font:inherit;font-weight:600;cursor:pointer}',
    '.send[disabled]{opacity:.6;cursor:default}',
    '.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}'
  ].join('');

  var context = null;
  var questions = [];
  var host, root, button, drawer, list, form, input, send, note, live;
  var timer = null;
  var busy = false;

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    var names = attrs ? Object.keys(attrs) : [];
    for (var i = 0; i < names.length; i++) node.setAttribute(names[i], attrs[names[i]]);
    if (text != null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function request(method, path, body) {
    var init = { method: method, credentials: 'same-origin', headers: { 'X-Atrium-Panel': '1' } };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return fetch(API + path, init).then(function (res) {
      return res.json().then(function (data) { return { status: res.status, data: data }; },
        function () { return { status: res.status, data: null }; });
    });
  }

  function loadIds() {
    try {
      var ids = JSON.parse(window.sessionStorage.getItem(STORE) || '[]');
      return Array.isArray(ids) ? ids.filter(function (id) { return typeof id === 'string'; }).slice(-20) : [];
    } catch (e) {
      return [];
    }
  }

  function saveIds() {
    try {
      var ids = questions.filter(function (q) { return q.status !== 'lost'; }).map(function (q) { return q.id; });
      window.sessionStorage.setItem(STORE, JSON.stringify(ids.slice(-20)));
    } catch (e) { /* storage may be unavailable: questions then last until the page reloads */ }
  }

  function page() {
    var out = { path: String(window.location.pathname || '/').slice(0, 300) };
    var record = context;
    if (!record) {
      var marked = document.querySelector('[data-atrium-context]');
      record = marked ? marked.getAttribute('data-atrium-context') : null;
    }
    if (record) out.record_id = String(record).slice(0, 120);
    return out;
  }

  function pending(q) {
    return q.status === 'waiting' || q.status === 'answering';
  }

  function render() {
    clear(list);
    if (!questions.length) {
      list.appendChild(el('li', { class: 'empty' }, 'Ask about what you see on this page.'));
      return;
    }
    for (var i = questions.length - 1; i >= 0; i--) {
      var q = questions[i];
      var item = el('li', { class: 'item' });
      if (q.text) item.appendChild(el('p', { class: 'question' }, q.text));
      item.appendChild(el('p', { class: 'status' }, LABELS[q.status] || q.status));
      if (q.answer) {
        item.appendChild(el('p', { class: 'answer' }, q.answer));
        if (q.by) item.appendChild(el('p', { class: 'by' }, '- ' + q.by));
      }
      list.appendChild(item);
    }
  }

  function announce(text) {
    live.textContent = '';
    live.textContent = text;
  }

  function refresh() {
    var open = questions.filter(function (q) { return pending(q) || !q.loaded; });
    return Promise.all(open.map(function (q) {
      return request('GET', '/questions/' + encodeURIComponent(q.id)).then(function (res) {
        var before = q.status;
        if (res.status === 404) {
          q.status = 'lost';
        } else if (res.status === 200 && res.data) {
          q.status = String(res.data.status || 'waiting');
          q.text = typeof res.data.text === 'string' ? res.data.text : q.text;
          q.answer = typeof res.data.answer === 'string' ? res.data.answer : null;
          q.by = typeof res.data.by === 'string' ? res.data.by : null;
          q.loaded = true;
        }
        if (before !== q.status && !pending(q)) announce(LABELS[q.status] || q.status);
      }, function () { /* offline: try again on the next poll */ });
    })).then(function () {
      saveIds();
      render();
      schedule();
    });
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    timer = null;
    if (questions.some(pending)) timer = setTimeout(refresh, POLL_MS);
  }

  function ask(event) {
    if (event) event.preventDefault();
    var text = String(input.value || '').trim();
    if (!text || busy) return Promise.resolve();
    if (text.length > MAX_TEXT) {
      note.textContent = ERRORS[413];
      return Promise.resolve();
    }
    busy = true;
    // disabling the focused Ask button would drop the focus to the page (Esc would no longer close the drawer)
    if (root.activeElement === send) input.focus();
    send.setAttribute('disabled', '');
    note.textContent = '';
    return request('POST', '/ask', { text: text, page: page() }).then(function (res) {
      if (res.status === 200 && res.data && typeof res.data.question_id === 'string') {
        questions.push({ id: res.data.question_id, text: text, status: 'waiting', answer: null, by: null, loaded: true });
        input.value = '';
        saveIds();
        render();
        announce(LABELS.waiting);
        schedule();
      } else {
        note.textContent = ERRORS[res.status] || 'The question could not be sent.';
      }
    }, function () {
      note.textContent = 'The question could not be sent.';
    }).then(function () {
      busy = false;
      send.removeAttribute('disabled');
    });
  }

  function open() {
    if (!drawer) return;
    drawer.removeAttribute('hidden');
    button.setAttribute('aria-expanded', 'true');
    input.focus();
    refresh();
  }

  function close() {
    if (!drawer) return;
    drawer.setAttribute('hidden', '');
    button.setAttribute('aria-expanded', 'false');
    button.focus();
  }

  function build() {
    host = el('div', { 'data-atrium-team': '' });
    root = host.attachShadow({ mode: 'open' });
    if (typeof CSSStyleSheet === 'function' && 'adoptedStyleSheets' in root) {
      var sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
      root.adoptedStyleSheets = [sheet];
    } else {
      root.appendChild(el('style', null, CSS));
    }
    button = el('button', { class: 'button', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'atrium-team' },
      'Ask the team');
    drawer = el('section', { class: 'drawer', id: 'atrium-team', role: 'dialog', 'aria-modal': 'false',
      'aria-labelledby': 'atrium-team-title', hidden: '' });
    var head = el('div', { class: 'head' });
    head.appendChild(el('h2', { class: 'title', id: 'atrium-team-title' }, 'Ask the team'));
    var closer = el('button', { class: 'close', type: 'button', 'aria-label': 'Close' }, '×');
    head.appendChild(closer);
    drawer.appendChild(head);
    drawer.appendChild(el('p', { class: 'banner' }, BANNER));
    list = el('ol', { class: 'list', 'aria-label': 'Your questions' });
    drawer.appendChild(list);
    form = el('form', { novalidate: '' });
    var label = el('label', { class: 'sr', for: 'atrium-team-text' }, 'Your question');
    input = el('textarea', { id: 'atrium-team-text', maxlength: String(MAX_TEXT), rows: '3',
      placeholder: 'Ask about what you see on this page' });
    var row = el('div', { class: 'row' });
    note = el('p', { class: 'note', role: 'status' });
    send = el('button', { class: 'send', type: 'submit' }, 'Ask');
    row.appendChild(note);
    row.appendChild(send);
    form.appendChild(label);
    form.appendChild(input);
    form.appendChild(row);
    drawer.appendChild(form);
    live = el('div', { class: 'sr', 'aria-live': 'polite' });
    root.appendChild(button);
    root.appendChild(drawer);
    root.appendChild(live);
    button.addEventListener('click', function () {
      if (drawer.hasAttribute('hidden')) open(); else close();
    });
    closer.addEventListener('click', close);
    form.addEventListener('submit', ask);
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) ask(event);
    });
    root.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && !drawer.hasAttribute('hidden')) {
        event.stopPropagation();
        close();
      }
    });
    document.body.appendChild(host);
    render();
  }

  function start() {
    questions = loadIds().map(function (id) { return { id: id, status: 'waiting', loaded: false }; });
    return request('GET', '/status').then(function (res) {
      if (res.status !== 200 || !res.data || res.data.enabled !== true) return; // no session or no panel: no button
      build();
      if (questions.length) refresh();
    }, function () { /* the bridge is not reachable: the tool works unchanged */ });
  }

  var ready = null;
  window.AtriumTeam = {
    setContext: function (value) {
      context = value && value.type != null && value.id != null ? String(value.type) + ':' + String(value.id) : null;
    },
    open: open,
    close: close,
    refresh: function () { return drawer ? refresh() : Promise.resolve(); },
    ask: function (text) {
      if (!input) return Promise.resolve();
      input.value = String(text == null ? '' : text);
      return ask(null);
    },
    ready: function () { return ready; }
  };
  if (document.readyState === 'loading') {
    ready = new Promise(function (resolve) {
      document.addEventListener('DOMContentLoaded', function () { start().then(resolve); });
    });
  } else {
    ready = start();
  }
})();
