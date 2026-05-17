/* ═══════════════════════════════════════════════════════════════
   BinIdentifier — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

(() => {
  "use strict";

  // ── DOM refs ──────────────────────────────────────────────────
  const dropzone   = document.getElementById("dropzone");
  const fileInput  = document.getElementById("file-input");
  const fileInfo   = document.getElementById("file-info");
  const filenameEl = document.getElementById("filename");
  const clearBtn   = document.getElementById("clear-btn");
  const analyzeBtn = document.getElementById("analyze-btn");
  const resultsEl  = document.getElementById("results");
  const errorBanner= document.getElementById("error-banner");
  const errorMsg   = document.getElementById("error-msg");

  let selectedFile = null;

  // ── File selection ────────────────────────────────────────────
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });

  // Drag events
  ["dragenter","dragover"].forEach(evt =>
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add("dragover"); })
  );
  ["dragleave","drop"].forEach(evt =>
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove("dragover"); })
  );
  dropzone.addEventListener("drop", e => {
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });

  clearBtn.addEventListener("click", clearFile);

  function setFile(file) {
    selectedFile = file;
    filenameEl.textContent = `${file.name}  (${formatSize(file.size)})`;
    fileInfo.style.display = "flex";
    analyzeBtn.disabled = false;
    hideError();
    resultsEl.style.display = "none";
  }

  function clearFile() {
    selectedFile = null;
    fileInput.value = "";
    fileInfo.style.display = "none";
    analyzeBtn.disabled = true;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  // ── Analyze ───────────────────────────────────────────────────
  analyzeBtn.addEventListener("click", async () => {
    if (!selectedFile) return;

    analyzeBtn.classList.add("btn--loading");
    analyzeBtn.disabled = true;
    hideError();
    resultsEl.style.display = "none";

    const form = new FormData();
    form.append("binary", selectedFile);

    try {
      const res = await fetch("/api/analyze", { method: "POST", body: form });
      const data = await res.json();

      if (!res.ok || data.error) {
        showError(data.error || `Server error (${res.status})`);
        return;
      }

      renderResults(data);
    } catch (err) {
      showError(`Network error: ${err.message}`);
    } finally {
      analyzeBtn.classList.remove("btn--loading");
      analyzeBtn.disabled = false;
    }
  });

  // ── Error helpers ─────────────────────────────────────────────
  function showError(msg) {
    errorMsg.textContent = msg;
    errorBanner.style.display = "block";
  }
  function hideError() { errorBanner.style.display = "none"; }

  // ── Render results ────────────────────────────────────────────
  function renderResults(data) {
    renderSummary(data);
    renderProtections(data.protections);
    renderAutoDetected(data.auto_detected || {});
    renderVulnerabilities(data.vulnerabilities);
    initTabs(data);

    resultsEl.style.display = "block";
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ── Summary ───────────────────────────────────────────────────
  function renderSummary(data) {
    const grid = document.getElementById("summary-grid");
    const items = [
      ["Filename", data.filename],
      ["Type", data.file_type],
      ["Architecture", data.protections.arch],
      ["Bits", data.protections.bits],
      ["Endianness", data.protections.endian],
      ["Stripped", data.protections.stripped ? "Yes" : "No"],
      ["Imports", data.imported_functions.length],
      ["Vulnerabilities", data.vulnerabilities.length],
    ];
    grid.innerHTML = items.map(([label, value]) => `
      <div class="summary-item">
        <div class="summary-item__label">${label}</div>
        <div class="summary-item__value">${escHtml(String(value))}</div>
      </div>
    `).join("");
  }

  // ── Protections ───────────────────────────────────────────────
  function renderProtections(prot) {
    const grid = document.getElementById("prot-grid");
    const items = [
      ["NX / DEP", prot.nx],
      ["PIE", prot.pie],
      ["RELRO", prot.relro],
      ["Stack Canary", prot.canary],
      ["FORTIFY", prot.fortify],
    ];
    grid.innerHTML = items.map(([name, val]) => {
      const cls = val.toLowerCase().replace(/\s+/g, "-");
      return `
        <div class="prot-chip prot-chip--${cls}">
          <span class="prot-chip__dot"></span>
          <span class="prot-chip__name">${name}</span>
          <span class="prot-chip__val">${val}</span>
        </div>`;
    }).join("");
  }

  // ── Auto-Detected Parameters ──────────────────────────────────
  function renderAutoDetected(ad) {
    let el = document.getElementById("auto-detected");
    if (!el) {
      el = document.createElement("div");
      el.id = "auto-detected";
      const vulnCard = document.getElementById("vulns-list").closest(".card");
      vulnCard.parentNode.insertBefore(el, vulnCard);
    }

    const items = [];
    if (ad.bof_offset != null)
      items.push(["BOF Offset", `${ad.bof_offset} bytes`, "cyclic + GDB x/gx $rsp"]);
    if (ad.fmt_offset != null)
      items.push(["Fmt Str Offset", `%${ad.fmt_offset}$p`, "sequential %N$p probe"]);
    if (ad.prompt)
      items.push(["Input Prompt", `"${ad.prompt}"`, "live detection"]);
    if (ad.prompts && ad.prompts.length && !ad.prompt)
      items.push(["Input Prompts", ad.prompts.slice(0,3).map(p => `"${p}"`).join(", "), "string analysis"]);
    if (ad.libc_path)
      items.push(["Libc Path", ad.libc_path, "ldd"]);
    if (ad.one_gadgets && ad.one_gadgets.length)
      items.push(["one_gadgets", ad.one_gadgets.map(g => g.addr).join(", "), "one_gadget tool"]);

    if (!items.length) { el.innerHTML = ""; return; }

    el.innerHTML = `
      <div class="card auto-card">
        <div class="card__title">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M10 6v4l2.5 2.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
          Auto-Detected Parameters
          <span class="badge badge--count">${items.length}</span>
        </div>
        <div class="auto-grid">
          ${items.map(([label, value, method]) => `
            <div class="auto-item">
              <div class="auto-item__check">✓</div>
              <div>
                <div class="auto-item__label">${label}</div>
                <div class="auto-item__value">${escHtml(String(value))}</div>
                <div class="auto-item__method">via ${escHtml(method)}</div>
              </div>
            </div>
          `).join("")}
        </div>
      </div>`;
  }

  // ── Vulnerabilities ───────────────────────────────────────────
  function renderVulnerabilities(vulns) {
    const list = document.getElementById("vulns-list");
    const count = document.getElementById("vuln-count");
    count.textContent = vulns.length;

    if (!vulns.length) {
      list.innerHTML = `<div class="no-vulns">No vulnerabilities detected. This binary may be well-hardened or require dynamic analysis.</div>`;
      return;
    }

    list.innerHTML = vulns.map(v => {
      const diffClass = difficultyClass(v.difficulty);
      const confPct = Math.round(v.confidence * 100);
      const confColor = confPct >= 70 ? "var(--accent-green)" : confPct >= 40 ? "var(--accent-amber)" : "var(--accent-red)";
      const recBadge = v.recommended ? '<span class="badge badge--rec">★ RECOMMENDED</span>' : '';
      const valBadge = v.validation_result ? `<span class="badge badge--val badge--val-${v.validation_result}">${validationLabel(v.validation_result)}</span>` : '';
      const confirmedBadge = (v.confirmed_offset != null || v.confirmed_fmt_offset != null) ? '<span class="badge badge--confirmed">CONFIRMED</span>' : '';

      return `
      <div class="vuln ${v.recommended ? 'vuln--recommended' : ''}" data-id="${v.id}">
        <div class="vuln__header" onclick="this.parentElement.classList.toggle('open')">
          <span class="vuln__chevron">▶</span>
          <span class="vuln__name">${escHtml(v.name)}</span>
          <div class="vuln__meta">
            ${recBadge}
            ${confirmedBadge}
            ${valBadge}
            <span class="badge badge--${diffClass}">${escHtml(v.difficulty)}</span>
            <div class="conf-bar" title="${confPct}% confidence">
              <div class="conf-bar__fill" style="width:${confPct}%;background:${confColor}"></div>
            </div>
          </div>
        </div>
        <div class="vuln__body">
          <p class="vuln__desc">${escHtml(v.description)}</p>

          ${v.recommended || v.confirmed_offset != null || v.confirmed_fmt_offset != null ? `
          <div class="checklist">
            <div class="checklist__title">Quick Steps</div>
            <div class="checklist__item done"><span>✅</span> Binary loaded</div>
            ${v.confirmed_offset != null ? `<div class="checklist__item done"><span>✅</span> Offset confirmed: <strong>${v.confirmed_offset}</strong></div>` : ''}
            ${v.confirmed_fmt_offset != null ? `<div class="checklist__item done"><span>✅</span> Fmt offset: <strong>%${v.confirmed_fmt_offset}$p</strong></div>` : ''}
            ${v.input_prompt ? `<div class="checklist__item done"><span>✅</span> Prompt: <strong>"${escHtml(v.input_prompt)}"</strong></div>` : ''}
            ${v.validation_result === 'shell' || v.validation_result === 'flag_leaked' ? `<div class="checklist__item done"><span>✅</span> <strong>Payload validated — WORKING!</strong></div>` :
              v.validation_result === 'crash' ? `<div class="checklist__item warn"><span>⚠️</span> Crashed — offset may need adjustment</div>` :
              `<div class="checklist__item pending"><span>▶</span> Run: python3 exploit.py</div>`}
          </div>
          ` : ''}

          <div class="vuln__tags">
            ${v.tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join("")}
          </div>

          <div class="vuln__section-title">Evidence</div>
          <ul class="vuln__evidence">
            ${v.evidence.map(e => `<li>${escHtml(e)}</li>`).join("")}
          </ul>

          ${v.exploit_steps && v.exploit_steps.length ? `
          <div class="vuln__section-title vuln__section-title--steps">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 3h10v10H3z" stroke="currentColor" stroke-width="1.2" rx="1.5"/><path d="M6 6l2 2-2 2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 10h2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
            Exploitation Steps
          </div>
          <ol class="vuln__steps">
            ${v.exploit_steps.map(s => `<li>${formatStep(s)}</li>`).join("")}
          </ol>
          ` : ""}

          ${v.payload_script ? `
          <div class="vuln__section-title vuln__section-title--payload">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 12h4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
            Payload Crafter
            ${v.validation_result === 'shell' || v.validation_result === 'flag_leaked' ? '<span class="val-inline val-ok">✅ VALIDATED</span>' :
              v.validation_result === 'crash' ? '<span class="val-inline val-warn">⚠ Needs tweak</span>' : ''}
          </div>
          <div class="payload-block" data-vuln-id="${v.id}">
            <div class="payload-block__toolbar">
              <span class="payload-block__lang">python</span>
              <div class="payload-block__remote">
                <input type="text" class="remote-host" placeholder="HOST" value="TARGET_HOST" />
                <input type="text" class="remote-port" placeholder="PORT" value="1337" />
                <button class="payload-block__toggle-remote" onclick="toggleRemote(this)" title="Switch to remote">
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/><path d="M2 8h12M8 2c-2 2-2 10 0 12M8 2c2 2 2 10 0 12" stroke="currentColor" stroke-width="1"/></svg>
                  Remote
                </button>
              </div>
              <button class="payload-block__copy" onclick="copyPayload(this)" title="Copy">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M11 5V3.5A1.5 1.5 0 009.5 2h-6A1.5 1.5 0 002 3.5v6A1.5 1.5 0 003.5 11H5" stroke="currentColor" stroke-width="1.2"/></svg>
                <span>Copy</span>
              </button>
              <button class="payload-block__download" onclick="downloadPayload(this)" title="Download .py">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2v8m0 0l-3-3m3 3l3-3M3 12h10" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                <span>.py</span>
              </button>
            </div>
            <pre class="payload-block__code"><code>${escHtml(v.payload_script)}</code></pre>
          </div>
          ` : ""}

          ${v.gdb_script ? `
          <div class="vuln__section-title vuln__section-title--gdb">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2" fill="currentColor"/><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/><path d="M8 2v2M8 12v2M2 8h2M12 8h2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
            GDB Debug Script
          </div>
          <div class="payload-block gdb-block" data-vuln-id="gdb-${v.id}">
            <div class="payload-block__toolbar">
              <span class="payload-block__lang" style="color:var(--accent-green)">gdb</span>
              <button class="payload-block__copy" onclick="copyPayload(this)" title="Copy">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M11 5V3.5A1.5 1.5 0 009.5 2h-6A1.5 1.5 0 002 3.5v6A1.5 1.5 0 003.5 11H5" stroke="currentColor" stroke-width="1.2"/></svg>
                <span>Copy</span>
              </button>
              <button class="payload-block__download" onclick="downloadGdb(this)" title="Download .gdb">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2v8m0 0l-3-3m3 3l3-3M3 12h10" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                <span>.gdb</span>
              </button>
            </div>
            <pre class="payload-block__code gdb-code"><code>${escHtml(v.gdb_script)}</code></pre>
          </div>
          ` : ""}

          <div class="vuln__section-title">Recommendations</div>
          <ul class="vuln__recs">
            ${v.recommendations.map(r => `<li>${escHtml(r)}</li>`).join("")}
          </ul>
        </div>
      </div>`;
    }).join("");
  }

  function difficultyClass(d) {
    return d.toLowerCase().replace(/[\s–]+/g, "-");
  }

  function validationLabel(status) {
    const map = {
      shell: "✅ Shell", flag_leaked: "✅ Flag!", clean_exit: "⚠ Clean exit",
      crash: "✗ Crash", abort: "✗ Abort", timeout: "⏱ Timeout",
      confirmed: "✅ Confirmed",
    };
    return map[status] || status;
  }

  // ── Tabs ──────────────────────────────────────────────────────
  function initTabs(data) {
    const tabBar = document.getElementById("detail-tabs");
    const content = document.getElementById("tab-content");

    const tabData = {
      imports: () => listToHtml(data.imported_functions),
      exports: () => listToHtml(data.exported_functions),
      sections: () => sectionsTable(data.sections),
      strings: () => listToHtml(data.raw_strings_sample),
    };

    // Activate first tab
    showTab("imports");

    tabBar.addEventListener("click", e => {
      const btn = e.target.closest(".tab");
      if (!btn) return;
      tabBar.querySelectorAll(".tab").forEach(t => t.classList.remove("tab--active"));
      btn.classList.add("tab--active");
      showTab(btn.dataset.tab);
    });

    function showTab(key) {
      content.innerHTML = tabData[key] ? tabData[key]() : "";
    }
  }

  function listToHtml(arr) {
    if (!arr || !arr.length) return `<p style="color:var(--text-muted)">None</p>`;
    return arr.map(s => `<div>${escHtml(s)}</div>`).join("");
  }

  function sectionsTable(sections) {
    if (!sections || !sections.length) return `<p style="color:var(--text-muted)">No sections</p>`;
    const flag = (v) => v
      ? `<span class="sec-flag sec-flag--on">✓</span>`
      : `<span class="sec-flag sec-flag--off">·</span>`;
    const rows = sections.map(s => `
      <tr>
        <td>${escHtml(s.name || "(empty)")}</td>
        <td>${escHtml(s.address)}</td>
        <td>${s.size.toLocaleString()}</td>
        <td>${flag(s.flags.exec)}</td>
        <td>${flag(s.flags.write)}</td>
        <td>${flag(s.flags.alloc)}</td>
      </tr>`).join("");
    return `<table class="sec-table">
      <thead><tr><th>Name</th><th>Addr</th><th>Size</th><th>X</th><th>W</th><th>A</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  // ── Utils ─────────────────────────────────────────────────────
  function formatStep(step) {
    // Split step into description and optional code block.
    // Steps with \n contain inline code after the first line.
    const parts = step.split("\n");
    const desc = escHtml(parts[0]);
    if (parts.length <= 1) return desc;
    const code = parts.slice(1).map(l => escHtml(l)).join("\n");
    return `${desc}<pre class="step-code"><code>${code}</code></pre>`;
  }

  function escHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }
})();

// ── Global payload helpers (called from onclick) ─────────────
function copyPayload(btn) {
  const block = btn.closest(".payload-block");
  const code = block.querySelector("code").textContent;
  navigator.clipboard.writeText(code).then(() => {
    const span = btn.querySelector("span");
    const orig = span.textContent;
    span.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => { span.textContent = orig; btn.classList.remove("copied"); }, 2000);
  });
}

function downloadPayload(btn) {
  const block = btn.closest(".payload-block");
  const code = block.querySelector("code").textContent;
  const vulnId = block.dataset.vulnId || "exploit";
  const blob = new Blob([code], { type: "text/x-python" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `exploit_vuln${vulnId}.py`;
  a.click();
  URL.revokeObjectURL(url);
}

function toggleRemote(btn) {
  const block = btn.closest(".payload-block");
  const code = block.querySelector("code");
  const hostInput = block.querySelector(".remote-host");
  const portInput = block.querySelector(".remote-port");
  const host = hostInput.value.trim() || "TARGET_HOST";
  const port = portInput.value.trim() || "1337";
  let text = code.textContent;

  if (text.includes("p = process(binary)")) {
    // Switch to remote
    text = text.replace(
      /# p = remote\('.*?', .*?\)\np = process\(binary\)/,
      `p = remote('${host}', ${port})\n# p = process(binary)`
    );
    // fallback simpler replace
    if (text.includes("p = process(binary)")) {
      text = text.replace("p = process(binary)", `p = remote('${host}', ${port})`);
    }
    btn.classList.add("active");
    btn.querySelector("span") && (btn.querySelector("span").textContent = "Local");
  } else {
    // Switch back to local
    text = text.replace(
      /p = remote\('.*?', .*?\)\n# p = process\(binary\)/,
      `# p = remote('${host}', ${port})\np = process(binary)`
    );
    if (!text.includes("p = process(binary)")) {
      text = text.replace(/p = remote\('.*?', .*?\)/, "p = process(binary)");
    }
    btn.classList.remove("active");
    btn.querySelector("span") && (btn.querySelector("span").textContent = "Remote");
  }

  code.textContent = text;
}

function downloadGdb(btn) {
  const block = btn.closest(".payload-block");
  const code = block.querySelector("code").textContent;
  const blob = new Blob([code], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "debug.gdb";
  a.click();
  URL.revokeObjectURL(url);
}
