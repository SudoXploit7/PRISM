/* =======================================================================
   PRISM - Dashboard JavaScript
   WebSocket handlers, panel renderers, UI orchestration
   ======================================================================= */

const socket = io();
let scanComplete = false;

// ── Page Init: Restore scan state on refresh ────────────────────────────
document.addEventListener('DOMContentLoaded', async function() {
    try {
        const res = await fetch('/api/results').then(r => r.json());
        if (res && res.scan_status === 'complete') {
            scanComplete = true;
            updateStatus('connected', 'Assessment Complete');
            document.getElementById('btn-export').style.display = '';

            const btn = document.getElementById('btn-start-scan');
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<svg style="width:12px;height:12px;display:inline;vertical-align:middle;margin-right:5px" viewBox="0 0 16 16" fill="currentColor"><polygon points="4,2 14,8 4,14"/></svg> Launch Assessment';
            }

            // Pre-load all sections including new offensive ops
            renderOverview(res);
            await Promise.all([
                loadSectionData('shadow-admins'),
                loadSectionData('privesc'),
                loadSectionData('network'),
                loadSectionData('credentials'),
                loadSectionData('ghosts'),
                loadSectionData('entropy'),
                loadSectionData('kill-chain'),
                loadSectionData('blast-radius'),
                loadSectionData('narrative'),
                loadSectionData('fingerprints'),
                loadSectionData('mitre'),
                loadSectionData('remediation'),
                loadSectionData('mvc'),
                loadSectionData('ransomware'),
                loadSectionData('supply-chain'),
                loadSectionData('golden-saml'),
            ]);

            // Populate breach simulator identity dropdown
            populateBreachSelector();

            showToast('Previous assessment results loaded. Click Launch Assessment to run a fresh scan.', 'info');
        }
    } catch(e) {
        // No previous scan or server not ready - that's fine
        console.log('No previous scan state to restore:', e.message);
    }
});

let graphNetwork = null;

// ── Section Navigation ──────────────────────────────────────────────────
function showSection(id) {
    document.querySelectorAll('.section-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const panel = document.getElementById('section-' + id);
    if (panel) panel.classList.add('active');
    const nav = document.querySelector(`.nav-item[data-section="${id}"]`);
    if (nav) nav.classList.add('active');

    // Attack graph needs explicit render when its panel becomes visible
    if (scanComplete) {
        if (id === 'attack-graph') {
            renderAttackGraph();
        } else {
            loadSectionData(id);
        }
    }
}

// ── Credential Modal ─────────────────────────────────────────────────────
function openCredentialModal() {
    document.getElementById('credential-modal').classList.add('show');
    document.getElementById('modal-error').style.display = 'none';
    document.getElementById('input-access-key').focus();
}

function closeCredentialModal() {
    document.getElementById('credential-modal').classList.remove('show');
}

// ── Start Scan ───────────────────────────────────────────────────────────
function startScan() {
    const accessKey = document.getElementById('input-access-key').value.trim();
    const secretKey = document.getElementById('input-secret-key').value.trim();
    const region    = document.getElementById('input-region').value;

    if (!accessKey || !secretKey) {
        const err = document.getElementById('modal-error');
        err.textContent = 'Access Key and Secret Key are required.';
        err.style.display = 'block';
        return;
    }

    closeCredentialModal();
    showSection('scan');

    document.getElementById('input-access-key').value = '';
    document.getElementById('input-secret-key').value = '';

    const btn = document.getElementById('btn-start-scan');
    btn.disabled = true;
    btn.innerHTML = `<svg style="width:12px;height:12px;display:inline;vertical-align:middle;margin-right:5px;animation:spin 1s linear infinite" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2a7 7 0 100 14A7 7 0 009 2z" opacity="0.3"/><path d="M9 2a7 7 0 017 7"/></svg> Scanning...`;

    updateStatus('scanning', 'Scanning...');
    document.getElementById('terminal-output').innerHTML = '';
    
    // Reset progress UI to prevent backward jump
    document.getElementById('scan-progress-bar').style.width = '0%';
    document.getElementById('scan-percent').textContent = '0%';
    document.getElementById('scan-phase').textContent = 'Initializing...';

    socket.emit('scan_start', { access_key: accessKey, secret_key: secretKey, region });
    showToast('Assessment started. Monitor the terminal for live progress.', 'info');
}

// ── Socket Events ────────────────────────────────────────────────────────
socket.on('scan_progress', function(data) {
    const bar   = document.getElementById('scan-progress-bar');
    const phase = document.getElementById('scan-phase');
    const pct   = document.getElementById('scan-percent');
    bar.style.width = (data.progress || 0) + '%';
    phase.textContent = data.phase || '';
    pct.textContent   = (data.progress || 0) + '%';
});

socket.on('scan_log', function(data) {
    const terminal = document.getElementById('terminal-output');
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const msg = data.message || '';
    let cls = 'info';
    if (msg.includes('complete') || msg.includes('Assessment complete') || msg.includes('purged')) cls = 'success';
    else if (msg.includes('Error') || msg.includes('failed') || msg.includes('ERROR')) cls = 'error';
    else if (msg.includes('Identified') || msg.includes('Mapped') || msg.includes('Detected')) cls = 'highlight';

    line.innerHTML = `<span class="timestamp">[${esc(data.timestamp || '')}]</span> <span class="${cls}">${esc(msg)}</span>`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
});

socket.on('scan_complete', function() {
    scanComplete = true;

    const btn = document.getElementById('btn-start-scan');
    btn.disabled = false;
    btn.innerHTML = `<svg style="width:13px;height:13px;display:inline;vertical-align:middle;margin-right:5px;" viewBox="0 0 16 16" fill="currentColor"><polygon points="4,2 14,8 4,14"/></svg> Launch Assessment`;

    document.getElementById('btn-export').style.display = '';
    updateStatus('connected', 'Assessment Complete');
    showToast('Threat assessment complete. All vectors mapped.', 'success');
    loadAllData();
    // Stay on scan section briefly so user sees 100%, then switch to overview
    setTimeout(() => showSection('overview'), 800);
});

socket.on('scan_error', function(data) {
    const btn = document.getElementById('btn-start-scan');
    btn.disabled = false;
    btn.innerHTML = `<svg style="width:13px;height:13px;display:inline;vertical-align:middle;margin-right:5px;" viewBox="0 0 16 16" fill="currentColor"><polygon points="4,2 14,8 4,14"/></svg> Launch Assessment`;
    updateStatus('error', 'Error');
    showToast('Assessment error: ' + (data.message || 'Unknown error'), 'error');

    const terminal = document.getElementById('terminal-output');
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.innerHTML = `<span class="error">ERROR: ${esc(data.message || '')}</span>`;
    terminal.appendChild(line);
});

// ── Status Indicator ─────────────────────────────────────────────────────
function updateStatus(state, text) {
    document.getElementById('status-dot').className = 'status-dot ' + state;
    document.getElementById('status-text').textContent = text;
}

// ── Data Loading ─────────────────────────────────────────────────────────
async function loadAllData() {
    try {
        const results = await fetch('/api/results').then(r => r.json());
        renderOverview(results);

        // Pre-fetch all section data in parallel (graph loads on demand)
        await Promise.all([
            loadSectionData('shadow-admins'),
            loadSectionData('privesc'),
            loadSectionData('network'),
            loadSectionData('credentials'),
            loadSectionData('ghosts'),
            loadSectionData('entropy'),
            loadSectionData('kill-chain'),
            loadSectionData('blast-radius'),
            loadSectionData('narrative'),
            loadSectionData('fingerprints'),
            loadSectionData('mitre'),
            loadSectionData('remediation'),
            loadSectionData('mvc'),
            loadSectionData('ransomware'),
            loadSectionData('supply-chain'),
            loadSectionData('golden-saml'),
        ]);
        populateBreachSelector();
    } catch (e) {
        showToast('Failed to load results: ' + e.message, 'error');
    }
}

async function loadSectionData(section) {
    try {
        switch (section) {
            case 'attack-graph':
                await renderAttackGraph();
                break;
            case 'mvc':
                await renderMVC();
                break;
            case 'assumed-breach':
                await populateBreachSelector();
                // If an identity is already selected, re-run simulation
                const sel = document.getElementById('breach-identity-select');
                if (sel && sel.value) await loadBreachSim();
                break;
            case 'ransomware':
                await renderRansomware();
                break;
            case 'supply-chain':
                await renderSupplyChain();
                break;
            case 'golden-saml':
                await renderGoldenSAML();
                break;
            case 'shadow-admins': {
                const d = await fetch('/api/shadow-admins').then(r => r.json());
                renderShadowAdmins(d);
                break;
            }
            case 'privesc': {
                const d = await fetch('/api/privesc-paths').then(r => r.json());
                renderPrivesc(d);
                break;
            }
            case 'network': {
                const d = await fetch('/api/network-exposure').then(r => r.json());
                renderFindings(d, 'network-list');
                break;
            }
            case 'credentials': {
                const d = await fetch('/api/credential-health').then(r => r.json());
                renderCredentials(d);
                break;
            }
            case 'ghosts': {
                const d = await fetch('/api/ghost-identities').then(r => r.json());
                renderGhosts(d);
                break;
            }
            case 'entropy': {
                const d = await fetch('/api/permission-entropy').then(r => r.json());
                renderEntropy(d);
                break;
            }
            case 'kill-chain': {
                const d = await fetch('/api/kill-chain').then(r => r.json());
                renderKillChain(d);
                break;
            }
            case 'blast-radius': {
                const d = await fetch('/api/blast-radius').then(r => r.json());
                renderBlastRadius(d);
                break;
            }
            case 'narrative': {
                const d = await fetch('/api/attack-narrative').then(r => r.json());
                renderNarrative(d);
                break;
            }
            case 'fingerprints': {
                const d = await fetch('/api/policy-fingerprints').then(r => r.json());
                renderFingerprints(d);
                break;
            }
            case 'mitre': {
                const d = await fetch('/api/mitre-heatmap').then(r => r.json());
                renderMitre(d);
                break;
            }
            case 'remediation': {
                const d = await fetch('/api/report-data').then(r => r.json());
                renderRemediation(d.remediation_plan || []);
                break;
            }
        }
    } catch (e) {
        console.error('Failed to load section ' + section + ':', e);
    }
}

// ── Overview ──────────────────────────────────────────────────────────────
function renderOverview(data) {
    document.getElementById('overview-empty').style.display = 'none';
    document.getElementById('overview-content').style.display = '';

    const risk  = data.risk_summary || {};
    const score = risk.overall_score || 0;
    const rating = risk.rating || 'N/A';

    const circ   = 2 * Math.PI * 80;
    const offset = circ - (score / 100) * circ;
    const fill   = document.getElementById('risk-gauge-fill');
    const gaugeColor = score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 40 ? '#3b82f6' : '#10b981';
    fill.style.stroke = gaugeColor;
    fill.style.strokeDasharray  = circ;
    fill.style.strokeDashoffset = offset;

    const scoreEl  = document.getElementById('risk-score-value');
    const ratingEl = document.getElementById('risk-rating-label');
    scoreEl.style.color = gaugeColor;
    animateCounter(scoreEl, 0, score, 900);
    ratingEl.textContent = rating;

    const sev    = risk.severity_counts || {};
    const maxSev = Math.max(sev.CRITICAL || 0, sev.HIGH || 0, sev.MEDIUM || 0, sev.LOW || 0, 1);
    const sevColors = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#3b82f6', LOW: '#10b981' };
    document.getElementById('severity-bars').innerHTML = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => {
        const count = sev[s] || 0;
        const pct   = (count / maxSev) * 100;
        return `<div class="entropy-bar">
            <div class="bar-label">${s}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${sevColors[s]}"></div></div>
            <span style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);min-width:28px;text-align:right;">${count}</span>
        </div>`;
    }).join('');

    const kpis = [
        { label: 'IAM Users',        value: (data.users || []).length,                    cls: '' },
        { label: 'IAM Roles',        value: (data.roles || []).length,                    cls: '' },
        { label: 'Shadow Admins',    value: (data.shadow_admin_findings || []).length,    cls: 'critical' },
        { label: 'Privesc Paths',    value: (data.privesc_findings || []).length,         cls: 'high' },
        { label: 'Ghost Identities', value: (data.ghost_identities || []).length,         cls: 'critical' },
        { label: 'Network Exposures',value: (data.network_findings || []).length,         cls: 'high' },
        { label: 'Credential Issues',value: (data.credential_findings || []).length,      cls: 'medium' },
        { label: 'Remediation Items',value: (data.remediation_plan || []).length,         cls: 'green' },
    ];
    document.getElementById('kpi-grid').innerHTML = kpis.map(k => `
        <div class="kpi-card">
            <div class="kpi-label">${k.label}</div>
            <div class="kpi-value ${k.cls}">${k.value}</div>
        </div>`).join('');

    setBadge('badge-shadow', (data.shadow_admin_findings || []).length);
    setBadge('badge-privesc', (data.privesc_findings || []).length);
    setBadge('badge-ghosts',  (data.ghost_identities || []).length);
}

function animateCounter(el, from, to, duration) {
    const start = performance.now();
    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        el.textContent = Math.floor(from + (to - from) * progress);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ── Attack Graph ──────────────────────────────────────────────────────────
async function renderAttackGraph() {
    // Guard: wait for vis to load (handles async CDN fallback loading)
    if (typeof vis === 'undefined') {
        console.warn('vis not loaded yet, retrying in 500ms...');
        setTimeout(renderAttackGraph, 500);
        return;
    }
    const container = document.getElementById('attack-graph-container');
    if (!container) return;

    // If network already initialized, just re-fit
    if (graphNetwork) {
        graphNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        return;
    }

    try {
        const data = await fetch('/api/graph').then(r => r.json());

        if (!data.nodes || data.nodes.length === 0) {
            container.innerHTML = `<div class="empty-state" style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;">
                <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.2" width="48" height="48" opacity="0.3">
                    <circle cx="24" cy="12" r="5"/><circle cx="10" cy="36" r="5"/><circle cx="38" cy="36" r="5"/>
                    <line x1="24" y1="17" x2="10" y2="31"/><line x1="24" y1="17" x2="38" y2="31"/>
                </svg>
                <div style="margin-top:12px;font-size:13px;color:var(--text-muted);">No IAM relationships found.<br>Ensure credentials have iam:List* and iam:Get* permissions.</div>
            </div>`;
            return;
        }

        const colorMap  = { user:'#3b82f6', role:'#8b5cf6', service:'#06b6d4', external:'#f59e0b', admin_target:'#ef4444', policy:'#10b981', internet:'#ef4444' };
        const riskBorder = { critical:'#ef4444', high:'#f59e0b', medium:'#3b82f6', low:'#475569' };
        const shapeMap  = { admin_target:'diamond', service:'triangleDown', policy:'square', internet:'star', user:'dot', role:'dot' };

        const nodes = new vis.DataSet(data.nodes.map(n => ({
            id: n.id,
            label: n.label || n.id,
            title: `<div style="background:#111827;color:#e2e8f0;padding:8px 12px;border-radius:6px;font-size:12px;border:1px solid #1f2937;max-width:220px">
                <b>${n.id}</b><br>Type: ${n.type || 'unknown'}<br>Risk: ${(n.risk||'').toUpperCase()}
                ${n.is_admin ? '<br><span style="color:#ef4444;font-weight:600">Administrator</span>' : ''}
                ${n.is_shadow_admin ? '<br><span style="color:#f59e0b;font-weight:600">Shadow Admin</span>' : ''}
                ${n.actions ? `<br>Actions: ${n.actions}` : ''}
            </div>`,
            color: {
                background: colorMap[n.type] || '#3b82f6',
                border:     riskBorder[n.risk] || '#475569',
                highlight:  { background: '#fff', border: riskBorder[n.risk] || '#475569' },
                hover:      { background: colorMap[n.type] || '#3b82f6', border: '#ffffff' },
            },
            borderWidth:      n.risk === 'critical' ? 3 : 1.5,
            borderWidthSelected: 4,
            font:  { color: '#e2e8f0', size: 11, face: 'Inter, sans-serif' },
            shape: shapeMap[n.type] || 'dot',
            size:  n.risk === 'critical' ? 22 : n.is_admin ? 18 : 13,
            shadow: n.risk === 'critical' ? { enabled: true, color: 'rgba(239,68,68,0.4)', size: 12, x: 0, y: 0 } : false,
        })));

        const edges = new vis.DataSet(data.edges.map(e => ({
            from:   e.from,
            to:     e.to,
            title:  `<div style="background:#111827;color:#e2e8f0;padding:6px 10px;border-radius:4px;font-size:11px;border:1px solid #1f2937">${e.type || e.label || ''}</div>`,
            color:  { color: e.is_attack ? '#ef4444' : '#334155', opacity: e.is_attack ? 0.9 : 0.5, highlight: '#ffffff' },
            arrows: { to: { enabled: true, scaleFactor: 0.8 } },
            dashes: !e.is_attack,
            width:  e.is_attack ? 2.5 : 1,
            smooth: { type: 'curvedCW', roundness: 0.15 },
            label:  e.is_attack ? (e.vector || e.type || '') : '',
            font:   { color: '#64748b', size: 9, align: 'middle' },
        })));

        const options = {
            physics: {
                enabled: true,
                solver: 'barnesHut',
                barnesHut: { gravitationalConstant: -4000, centralGravity: 0.3, springLength: 120, damping: 0.12 },
                stabilization: { iterations: 150, updateInterval: 25 },
            },
            interaction: {
                hover: true,
                tooltipDelay: 150,
                navigationButtons: true,
                keyboard: true,
                zoomView: true,
            },
            layout: { randomSeed: 42 },
        };

        graphNetwork = new vis.Network(container, { nodes, edges }, options);

        graphNetwork.on('stabilizationIterationsDone', function() {
            graphNetwork.setOptions({ physics: { enabled: false } });
            graphNetwork.fit({ animation: { duration: 600, easingFunction: 'easeOutQuad' } });
        });

    } catch (e) {
        console.error('Attack graph render failed:', e);
        container.innerHTML = `<div class="empty-state" style="height:100%;display:flex;align-items:center;justify-content:center;">
            <div style="font-size:12px;color:var(--accent-red);">Graph render failed: ${esc(e.message)}</div>
        </div>`;
    }
}

// ── Shadow Admins ─────────────────────────────────────────────────────────
function renderShadowAdmins(data) {
    const el = document.getElementById('shadow-admin-list');
    if (!data || data.length === 0) { el.innerHTML = emptyMsg('No shadow admin paths identified.', 'shadow'); return; }
    el.innerHTML = `<table class="data-table">
        <thead><tr><th>Severity</th><th>CVSS</th><th>Identity</th><th>Escalation Vectors</th><th>Impact</th></tr></thead>
        <tbody>${data.map(f => `<tr>
            <td>${severityBadge(f.severity)}</td>
            <td class="mono" style="color:${cvssColor(f.cvss_score)}">${f.cvss_score ? f.cvss_score.toFixed(1) : 'N/A'}</td>
            <td class="mono">${esc(f.identity)}</td>
            <td>${(f.escalation_vectors||[]).map(v=>`<span class="tag">${esc(v)}</span>`).join(' ')}</td>
            <td style="font-size:11px;color:var(--text-secondary)">${esc((f.impact||f.description||'').substring(0,100))}</td>
        </tr>`).join('')}</tbody>
    </table>`;
}

// ── Privesc ───────────────────────────────────────────────────────────────
function renderPrivesc(data) {
    const findings = data.findings || [];
    const el = document.getElementById('privesc-list');
    if (findings.length === 0) { el.innerHTML = emptyMsg('No privilege escalation paths found.', 'privesc'); return; }
    el.innerHTML = `<table class="data-table">
        <thead><tr><th>Severity</th><th>CVSS</th><th>Identity</th><th>Vector</th><th>Category</th><th>MITRE</th></tr></thead>
        <tbody>${findings.map(f => `<tr>
            <td>${severityBadge(f.severity)}</td>
            <td class="mono" style="color:${cvssColor(f.cvss_score)}">${f.cvss_score ? f.cvss_score.toFixed(1) : 'N/A'}</td>
            <td class="mono">${esc(f.identity)}</td>
            <td><span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono)">${esc(f.vector_id)}</span> <strong>${esc(f.vector_name)}</strong></td>
            <td>${esc(f.category)}</td>
            <td class="mono" style="color:var(--accent-cyan)">${esc(f.mitre)}</td>
        </tr>`).join('')}</tbody>
    </table>`;
}

// ── Generic Findings Table ────────────────────────────────────────────────
function renderFindings(data, containerId) {
    const el = document.getElementById(containerId);
    if (!data || data.length === 0) { el.innerHTML = emptyMsg('No findings in this category.', 'shield'); return; }
    el.innerHTML = `<table class="data-table">
        <thead><tr><th>Severity</th><th>CVSS</th><th>Type</th><th>Resource</th><th>Description</th></tr></thead>
        <tbody>${data.map(f => `<tr>
            <td>${severityBadge(f.severity)}</td>
            <td class="mono" style="color:${cvssColor(f.cvss_score)}">${f.cvss_score ? Number(f.cvss_score).toFixed(1) : 'N/A'}</td>
            <td class="mono">${esc(f.type || '')}</td>
            <td class="mono">${esc((f.resource || f.identity || '').substring(0,30))}</td>
            <td style="font-size:11px;">${esc((f.description||'').substring(0,120))}</td>
        </tr>`).join('')}</tbody>
    </table>`;
}

// ── Credentials ───────────────────────────────────────────────────────────
function renderCredentials(data) {
    const stats = data.stats || {};
    document.getElementById('cred-stats').innerHTML = [
        { label: 'Total Keys',    value: stats.total_keys || 0 },
        { label: 'Critical Age',  value: stats.critical_keys || 0 },
        { label: 'No MFA',        value: stats.users_without_mfa || 0 },
    ].map(s => `<div class="cred-stat"><div class="stat-value">${s.value}</div><div class="stat-label">${s.label}</div></div>`).join('');
    renderFindings(data.findings || [], 'credential-list');
}

// ── Ghost Identities ──────────────────────────────────────────────────────
function renderGhosts(data) {
    const el = document.getElementById('ghost-list');
    if (!data || data.length === 0) { el.innerHTML = emptyMsg('No ghost identities detected.', 'ghost'); return; }
    el.innerHTML = data.map(g => {
        const scoreColor = g.ghost_score >= 70 ? '#ef4444' : g.ghost_score >= 40 ? '#f59e0b' : '#3b82f6';
        return `<div class="ghost-card">
            <div class="ghost-header">
                <div class="ghost-name">
                    ${severityBadge(g.severity)} <span class="mono">${esc(g.identity)}</span>
                    ${g.is_shadow_admin ? '<span class="tag" style="background:rgba(239,68,68,0.15);color:#ef4444;border-color:rgba(239,68,68,0.3);margin-left:6px">Shadow Admin</span>' : ''}
                </div>
                <div style="font-family:var(--font-mono);font-size:22px;font-weight:700;color:${scoreColor}">${g.ghost_score}<span style="font-size:12px;font-weight:400;color:var(--text-muted)">/100</span></div>
            </div>
            <div class="ghost-meta">
                <span>Dormant: ${g.days_dormant} days</span>
                <span>Last used: ${esc(g.last_used || 'Never')}</span>
                <span>Escalation vectors: ${(g.escalation_vectors||[]).length}</span>
            </div>
            <div style="margin-top:10px;font-size:12px;color:var(--text-secondary)">${esc(g.description||'')}</div>
        </div>`;
    }).join('');
}

// ── Entropy ───────────────────────────────────────────────────────────────
function renderEntropy(data) {
    const el = document.getElementById('entropy-content');
    if (!data || (data.entropy_score === undefined && data.entropy_score !== 0)) {
        el.innerHTML = emptyMsg('No entropy data available.', 'wave');
        return;
    }
    const score = data.entropy_score || 0;
    const scoreColor = score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 40 ? '#3b82f6' : '#10b981';
    const circ   = 2 * Math.PI * 80;
    const offset = circ - (score / 100) * circ;
    const serviceEntropy = data.per_service_entropy || {};
    const maxE = Math.max(...Object.values(serviceEntropy).map(Number), 0.01);

    el.innerHTML = `
        <div class="entropy-gauge-wrapper">
            <div class="risk-gauge">
                <svg viewBox="0 0 200 200">
                    <circle class="gauge-bg" cx="100" cy="100" r="80"/>
                    <circle class="gauge-fill" cx="100" cy="100" r="80"
                        style="stroke:${scoreColor};stroke-dasharray:${circ};stroke-dashoffset:${offset}"/>
                </svg>
                <div class="gauge-center">
                    <div class="gauge-score" style="color:${scoreColor}">${score}</div>
                    <div class="gauge-label">${esc(data.chaos_level || 'N/A')}</div>
                </div>
            </div>
            <div style="text-align:center;margin-top:14px;">
                <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Largest Chaos Source</div>
                <div style="font-size:15px;font-weight:600;color:var(--accent-cyan);font-family:var(--font-mono);margin-top:4px">${esc(data.biggest_chaos_source || 'N/A')}</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Removing this identity reduces entropy by ${data.entropy_reduction_if_removed ? data.entropy_reduction_if_removed.toFixed(2) : 'N/A'}</div>
            </div>
        </div>
        <div class="entropy-details">
            <div style="font-size:13px;font-weight:600;color:var(--text-heading);margin-bottom:14px;">Per-Service Entropy Contribution</div>
            ${Object.entries(serviceEntropy).slice(0, 14).map(([svc, val]) => `
                <div class="entropy-bar">
                    <div class="bar-label">${svc}</div>
                    <div class="bar-track"><div class="bar-fill" style="width:${(Number(val)/maxE)*100}%"></div></div>
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);min-width:44px;text-align:right">${Number(val).toFixed(3)}</span>
                </div>`).join('')}
        </div>`;
}

// ── Kill Chain ────────────────────────────────────────────────────────────
function renderKillChain(data) {
    const tl = document.getElementById('kill-chain-timeline');
    if (!data || !data.phases || data.phases.length === 0) {
        tl.innerHTML = emptyMsg('No kill chain data available.', 'clock');
        return;
    }
    document.getElementById('kc-summary').textContent =
        `Total attack duration: ~${data.total_attack_duration_minutes} minutes  |  ` +
        `Blind spots: ${(data.blind_spots||[]).join(', ') || 'None'}  |  ` +
        `Earliest detection at: ${data.earliest_detection_at_phase || 'Not detected'}`;

    tl.innerHTML = data.phases.map((p, i) => {
        const isBlind = !p.logged_by_cloudtrail;
        const detPct  = Math.round((p.detection_probability || 0) * 100);
        return `<div class="kc-phase ${isBlind ? 'blind' : 'detected'}">
            <div class="kc-phase-header">
                <div class="kc-phase-name">
                    <span class="kc-step">${i+1}</span>
                    ${esc(p.phase)}
                </div>
                <div class="kc-phase-time">+${p.duration_minutes} min</div>
            </div>
            <div class="kc-phase-desc">${esc(p.description || '')}</div>
            <div class="kc-detection ${isBlind ? 'blind' : ''}">
                ${isBlind ? '[BLIND SPOT] Not logged' : '[LOGGED] Visible in CloudTrail'}
                &nbsp;&bull;&nbsp; Detection probability: ${detPct}%
                ${p.mitre_technique ? ` &nbsp;&bull;&nbsp; <span class="mono">${esc(p.mitre_technique)}</span>` : ''}
            </div>
        </div>`;
    }).join('');
}

// ── Blast Radius ──────────────────────────────────────────────────────────
function renderBlastRadius(data) {
    const el = document.getElementById('blast-list');
    if (!data || data.length === 0) { el.innerHTML = emptyMsg('No blast radius data.', 'blast'); return; }
    el.innerHTML = data.slice(0, 10).map(b => {
        const dims = b.dimensions || {};
        const sc   = b.overall_blast_score || 0;
        const scoreColor = sc >= 500 ? '#ef4444' : sc >= 200 ? '#f59e0b' : sc >= 50 ? '#3b82f6' : '#10b981';
        const dimLabel = { data:'Data', compute:'Compute', identity:'Identity', billing:'Billing', logging:'Logging' };
        return `<div class="blast-card">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
                <div>
                    <div style="font-weight:600;font-size:15px;color:var(--text-heading);font-family:var(--font-mono)">${esc(b.identity)}</div>
                    ${b.has_wildcard ? '<div style="font-size:11px;color:#ef4444;margin-top:2px">Full Administrator (*)</div>' : ''}
                </div>
                <div style="text-align:right;">
                    <div style="font-family:var(--font-mono);font-size:32px;font-weight:800;color:${scoreColor};line-height:1">${sc}</div>
                    <div style="font-size:10px;color:var(--text-muted)">Blast Score</div>
                </div>
            </div>
            <div class="blast-dims">
                ${['data','compute','identity','billing','logging'].map(d => {
                    const dim = dims[d] || {};
                    const ds  = dim.score || 0;
                    const dc  = ds >= 200 ? '#ef4444' : ds >= 100 ? '#f59e0b' : ds >= 30 ? '#3b82f6' : '#475569';
                    return `<div class="blast-dim">
                        <div class="blast-dim-label">${dimLabel[d]}</div>
                        <div class="blast-dim-value" style="color:${dc}">${ds}</div>
                    </div>`;
                }).join('')}
            </div>
            ${b.worst_case_scenario ? `<div style="margin-top:12px;font-size:12px;color:var(--text-secondary);line-height:1.6;border-top:1px solid var(--border-primary);padding-top:12px;">${esc(b.worst_case_scenario)}</div>` : ''}
        </div>`;
    }).join('');
}

// ── Narrative ─────────────────────────────────────────────────────────────
function renderNarrative(data) {
    const el = document.getElementById('narrative-content');
    if (!data || !data.executive_narrative) { el.innerHTML = emptyMsg('No attack narrative generated.', 'doc'); return; }
    const stepsHtml = data.attack_steps && data.attack_steps.length ? `
        <div style="margin-top:20px;">
            <div class="narrative-label">Attack Steps</div>
            <table class="data-table"><thead><tr><th>Step</th><th>Phase</th><th>Time</th><th>Action</th><th>MITRE</th></tr></thead>
            <tbody>${data.attack_steps.map(s => `<tr>
                <td class="mono">${s.step}</td>
                <td>${esc(s.phase)}</td>
                <td class="mono">${esc(s.time_offset || '')}</td>
                <td>${esc(s.action || '')}</td>
                <td class="mono" style="color:var(--accent-cyan)">${esc(s.mitre || '')}</td>
            </tr>`).join('')}</tbody></table>
        </div>` : '';

    el.innerHTML = `
        <div class="narrative-block">
            <div class="narrative-label">Executive Summary</div>
            ${data.executive_narrative.split('\n\n').map(p => `<p style="margin-bottom:12px;line-height:1.7;">${esc(p)}</p>`).join('')}
        </div>
        <div class="narrative-block">
            <div class="narrative-label">Technical Narrative</div>
            <p style="line-height:1.7;">${esc(data.technical_narrative || '')}</p>
        </div>
        <div style="display:flex;gap:16px;margin-top:16px;">
            <div class="cred-stat" style="flex:1;"><div class="stat-value" style="color:var(--accent-cyan)">${data.time_to_admin_minutes || 'N/A'} min</div><div class="stat-label">Time to Admin</div></div>
            <div class="cred-stat" style="flex:1;"><div class="stat-value" style="color:var(--accent-red)">${esc(data.detection_likelihood || 'N/A')}</div><div class="stat-label">Detection Likelihood</div></div>
            <div class="cred-stat" style="flex:1;"><div class="stat-value" style="color:var(--accent-orange)">${esc(data.initial_access_vector || 'N/A')}</div><div class="stat-label">Initial Vector</div></div>
        </div>
        ${stepsHtml}`;
}

// ── Fingerprints ──────────────────────────────────────────────────────────
function renderFingerprints(data) {
    const fps = data.fingerprints || [];
    const el  = document.getElementById('fingerprint-list');
    if (fps.length === 0) { el.innerHTML = emptyMsg('No dangerous policy fingerprints detected.', 'fingerprint'); return; }

    el.innerHTML = `<div style="margin-bottom:16px;font-size:13px;color:var(--text-secondary);">
        Scanned <strong>${data.total_policies_scanned || 0}</strong> identities &bull;
        Found <strong style="color:var(--accent-red)">${data.dangerous_fingerprints_found || 0}</strong> dangerous fingerprint matches
    </div>` + fps.map(f => {
        const scoreColor = f.risk_score >= 80 ? '#ef4444' : f.risk_score >= 60 ? '#f59e0b' : '#3b82f6';
        return `<div class="fingerprint-card">
            <div class="fingerprint-score" style="color:${scoreColor}">${f.risk_score}</div>
            <div class="fingerprint-info">
                <div class="fingerprint-name">${esc(f.policy_name || f.identity || '')}</div>
                <div class="fingerprint-pattern">Pattern: <strong>${esc(f.matched_pattern)}</strong> &nbsp;&bull;&nbsp; ${esc(f.threat_category)}</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${esc(f.description || '')}</div>
            </div>
            ${severityBadge(f.risk_score >= 90 ? 'CRITICAL' : f.risk_score >= 70 ? 'HIGH' : 'MEDIUM')}
        </div>`;
    }).join('');
}

// ── MITRE Heatmap ─────────────────────────────────────────────────────────
function renderMitre(data) {
    const el = document.getElementById('mitre-grid');
    if (!data || !data.heatmap) { el.innerHTML = emptyMsg('No MITRE ATT&CK data available.', 'target'); return; }

    const order = data.tactics_order || [];
    el.innerHTML = order.map(tactic => {
        const techniques = data.heatmap[tactic] || [];
        return `<div class="mitre-tactic">
            <div class="mitre-tactic-name">${esc(tactic)}</div>
            ${techniques.map(t => {
                const hitClass = t.hit ? `hit ${(t.severity||'MEDIUM').toLowerCase()}` : 'nohit';
                return `<div class="mitre-technique ${hitClass}" title="${esc(t.id)}: ${esc(t.name)}">
                    <span style="font-family:var(--font-mono);font-size:9px;opacity:0.8">${esc(t.id)}</span>
                    <span style="display:block;font-size:10px;margin-top:1px">${esc(t.name)}</span>
                </div>`;
            }).join('')}
        </div>`;
    }).join('');
}

// ── Remediation ───────────────────────────────────────────────────────────
function renderRemediation(data) {
    const el = document.getElementById('remediation-list');
    if (!data || data.length === 0) { el.innerHTML = emptyMsg('No remediation items.', 'shield'); return; }
    el.innerHTML = data.slice(0, 30).map(r => `
        <div class="remediation-item">
            <div class="remediation-priority ${(r.priority||'').toLowerCase()}">${esc(r.priority || 'P3')}</div>
            <div class="remediation-details">
                <div class="remediation-summary">${severityBadge(r.severity)} ${esc(r.summary || '')}</div>
                <div style="font-size:12px;color:var(--text-muted);margin-top:4px">${esc(r.detailed_remediation || '')}</div>
                ${r.cli_command ? `<div class="remediation-cmd">${esc(r.cli_command)}</div>` : ''}
            </div>
        </div>`).join('');
}


// ── No-scan notice helper ─────────────────────────────────────────────────
function noScanMsg(featureName) {
    return `<div class="rescan-notice">
        <svg viewBox="0 0 48 48" fill="none" stroke="#f59e0b" stroke-width="1.5" width="44" height="44">
            <circle cx="24" cy="24" r="20"/>
            <line x1="24" y1="14" x2="24" y2="26"/>
            <circle cx="24" cy="32" r="1.5" fill="#f59e0b" stroke="none"/>
        </svg>
        <div class="rescan-badge">
            <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12">
                <path d="M12 7A5 5 0 112 7"/><polyline points="12,4 12,7 9,7"/>
            </svg>
            Assessment Required
        </div>
        <h3>${featureName} needs a scan</h3>
        <p>Click <strong>Launch Assessment</strong>, enter your credentials, and run a full assessment. Results will appear here automatically.</p>
    </div>`;
}

// ── PDF Download ──────────────────────────────────────────────────────────
function downloadPDF() {
    showToast('Generating threat report PDF...', 'info');
    window.open('/api/download-pdf', '_blank');
}

// ── Utilities ─────────────────────────────────────────────────────────────
function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = String(str || '');
    return d.innerHTML;
}
const esc = escapeHtml;

function severityBadge(severity) {
    const s   = (severity || '').toUpperCase();
    const cls = s === 'CRITICAL' ? 'critical' : s === 'HIGH' ? 'high' : s === 'MEDIUM' ? 'medium' : 'low';
    return `<span class="severity-badge ${cls}">${s}</span>`;
}

function cvssColor(score) {
    if (!score && score !== 0) return 'var(--text-muted)';
    const n = Number(score);
    return n >= 9.0 ? '#ef4444' : n >= 7.0 ? '#f59e0b' : n >= 4.0 ? '#3b82f6' : '#10b981';
}

function setBadge(id, count) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = count;
    el.style.display = count > 0 ? '' : 'none';
}

function emptyMsg(text) {
    return `<div class="empty-state">
        <svg viewBox="0 0 36 36" fill="none" stroke="currentColor" stroke-width="1.2" width="36" height="36" style="opacity:0.3;margin-bottom:12px">
            <circle cx="18" cy="18" r="15"/><line x1="12" y1="18" x2="24" y2="18"/>
        </svg>
        <div class="empty-desc">${esc(text)}</div>
    </div>`;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.innerHTML = `<span>${esc(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 5000);
}


// ── Theme Toggle ──────────────────────────────────────────────────────────
(function() {
    var saved = localStorage.getItem('prism-theme') || 'dark';
    applyTheme(saved);
})();

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('prism-theme', theme);
    var dark  = document.getElementById('theme-icon-dark');
    var light = document.getElementById('theme-icon-light');
    if (!dark || !light) return;
    if (theme === 'light') {
        dark.style.display  = 'none';
        light.style.display = '';
    } else {
        dark.style.display  = '';
        light.style.display = 'none';
    }
}

function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
}


// ── MVC Engine ────────────────────────────────────────────────────────────
async function renderMVC() {
    const el = document.getElementById('mvc-content');
    if (!el) return;
    el.innerHTML = '<div style="color:var(--text-muted);padding:20px;">Loading...</div>';
    try {
        const data = await fetch('/api/mvc').then(r => r.json());
        if (data && data.error === 'no_scan') {
            el.innerHTML = noScanMsg('MVC Engine');
            return;
        }
        if (!data || !data.paths || data.paths.length === 0) {
            el.innerHTML = `<div class="rescan-notice">
                <svg viewBox="0 0 48 48" fill="none" stroke="#10b981" stroke-width="1.5" width="44" height="44">
                    <circle cx="24" cy="24" r="20"/><polyline points="14,24 21,31 34,18"/>
                </svg>
                <h3 style="color:#10b981">No Attack Paths Found</h3>
                <p>No viable attack path from any identity to administrator was identified. This is a positive security result.</p>
                ${data && data.account_rating ? `<div style="margin-top:8px;font-size:13px;color:var(--accent-cyan)">Account Rating: <strong>${esc(data.account_rating)}</strong></div>` : ''}
            </div>`;
            return;
        }
        const ratingColor = {'CATASTROPHIC':'#ef4444','CRITICAL':'#ef4444','HIGH':'#f59e0b','MEDIUM':'#3b82f6','LOW':'#10b981'}[data.account_rating] || '#10b981';
        const statsBar = `<div class="kpi-grid" style="margin-bottom:24px;">
            <div class="kpi-card"><div class="kpi-label">Account Rating</div><div class="kpi-value" style="color:${ratingColor}">${esc(data.account_rating||'N/A')}</div></div>
            <div class="kpi-card"><div class="kpi-label">Total Paths</div><div class="kpi-value critical">${data.total_paths||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Already Admin</div><div class="kpi-value critical">${data.zero_hop_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">1-Step to Admin</div><div class="kpi-value high">${data.one_hop_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">2-Step to Admin</div><div class="kpi-value medium">${data.two_hop_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Fastest Path</div><div class="kpi-value" style="color:var(--accent-cyan)">${data.fastest_seconds != null ? data.fastest_seconds+'s' : 'N/A'}</div></div>
        </div>`;
        const paths = (data.paths||[]).map(p => {
            const hops = p.hops === 0 ? '<span style="color:#ef4444;font-weight:700">ALREADY ADMIN</span>' : `<span class="mono">${p.hops} hop${p.hops>1?'s':''}</span>`;
            const steps = (p.steps||[]).map((s,i) => `
                <div class="mvc-step ${s.logged?'logged':'blind'}">
                    <div class="mvc-step-num">${i+1}</div>
                    <div class="mvc-step-body">
                        <div class="mvc-step-action">${esc(s.action)}</div>
                        <div class="mvc-step-target">Target: <span class="mono">${esc(s.target)}</span></div>
                        <div class="mvc-step-meta">${s.logged?'[LOGGED]':'[BLIND SPOT]'} &bull; <span class="mono" style="color:var(--accent-cyan)">${esc(s.mitre||'')}</span> &bull; +${s.seconds}s</div>
                        <div class="remediation-cmd" style="margin-top:6px">${esc(s.command||'')}</div>
                    </div>
                </div>`).join('');
            return `<div class="mvc-path-card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                    <div style="font-weight:700;font-size:14px;color:var(--text-heading);font-family:var(--font-mono)">${esc(p.start_identity)}</div>
                    <div style="display:flex;gap:8px;align-items:center">${hops} ${severityBadge(p.severity)} <span style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted)">${p.total_seconds}s total</span></div>
                </div>
                ${steps}
                <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">Logged steps: ${p.logged_steps||0} &bull; Blind spots: ${p.blind_steps||0}</div>
            </div>`;
        }).join('');
        el.innerHTML = statsBar + paths;
        setBadge('badge-mvc', data.total_paths||0);
    } catch(e) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">Failed to load MVC data: ' + esc(e.message) + '</div>'; }
}

// ── Assumed Breach ────────────────────────────────────────────────────────
async function populateBreachSelector() {
    try {
        const identities = await fetch('/api/assumed-breach/identities').then(r => r.json());
        const sel = document.getElementById('breach-identity-select');
        if (!sel) return;
        // Clear existing options except placeholder
        while (sel.options.length > 1) sel.remove(1);
        if (!identities || identities.length === 0) {
            const el = document.getElementById('breach-content');
            if (el) el.innerHTML = noScanMsg('Assumed Breach Simulator');
            return;
        }
        identities.forEach(id => {
            const opt = document.createElement('option');
            opt.value = id; opt.textContent = id;
            sel.appendChild(opt);
        });
    } catch(e) {}
}
async function loadBreachSim() {
    const sel = document.getElementById('breach-identity-select');
    const el  = document.getElementById('breach-content');
    if (!sel || !el || !sel.value) return;
    el.innerHTML = '<div style="color:var(--text-muted);padding:20px">Simulating breach from ' + esc(sel.value) + '...</div>';
    try {
        const data = await fetch('/api/assumed-breach?identity=' + encodeURIComponent(sel.value)).then(r => r.json());
        if (data.error) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">' + esc(data.error) + '</div>'; return; }
        const ratingColor = {'CRITICAL':'#ef4444','HIGH':'#f59e0b','MEDIUM':'#3b82f6'}[data.risk_rating]||'#10b981';
        const statsBar = `<div class="kpi-grid" style="margin-bottom:24px;">
            <div class="kpi-card"><div class="kpi-label">Risk Rating</div><div class="kpi-value" style="color:${ratingColor}">${esc(data.risk_rating||'N/A')}</div></div>
            <div class="kpi-card"><div class="kpi-label">Available Moves</div><div class="kpi-value critical">${data.available_moves||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Critical Actions</div><div class="kpi-value critical">${data.critical_moves||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Time to Impact</div><div class="kpi-value high">${data.time_to_impact_minutes||0} min</div></div>
            <div class="kpi-card"><div class="kpi-label">Wildcard Admin</div><div class="kpi-value" style="color:${data.has_wildcard?'#ef4444':'#10b981'}">${data.has_wildcard?'YES':'NO'}</div></div>
        </div>`;
        const narrative = `<div class="narrative-block"><div class="narrative-label">Worst-Case Scenario</div><p style="line-height:1.7">${esc(data.worst_case||'')}</p></div>`;
        const cats = data.by_category || {};
        const catColors = data.category_colors || {};
        const catCards = Object.entries(cats).map(([cat, moves]) => {
            const avail = moves.filter(m => m.available);
            if (!avail.length && !moves.length) return '';
            const color = catColors[cat] || '#3b82f6';
            const rows = moves.map(m => `<tr style="${m.available?'':'opacity:0.35'}">
                <td class="mono" style="font-size:10px">${esc(m.action)}</td>
                <td>${m.available?'<span style="color:#10b981;font-weight:600">YES</span>':'<span style="color:#475569">NO</span>'}</td>
                <td style="font-family:var(--font-mono);font-size:11px;color:${m.cvss>=9?'#ef4444':m.cvss>=7?'#f59e0b':'#3b82f6'}">${m.cvss}</td>
                <td style="font-size:10px;color:var(--text-muted)">${esc(m.impact)}</td>
            </tr>`).join('');
            return `<div class="breach-cat-card" style="border-left:3px solid ${color}">
                <div style="font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;color:${color};margin-bottom:10px">${esc(cat)} <span style="color:var(--text-muted);font-weight:400">(${avail.length}/${moves.length} available)</span></div>
                <table class="data-table"><thead><tr><th>Action</th><th>Available</th><th>CVSS</th><th>Impact</th></tr></thead><tbody>${rows}</tbody></table>
            </div>`;
        }).filter(Boolean).join('');
        const timeline = (data.timeline||[]).map(t => `
            <div class="kc-phase ${t.logged?'detected':'blind'}">
                <div class="kc-phase-header"><div class="kc-phase-name">${esc(t.phase)}</div><div class="kc-phase-time">+${t.cumulative_minutes} min</div></div>
                <div class="kc-phase-desc">${esc(t.action)} -- ${esc(t.impact)}</div>
                <div class="kc-detection ${t.logged?'':'blind'}">${t.logged?'[LOGGED]':'[BLIND SPOT]'} &bull; CVSS ${t.cvss} &bull; <span class="mono">${esc(t.mitre)}</span></div>
            </div>`).join('');
        el.innerHTML = statsBar + narrative + '<div style="margin:20px 0 10px;font-size:13px;font-weight:600;color:var(--text-heading)">Attack Timeline</div>' + timeline +
            '<div style="margin:20px 0 10px;font-size:13px;font-weight:600;color:var(--text-heading)">Available Moves by Category</div>' + catCards;
    } catch(e) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">Simulation failed: ' + esc(e.message) + '</div>'; }
}

// ── Ransomware ────────────────────────────────────────────────────────────
async function renderRansomware() {
    const el = document.getElementById('ransomware-content');
    if (!el) return;
    try {
        const data = await fetch('/api/ransomware').then(r => r.json());
        if (data && data.error === 'no_scan') { el.innerHTML = noScanMsg('Ransomware Risk'); return; }
        if (!data || !data.risk_rating) { el.innerHTML = noScanMsg('Ransomware Risk'); return; }
        const score = data.overall_score||0;
        const sc = score>=80?'#ef4444':score>=55?'#f59e0b':score>=30?'#3b82f6':'#10b981';
        const circ=2*Math.PI*80; const off=circ-(score/100)*circ;
        const gauge = `<div style="display:flex;flex-direction:column;align-items:center;padding:20px;">
            <div class="risk-gauge" style="margin-bottom:12px;">
                <svg viewBox="0 0 200 200"><circle class="gauge-bg" cx="100" cy="100" r="80"/><circle class="gauge-fill" cx="100" cy="100" r="80" style="stroke:${sc};stroke-dasharray:${circ};stroke-dashoffset:${off}"/></svg>
                <div class="gauge-center"><div class="gauge-score" style="color:${sc}">${score}</div><div class="gauge-label">${esc(data.risk_rating)}</div></div>
            </div>
            <div style="font-size:12px;color:var(--text-muted);text-align:center">${esc(data.real_world_reference||'')}</div>
            <div style="margin-top:8px;font-size:13px;color:var(--accent-cyan)">Recovery estimate: ${esc(data.recovery_time_estimate||'N/A')}</div>
        </div>`;
        const idRows = (data.identity_results||[]).slice(0,10).map(r => `<tr>
            <td>${severityBadge(r.severity)}</td>
            <td class="mono">${esc(r.identity)}</td>
            <td>${r.phases_available}/6</td>
            <td>${r.full_ransom_capable?'<span style="color:#ef4444;font-weight:700">YES</span>':'<span style="color:#f59e0b">PARTIAL</span>'}</td>
            <td style="font-size:11px;color:var(--text-muted)">${(r.phases||[]).join(', ')}</td>
        </tr>`).join('');
        const bktRows = (data.bucket_results||[]).slice(0,10).map(b => `<tr>
            <td>${severityBadge(b.ransomware_risk)}</td>
            <td class="mono">${esc(b.bucket_name)}</td>
            <td>${b.versioning?'<span style="color:#10b981">ON</span>':'<span style="color:#ef4444">OFF</span>'}</td>
            <td>${b.object_lock?'<span style="color:#10b981">ON</span>':'<span style="color:#ef4444">OFF</span>'}</td>
            <td>${b.replication?'<span style="color:#10b981">YES</span>':'<span style="color:#f59e0b">NO</span>'}</td>
        </tr>`).join('');
        el.innerHTML = gauge +
            '<div style="margin:16px 0 8px;font-size:13px;font-weight:600;color:var(--text-heading)">Identities with Ransomware Capability</div>' +
            `<table class="data-table"><thead><tr><th>Severity</th><th>Identity</th><th>Phases</th><th>Full Ransom</th><th>Capabilities</th></tr></thead><tbody>${idRows}</tbody></table>` +
            '<div style="margin:20px 0 8px;font-size:13px;font-weight:600;color:var(--text-heading)">Bucket Protection Status</div>' +
            `<table class="data-table"><thead><tr><th>Risk</th><th>Bucket</th><th>Versioning</th><th>Object Lock</th><th>Replication</th></tr></thead><tbody>${bktRows}</tbody></table>`;
    } catch(e) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">Failed: ' + esc(e.message) + '</div>'; }
}

// ── Supply Chain ──────────────────────────────────────────────────────────
async function renderSupplyChain() {
    const el = document.getElementById('supply-chain-content');
    if (!el) return;
    try {
        const data = await fetch('/api/supply-chain').then(r => r.json());
        if (data && data.error === 'no_scan') { el.innerHTML = noScanMsg('Supply Chain'); return; }
        if (!data || !data.findings) { el.innerHTML = noScanMsg('Supply Chain'); return; }
        if (data.note) {
            el.innerHTML = `<div class="rescan-notice" style="padding:32px 20px">
                <svg viewBox="0 0 48 48" fill="none" stroke="#06b6d4" stroke-width="1.5" width="40" height="40"><circle cx="24" cy="24" r="20"/><line x1="24" y1="14" x2="24" y2="26"/><circle cx="24" cy="32" r="1.5" fill="#06b6d4" stroke="none"/></svg>
                <h3 style="color:#06b6d4">Live Session Required</h3>
                <p>${esc(data.note)}</p>
                <p style="margin-top:8px;font-size:11px;color:var(--text-muted)">Reference: ${esc(data.real_world_ref||'')}</p>
            </div>`;
            return;
        }
        const stats = `<div class="kpi-grid" style="margin-bottom:24px">
            <div class="kpi-card"><div class="kpi-label">Overall Risk</div><div class="kpi-value ${data.overall_risk?.toLowerCase()||''}">${esc(data.overall_risk||'N/A')}</div></div>
            <div class="kpi-card"><div class="kpi-label">Critical</div><div class="kpi-value critical">${data.critical_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">High</div><div class="kpi-value high">${data.high_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Total Findings</div><div class="kpi-value">${data.total_findings||0}</div></div>
        </div>`;
        const rows = (data.findings||[]).map(f => `<tr>
            <td>${severityBadge(f.severity)}</td>
            <td><span style="font-size:10px;font-family:var(--font-mono);color:var(--text-muted)">${esc(f.type||'')}</span></td>
            <td class="mono">${esc((f.resource||'').substring(0,30))}</td>
            <td style="font-size:11px">${esc((f.description||'').substring(0,120))}</td>
            <td style="font-family:var(--font-mono);font-size:10px;color:var(--accent-cyan)">${esc(f.mitre||'')}</td>
        </tr>`).join('');
        el.innerHTML = stats + `<div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">Reference: ${esc(data.real_world_ref||'')}</div>` +
            `<table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Resource</th><th>Description</th><th>MITRE</th></tr></thead><tbody>${rows}</tbody></table>`;
        setBadge('badge-supplychain', data.total_findings||0);
    } catch(e) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">Failed: ' + esc(e.message) + '</div>'; }
}

// ── Golden SAML ───────────────────────────────────────────────────────────
async function renderGoldenSAML() {
    const el = document.getElementById('golden-saml-content');
    if (!el) return;
    try {
        const data = await fetch('/api/golden-saml').then(r => r.json());
        if (data && data.error === 'no_scan') { el.innerHTML = noScanMsg('Golden SAML'); return; }
        if (!data || !data.findings) { el.innerHTML = noScanMsg('Golden SAML'); return; }
        const ratingColor = {'CRITICAL':'#ef4444','HIGH':'#f59e0b','LOW':'#10b981'}[data.overall_risk]||'#10b981';
        const header = `<div class="narrative-block" style="margin-bottom:20px">
            <div class="narrative-label">Technique Overview</div>
            <p style="line-height:1.7">${esc(data.technique_summary||'')}</p>
            <p style="margin-top:8px;font-size:11px;color:var(--text-muted)">Real-world reference: ${esc(data.real_world_ref||'')}</p>
        </div>`;
        const stats = `<div class="kpi-grid" style="margin-bottom:24px">
            <div class="kpi-card"><div class="kpi-label">Overall Risk</div><div class="kpi-value" style="color:${ratingColor}">${esc(data.overall_risk||'N/A')}</div></div>
            <div class="kpi-card"><div class="kpi-label">Critical</div><div class="kpi-value critical">${data.critical_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">High</div><div class="kpi-value high">${data.high_count||0}</div></div>
            <div class="kpi-card"><div class="kpi-label">Total</div><div class="kpi-value">${data.total_findings||0}</div></div>
        </div>`;
        const rows = (data.findings||[]).map(f => {
            const scenario = f.attack_scenario ? `<div class="remediation-cmd" style="margin-top:6px;white-space:normal">${esc(f.attack_scenario)}</div>` : '';
            const remediation = f.remediation ? `<div style="margin-top:4px;font-size:10px;color:var(--accent-green)">Fix: ${esc(f.remediation.substring(0,120))}</div>` : '';
            return `<div class="fingerprint-card" style="flex-direction:column;align-items:flex-start">
                <div style="display:flex;gap:12px;align-items:center;width:100%;margin-bottom:8px">
                    ${severityBadge(f.severity)}
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${esc(f.type||'')}</span>
                    <span class="mono" style="color:var(--accent-cyan);font-size:10px">${esc(f.mitre||'')}</span>
                    <span style="margin-left:auto;font-family:var(--font-mono);font-size:13px;font-weight:700;color:#f59e0b">${esc(f.resource||'')}</span>
                </div>
                <div style="font-size:12px;color:var(--text-secondary);line-height:1.6">${esc(f.description||'')}</div>
                ${scenario}${remediation}
            </div>`;
        }).join('');
        el.innerHTML = header + stats + rows;
        setBadge('badge-saml', data.total_findings||0);
    } catch(e) { el.innerHTML = '<div style="color:var(--accent-red);padding:20px">Failed: ' + esc(e.message) + '</div>'; }
}