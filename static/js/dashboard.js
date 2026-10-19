/* Renders a summary (from analytics.summarize) into the dashboard widgets. */
(function () {
  const COLORS = { Normal: '#0ca30c', Suspicious: '#fab219', Malicious: '#d03b3b' };
  const BLUE = '#2a78d6', GRID = '#ececec', INK = '#565959';
  const LABELS = ['Normal', 'Suspicious', 'Malicious'];
  const n = v => Number(v || 0).toLocaleString();
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  if (window.Chart) {
    Chart.defaults.font.family = 'Arial, Helvetica, sans-serif';
    Chart.defaults.color = INK;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.tooltip.backgroundColor = '#232f3e';
    Chart.defaults.maintainAspectRatio = false;
    Chart.defaults.animation.duration = 300;
  }
  const axes = (stacked, horizontal) => ({
    x: { stacked, grid: { display: horizontal, color: GRID }, border: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 12 }, beginAtZero: true },
    y: { stacked, grid: { display: !horizontal, color: GRID }, border: { display: false }, beginAtZero: true, ticks: { precision: 0 } },
  });

  function fmtTime(ts, bucket) {
    const d = new Date(ts * 1000);
    if (bucket < 3600) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: bucket < 60 ? '2-digit' : undefined });
    if (bucket < 86400) return d.toLocaleString([], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString([], { day: '2-digit', month: 'short', year: 'numeric' });
  }

  class Dashboard {
    constructor(prefix) { this.p = prefix; this.charts = {}; }
    el(id) { return document.getElementById(this.p + '-' + id); }

    upsert(key, config) {
      const c = this.charts[key];
      if (c) { c.data.labels = config.data.labels; c.data.datasets.forEach((ds, i) => { ds.data = config.data.datasets[i].data; if (config.data.datasets[i].backgroundColor) ds.backgroundColor = config.data.datasets[i].backgroundColor; }); c.update('none'); return; }
      this.charts[key] = new Chart(this.el(key), config);
    }

    render(s) {
      const k = s.kpis;
      const tiles = [
        ['blue', n(k.total), 'Events analysed'], ['ok', n(k.normal), 'Normal'], ['warn', n(k.suspicious), 'Suspicious'],
        ['bad', n(k.malicious), 'Malicious'], ['', k.threat_pct + '%', 'Threat rate'], ['', n(k.unique_ips), 'Unique IPs'],
        ['', n(k.flagged_ips), 'IPs flagged'], ['', k.avg_risk, 'Avg risk score'],
      ];
      this.el('kpis').innerHTML = tiles.map(([c, v, l]) => `<div class="kpi ${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');

      // 1. verdict distribution
      this.upsert('dist', {
        type: 'doughnut',
        data: { labels: LABELS, datasets: [{ data: LABELS.map(l => s.distribution[l]), backgroundColor: LABELS.map(l => COLORS[l]), borderColor: '#fff', borderWidth: 2 }] },
        options: { cutout: '62%', plugins: { legend: { position: 'right' }, tooltip: { callbacks: { label: ctx => {
          const tot = ctx.dataset.data.reduce((a, b) => a + b, 0) || 1; return ` ${ctx.label}: ${n(ctx.parsed)} (${(100 * ctx.parsed / tot).toFixed(1)}%)`; } } } } },
      });

      // 2. timeline
      const tl = s.timeline;
      this.upsert('timeline', {
        type: 'bar',
        data: { labels: tl.labels.map(t => fmtTime(t, tl.bucket_seconds)),
          datasets: LABELS.map(l => ({ label: l, data: tl.series[l], backgroundColor: COLORS[l], borderColor: '#fff', borderWidth: { top: 1 }, barPercentage: 0.95, categoryPercentage: 0.9 })) },
        options: { scales: axes(true, false), interaction: { mode: 'index', intersect: false }, plugins: { legend: { position: 'top', align: 'end' } } },
      });
      const note = this.el('tl-note');
      if (note && tl.bucket_seconds) {
        const b = tl.bucket_seconds, unit = b < 60 ? b + ' seconds' : b < 3600 ? (b / 60) + ' minutes' : b < 86400 ? (b / 3600) + ' hour(s)' : (b / 86400) + ' day(s)';
        note.textContent = `Events per ${unit}, stacked by verdict.`;
      }

      // 3. threat types
      this.upsert('reasons', {
        type: 'bar',
        data: { labels: s.reasons.map(r => r[0]), datasets: [{ label: 'Flagged events', data: s.reasons.map(r => r[1]), backgroundColor: BLUE, borderRadius: 4, borderSkipped: 'start', barPercentage: 0.7 }] },
        options: { indexAxis: 'y', scales: axes(false, true), plugins: { legend: { display: false } } },
      });

      // 4. top IPs
      this.upsert('ips', {
        type: 'bar',
        data: { labels: s.top_ips.map(r => r.ip),
          datasets: ['Suspicious', 'Malicious'].map(l => ({ label: l, data: s.top_ips.map(r => r[l]), backgroundColor: COLORS[l], borderColor: '#fff', borderWidth: { right: 2 }, barPercentage: 0.7 })) },
        options: { indexAxis: 'y', scales: axes(true, true), plugins: { legend: { position: 'top', align: 'end' } } },
      });

      // 5. risk histogram
      this.upsert('hist', {
        type: 'bar',
        data: { labels: s.risk_hist.map((_, i) => `${i * 10}-${i * 10 + 9 + (i === 9 ? 1 : 0)}`),
          datasets: [{ label: 'Events', data: s.risk_hist, backgroundColor: s.risk_hist.map((_, i) => i < 4 ? COLORS.Normal : i < 7 ? COLORS.Suspicious : COLORS.Malicious), borderRadius: 4, borderSkipped: 'start', barPercentage: 0.95, categoryPercentage: 0.95 }] },
        options: { scales: axes(false, false), plugins: { legend: { display: false } } },
      });

      // 6. flagged table
      const rows = s.recent_flagged.map(r => `<tr><td>${esc(new Date(r.ts * 1000).toLocaleString())}</td><td><span class="tag ${esc(r.label)}">${esc(r.label)}</span></td>
        <td class="num">${Math.round(r.risk)}</td><td>${esc(r.reason)}</td><td>${esc(r.ip)}</td><td>${esc(r.user || '-')}</td><td>${esc(r.action)}</td></tr>`);
      this.el('flagged').innerHTML = rows.join('') || '<tr><td colspan="7" class="empty">No suspicious activity in this window. 🎉</td></tr>';
    }
  }
  window.Dashboard = Dashboard;
})();
