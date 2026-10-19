/* Renders analytics.summarize() output and evaluation results with Chart.js. */
(function () {
  const COLORS = { Normal: '#0ca30c', Suspicious: '#fab219', Attack: '#d03b3b' };
  const SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#6250d6', '#e87ba4'];
  const BLUE = '#2a78d6', GRID = '#ececec', INK = '#565959';
  const VERDICTS = ['Normal', 'Suspicious', 'Attack'];
  const n = v => Number(v || 0).toLocaleString();
  const pct = v => v == null ? '-' : (100 * v).toFixed(1) + '%';
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  if (window.Chart) {
    Object.assign(Chart.defaults, { color: INK, maintainAspectRatio: false });
    Chart.defaults.font.family = 'Arial, Helvetica, sans-serif';
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.tooltip.backgroundColor = '#232f3e';
    Chart.defaults.animation.duration = 250;
  }
  const axes = (stacked, horizontal) => ({
    x: { stacked, grid: { display: horizontal, color: GRID }, border: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 14 }, beginAtZero: true },
    y: { stacked, grid: { display: !horizontal, color: GRID }, border: { display: false }, beginAtZero: true, ticks: { precision: 0 } },
  });
  const fmtTime = (ts, b) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: b < 60 ? '2-digit' : undefined });

  class Charts {
    constructor() { this.c = {}; }
    upsert(id, config) {
      const el = document.getElementById(id);
      if (!el) return;
      const c = this.c[id];
      if (c && c.config.type === config.type && c.data.datasets.length === config.data.datasets.length) {
        c.data.labels = config.data.labels;
        c.data.datasets.forEach((ds, i) => Object.assign(ds, config.data.datasets[i]));
        if (config.options && config.options.plugins) c.options.plugins = Object.assign(c.options.plugins, config.options.plugins);
        c.update('none'); return;
      }
      if (c) c.destroy();
      this.c[id] = new Chart(el, config);
    }
  }
  const stackedByVerdict = (rows, horizontal) => ({
    type: 'bar',
    data: { labels: rows.map(r => r.name), datasets: VERDICTS.map(v => ({ label: v, data: rows.map(r => r[v]), backgroundColor: COLORS[v], borderColor: '#fff', borderWidth: horizontal ? { right: 2 } : { top: 2 }, barPercentage: 0.75 })) },
    options: { indexAxis: horizontal ? 'y' : 'x', scales: axes(true, horizontal), interaction: { mode: 'index', intersect: false }, plugins: { legend: { position: 'top', align: 'end' } } },
  });

  class Dashboard {
    constructor(p) { this.p = p; this.ch = new Charts(); }
    id(x) { return this.p + '-' + x; }
    el(x) { return document.getElementById(this.id(x)); }

    render(s) {
      const k = s.kpis;
      const tiles = [['blue', n(k.total), 'Connections'], ['ok', n(k.normal), 'Normal'], ['warn', n(k.suspicious), 'Suspicious'],
        ['bad', n(k.attack), 'Attacks'], ['', k.threat_pct + '%', 'Threat rate'], ['', n(k.services_hit), 'Services targeted']];
      if (k.sources) tiles.push(['', n(k.sources), 'Source IPs']);
      if (k.avg_confidence) tiles.push(['', k.avg_confidence + '%', 'Avg confidence']);
      this.el('kpis').innerHTML = tiles.map(([c, v, l]) => `<div class="kpi ${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');

      this.ch.upsert(this.id('dist'), {
        type: 'doughnut',
        data: { labels: VERDICTS, datasets: [{ data: VERDICTS.map(v => s.distribution[v]), backgroundColor: VERDICTS.map(v => COLORS[v]), borderColor: '#fff', borderWidth: 2 }] },
        options: { cutout: '62%', plugins: { legend: { position: 'right' }, tooltip: { callbacks: { label: c => {
          const t = c.dataset.data.reduce((a, b) => a + b, 0) || 1; return ` ${c.label}: ${n(c.parsed)} (${(100 * c.parsed / t).toFixed(1)}%)`; } } } } },
      });

      const tl = s.timeline;
      const labels = tl.mode === 'time' ? tl.labels.map(t => fmtTime(t, tl.bucket)) : tl.labels;
      this.ch.upsert(this.id('timeline'), {
        type: 'bar',
        data: { labels, datasets: VERDICTS.map(v => ({ label: v, data: tl.series[v], backgroundColor: COLORS[v], borderColor: '#fff', borderWidth: { top: 1 }, barPercentage: 1, categoryPercentage: 0.9 })) },
        options: { scales: axes(true, false), interaction: { mode: 'index', intersect: false }, plugins: { legend: { position: 'top', align: 'end' } } },
      });
      this.el('tl-note').textContent = tl.mode === 'time'
        ? `Connections per ${tl.bucket < 60 ? tl.bucket + ' seconds' : tl.bucket / 60 + ' minute(s)'}, by verdict.`
        : `Connections in file order (groups of ${n(tl.bucket)}), by verdict.`;

      const fam = s.families || [];
      this.el('fam-note').textContent = fam.length ? 'Attack families found by the Attack Type Classification service.'
        : 'No attack types yet. Needs the Attack Type Classification service and some detected attacks.';
      this.ch.upsert(this.id('families'), {
        type: 'bar',
        data: { labels: fam.map(f => f[0]), datasets: [{ label: 'Connections', data: fam.map(f => f[1]), backgroundColor: BLUE, borderRadius: 4, borderSkipped: 'start', barPercentage: 0.6 }] },
        options: { indexAxis: 'y', scales: axes(false, true), plugins: { legend: { display: false } } },
      });

      this.ch.upsert(this.id('services'), stackedByVerdict(s.services.filter(r => r.Attack + r.Suspicious > 0), true));
      this.ch.upsert(this.id('protocols'), stackedByVerdict(s.protocols, false));

      const h = s.anomaly_hist;
      this.el('hist-note').textContent = h ? 'How unusual each connection looks. Red bars are past the alarm threshold.'
        : 'Needs the Anomaly Detection service.';
      if (h) {
        this.ch.upsert(this.id('hist'), {
          type: 'bar',
          data: { labels: h.counts.map((_, i) => h.edges[i].toFixed(2)),
            datasets: [{ label: 'Connections', data: h.counts, backgroundColor: h.counts.map((_, i) => h.edges[i + 1] > h.threshold ? COLORS.Attack : BLUE), barPercentage: 1, categoryPercentage: 0.95, borderRadius: 3 }] },
          options: { scales: axes(false, false), plugins: { legend: { display: false }, tooltip: { callbacks: { title: c => `score ${h.edges[c[0].dataIndex].toFixed(2)}-${h.edges[c[0].dataIndex + 1].toFixed(2)}` } } } },
        });
      }

      const srcCard = this.el('sources-card');
      const srcRows = (s.sources || []).filter(r => r.Attack + r.Suspicious > 0);
      if (srcCard) {
        srcCard.style.display = srcRows.length ? '' : 'none';
        if (srcRows.length) this.ch.upsert(this.id('sources'), stackedByVerdict(srcRows, true));
      }

      const rows = s.recent_flagged.map(r => `<tr><td>${r.ts ? esc(new Date(r.ts * 1000).toLocaleTimeString()) : ''}</td>
        <td><span class="tag ${esc(r.verdict)}">${esc(r.verdict)}</span></td><td>${esc(r.family || '-')}</td>
        <td class="num">${r.confidence != null ? (100 * r.confidence).toFixed(0) + '%' : '-'}</td>
        <td class="num">${r.anomaly_score != null ? r.anomaly_score.toFixed(3) : '-'}</td><td>${esc(r.src_ip || '-')}</td>
        <td>${esc(r.protocol)}/${esc(r.service)}</td><td>${esc(r.flag)}</td><td>${esc(r.label || '-')}</td></tr>`);
      this.el('flagged').innerHTML = rows.join('') || '<tr><td colspan="9" class="empty">No threats in this view. 🎉</td></tr>';
    }
  }

  const evalCharts = new Charts();
  function matrix(labels, cm, rowLabels) {
    rowLabels = rowLabels || labels;
    const head = '<tr><th></th>' + labels.map(l => `<th>${esc(l)}</th>`).join('') + '</tr>';
    const body = cm.map((row, i) => {
      const tot = row.reduce((a, b) => a + b, 0);
      return `<tr><th style="text-align:right">${esc(rowLabels[i])}</th>` + row.map(v => {
        const sh = tot ? v / tot : 0;
        return `<td style="background:rgba(42,120,214,${(0.06 + 0.9 * sh).toFixed(2)});color:${sh > 0.5 ? '#fff' : '#0f1111'}">${n(v)}<br><span style="font-weight:400;font-size:11px">${(100 * sh).toFixed(1)}%</span></td>`;
      }).join('') + '</tr>';
    }).join('');
    return `<table class="cm" style="border-collapse:collapse;width:100%"><tr><th></th><th colspan="${labels.length}">Predicted</th></tr>${head.replace('<th></th>', '<th>Actual</th>')}${body}</table>`;
  }

  window.renderEvaluation = function (p, ev, note) {
    const box = document.getElementById(p + '-eval');
    if (!box) return;
    if (!ev) { box.style.display = 'none'; return; }
    box.style.display = '';
    const $ = x => document.getElementById(p + '-' + x);
    const h = ev.hybrid;
    $('eval-note').textContent = `${note} ${n(h.samples)} labelled connections, ${n(ev.unseen_attacks)} from attack types not in the training data.`;
    $('eval-kpis').innerHTML = [['blue', pct(h.accuracy), 'Accuracy'], ['blue', pct(h.precision), 'Precision'], ['ok', pct(h.recall), 'Attacks detected (recall)'],
      ['blue', pct(h.f1), 'F1-score'], ['warn', pct(h.false_alarm_rate), 'False alarm rate']]
      .map(([c, v, l]) => `<div class="kpi ${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
    const names = Object.keys(ev.approaches);
    $('eval-table').innerHTML = '<thead><tr><th>Approach</th><th class="num">Accuracy</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th><th class="num">False alarms</th><th class="num">Known attacks caught</th><th class="num">Unseen attacks caught</th></tr></thead><tbody>' +
      names.map(a => { const m = ev.approaches[a]; return `<tr><td>${esc(a)}</td><td class="num">${pct(m.accuracy)}</td><td class="num">${pct(m.precision)}</td><td class="num">${pct(m.recall)}</td><td class="num">${pct(m.f1)}</td><td class="num">${pct(m.false_alarm_rate)}</td><td class="num">${pct(m.known_caught)}</td><td class="num">${pct(m.unseen_caught)}</td></tr>`; }).join('') + '</tbody>';
    evalCharts.upsert(p + '-eval-chart', {
      type: 'bar',
      data: { labels: names, datasets: [['Known attacks caught', 'known_caught'], ['Unseen attacks caught', 'unseen_caught'], ['False alarms', 'false_alarm_rate']].map(([l, key], i) => ({
        label: l, data: names.map(a => ev.approaches[a][key] == null ? null : +(100 * ev.approaches[a][key]).toFixed(1)), backgroundColor: SERIES[i], borderRadius: 4, borderSkipped: 'start', barPercentage: 0.8, categoryPercentage: 0.7 })) },
      options: { scales: { ...axes(false, false), x: { ...axes(false, false).x, ticks: { autoSkip: false } }, y: { ...axes(false, false).y, max: 100, ticks: { callback: v => v + '%' } } }, plugins: { legend: { position: 'top', align: 'end' }, tooltip: { callbacks: { label: c => ` ${c.dataset.label}: ${c.parsed.y}%` } } } },
    });
    $('eval-cm').innerHTML = matrix(h.labels, h.confusion_matrix);
    if (ev.family) {
      $('fam-wrap').style.display = '';
      $('fam-acc').textContent = `For actual attacks, the predicted attack type was right ${pct(ev.family.accuracy)} of the time. "normal" = the attack was missed.`;
      $('fam-cm').innerHTML = matrix(ev.family.labels, ev.family.confusion_matrix, ev.family.row_labels);
    } else $('fam-wrap').style.display = 'none';
  };
  window.Dashboard = Dashboard;
})();
