const REFRESH_INTERVAL_MS = 30_000;
const state = { period: "today", group: "site", scope: "all" };
const groupTitles = {
  site: "按站点汇总",
  destination: "按完整域名 / IP 汇总",
  process: "按应用汇总",
  rule: "按命中规则汇总",
  outbound: "按实际出口节点汇总",
  chain: "按完整出口链汇总",
};
const groupIcons = {
  site: "icon-globe",
  destination: "icon-globe",
  process: "icon-app",
  rule: "icon-shield",
  outbound: "icon-route",
  chain: "icon-layers",
};

function bytes(value) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const number = value / Math.pow(1024, index);
  return `${number.toFixed(index === 0 ? 0 : number >= 100 ? 0 : number >= 10 ? 1 : 2)} ${units[index]}`;
}

function relativeTime(value) {
  if (!value) return "尚未采样";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 5) return "刚刚更新";
  if (seconds < 60) return `${seconds} 秒前更新`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前更新`;
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node.textContent === String(text)) return;
  node.textContent = text;
}

function icon(name, className = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  if (className) svg.setAttribute("class", className);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#${name}`);
  svg.append(use);
  return svg;
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function renderDistribution(rows) {
  const root = document.getElementById("distribution");
  if (!rows.length) {
    root.innerHTML = '<div class="visual-empty">等待流量数据</div>';
    return;
  }
  const topRows = rows.filter(row => row.total > 0).slice(0, 3);
  const max = Math.max(...topRows.map(row => row.total), 1);
  root.replaceChildren(...topRows.map(row => {
    const item = document.createElement("div");
    item.className = "distribution-item";
    const label = document.createElement("span");
    label.className = "distribution-label";
    label.textContent = row.label;
    label.title = row.label;
    const bar = document.createElement("span");
    bar.className = "distribution-bar";
    const fill = document.createElement("i");
    fill.style.width = `${Math.max(3, row.total / max * 100)}%`;
    bar.append(fill);
    const value = document.createElement("span");
    value.className = "distribution-value";
    value.textContent = bytes(row.total);
    item.append(label, bar, value);
    return item;
  }));
}

function renderRows(rows) {
  const root = document.getElementById("rows");
  if (!rows.length) {
    root.innerHTML = '<div class="empty">这个时间范围内还没有流量。保持统计器运行后，数据会自动出现。</div>';
    return;
  }
  const max = Math.max(...rows.map(row => row.total), 1);
  root.replaceChildren(...rows.map((row, index) => {
    const item = document.createElement("div");
    item.className = "row";

    const label = document.createElement("div");
    label.className = "label";
    const labelLine = document.createElement("div");
    labelLine.className = "label-line";
    labelLine.append(icon(groupIcons[state.group], "row-icon"));
    const rank = document.createElement("span");
    rank.className = "rank";
    rank.textContent = String(index + 1).padStart(2, "0");
    const labelText = document.createElement("span");
    labelText.className = "label-text";
    labelText.textContent = row.label;
    labelLine.append(rank, labelText);
    label.append(labelLine);

    const sources = document.createElement("div");
    sources.className = "source-groups";
    const sourceGroups = Array.isArray(row.sourceGroups) ? row.sourceGroups : [];
    sourceGroups.forEach((group, groupIndex) => {
      const badge = document.createElement("span");
      badge.className = `source-badge source-${Math.min(groupIndex + 1, 3)}`;
      badge.title = `${group.label} · ${bytes(group.total)}`;
      const badgeIcon = icon(group.label === "自建" ? "icon-shield" : "icon-route");
      const badgeText = document.createElement("span");
      badgeText.textContent = group.label;
      badge.append(badgeIcon, badgeText);
      sources.append(badge);
    });
    if (!sourceGroups.length) {
      const unknown = document.createElement("span");
      unknown.className = "source-badge source-unknown";
      unknown.textContent = "未知分组";
      sources.append(unknown);
    }

    const usage = document.createElement("div");
    usage.className = "usage";
    const bar = document.createElement("div");
    bar.className = "bar";
    const fill = document.createElement("i");
    fill.style.width = `${Math.max(1, row.total / max * 100)}%`;
    bar.append(fill);
    const split = document.createElement("div");
    split.className = "split";
    split.textContent = `↓ ${bytes(row.download)}   ↑ ${bytes(row.upload)}`;
    usage.append(bar, split);

    const amount = document.createElement("div");
    amount.className = "amount";
    amount.textContent = bytes(row.total);
    item.append(label, sources, usage, amount);
    return item;
  }));
}

async function refresh() {
  try {
    const [summary, status] = await Promise.all([
      getJson(`/api/summary?period=${state.period}&group=${state.group}&scope=${state.scope}&limit=50`),
      getJson("/api/status"),
    ]);
    setText("total", bytes(summary.total));
    setText("download", bytes(summary.download));
    setText("upload", bytes(summary.upload));
    setText("connections", status.liveConnections);
    const knownRate = summary.total ? summary.known / summary.total * 100 : 100;
    setText("knownRate", `可归属 ${knownRate.toFixed(knownRate >= 99 ? 1 : 0)}%`);
    setText("lastUpdate", relativeTime(status.lastSuccess));
    const totalTransfer = summary.download + summary.upload;
    const downloadPercent = totalTransfer ? summary.download / totalTransfer * 100 : 50;
    const ring = document.getElementById("trafficRing");
    ring.style.setProperty("--download-percent", downloadPercent.toFixed(2));
    setText("downloadRate", `${Math.round(downloadPercent)}%`);
    setText("downloadLegend", bytes(summary.download));
    setText("uploadLegend", bytes(summary.upload));
    renderDistribution(summary.rows);
    renderRows(summary.rows);

    const dot = document.getElementById("statusDot");
    if (status.lastError) {
      dot.className = "dot bad";
      setText("statusText", "sing-box API 暂时离线");
    } else {
      dot.className = "dot ok";
      setText("statusText", "正在持续统计");
    }
  } catch (error) {
    document.getElementById("statusDot").className = "dot bad";
    setText("statusText", "统计器连接失败");
  }
}

document.getElementById("periods").addEventListener("click", event => {
  const button = event.target.closest("button[data-period]");
  if (!button) return;
  state.period = button.dataset.period;
  document.querySelectorAll("[data-period]").forEach(node => node.classList.toggle("active", node === button));
  document.getElementById("exportLink").href = `/api/export.csv?period=${state.period}&group=${state.group}&scope=${state.scope}`;
  refresh();
});

document.getElementById("groups").addEventListener("click", event => {
  const button = event.target.closest("button[data-group]");
  if (!button) return;
  state.group = button.dataset.group;
  document.querySelectorAll("[data-group]").forEach(node => node.classList.toggle("active", node === button));
  setText("groupTitle", groupTitles[state.group]);
  document.getElementById("exportLink").href = `/api/export.csv?period=${state.period}&group=${state.group}&scope=${state.scope}`;
  refresh();
});

document.getElementById("scopes").addEventListener("click", event => {
  const button = event.target.closest("button[data-scope]");
  if (!button) return;
  state.scope = button.dataset.scope;
  document.querySelectorAll("[data-scope]").forEach(node => node.classList.toggle("active", node === button));
  document.getElementById("exportLink").href = `/api/export.csv?period=${state.period}&group=${state.group}&scope=${state.scope}`;
  refresh();
});

document.querySelectorAll(".metric, .visual-panel, .panel").forEach(surface => {
  surface.addEventListener("pointermove", event => {
    const bounds = surface.getBoundingClientRect();
    surface.style.setProperty("--pointer-x", `${event.clientX - bounds.left}px`);
    surface.style.setProperty("--pointer-y", `${event.clientY - bounds.top}px`);
  });
});

refresh();
setInterval(() => {
  if (!document.hidden) refresh();
}, REFRESH_INTERVAL_MS);
