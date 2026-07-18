const state = { period: "today", group: "site", scope: "all" };
const groupTitles = {
  site: "按站点汇总",
  destination: "按完整域名 / IP 汇总",
  process: "按应用汇总",
  rule: "按命中规则汇总",
  outbound: "按实际出口节点汇总",
  chain: "按完整出口链汇总",
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

function setText(id, text) { document.getElementById(id).textContent = text; }

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
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
    const rank = document.createElement("span");
    rank.className = "rank";
    rank.textContent = String(index + 1).padStart(2, "0");
    label.append(rank, document.createTextNode(row.label));

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
    item.append(label, usage, amount);
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

refresh();
setInterval(refresh, 5000);
