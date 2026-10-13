const sessionsUI = {
  render(sessions) {
    const table = document.getElementById("sessions-table");
    const empty = document.getElementById("sessions-empty");
    const tbody = table.querySelector("tbody");
    tbody.innerHTML = "";

    if (!sessions || sessions.length === 0) {
      table.hidden = true;
      empty.hidden = false;
      empty.textContent = "В записи не найдено TCP-сессий.";
      return;
    }

    empty.hidden = true;
    table.hidden = false;

    sessions.forEach((s, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${escapeHtml(s.src_ip)}:${s.src_port}</td>
        <td>${escapeHtml(s.dst_ip)}:${s.dst_port}</td>
        <td>${s.packets}</td>
        <td>${formatTs(s.start_ts)}</td>
        <td>${s.duration.toFixed(3)}</td>
      `;
      tr.title = "stream=" + s.stream_index;
      tbody.appendChild(tr);
    });
  },
};

function formatTs(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.`
       + String(d.getMilliseconds()).padStart(3, "0");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}