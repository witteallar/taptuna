async function checkHealth() {
  const el = document.getElementById("health");
  el.className = "health";
  try {
    const h = await api.health();
    if (h.tshark_available) {
      el.textContent = "tshark: " + h.tshark_version;
      el.classList.add("ok");
    } else {
      el.textContent = "tshark недоступен: " + h.tshark_version;
      el.classList.add("err");
    }
  } catch (e) {
    el.textContent = "Ошибка проверки: " + e.message;
    el.classList.add("err");
  }
}

async function loadCaptureList() {
  const sel = document.getElementById("capture-list");
  sel.innerHTML = '<option value="">— загрузка… —</option>';
  try {
    const data = await api.listCaptures();
    sel.innerHTML = '<option value="">— выберите файл из data/captures —</option>';
    (data.files || []).forEach((f) => {
      const opt = document.createElement("option");
      opt.value = f.path;
      opt.textContent = `${f.name} (${formatSize(f.size)})`;
      sel.appendChild(opt);
    });
  } catch (e) {
    sel.innerHTML = `<option value="">Ошибка: ${escapeHtml(e.message)}</option>`;
  }
}

async function openCapture() {
  const path = document.getElementById("capture-path").value.trim();
  const status = document.getElementById("open-status");
  if (!path) {
    showToast("Укажите путь к файлу .pcap/.pcapng");
    return;
  }
  status.textContent = "Открытие…";
  status.classList.add("muted");
  try {
    const data = await api.openCapture(path);
    status.textContent =
      `Открыто: ${data.path} · сессий: ${data.sessions.length} · capture_id: ${data.capture_id}`;
    sessionsUI.render(data.sessions);
  } catch (e) {
    status.textContent = "Ошибка: " + e.message;
    showToast(`[${e.code}] ${e.message}`);
  }
}

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { t.hidden = true; }, 4500);
}

function formatSize(b) {
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
  return (b / 1024 / 1024).toFixed(1) + " MB";
}

document.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  loadCaptureList();

  document.getElementById("open-capture")
          .addEventListener("click", openCapture);

  document.getElementById("refresh-captures")
          .addEventListener("click", loadCaptureList);

  document.getElementById("capture-list")
          .addEventListener("change", (e) => {
            if (e.target.value) {
              document.getElementById("capture-path").value = e.target.value;
            }
          });

  document.getElementById("capture-path")
          .addEventListener("keydown", (e) => {
            if (e.key === "Enter") openCapture();
          });
});