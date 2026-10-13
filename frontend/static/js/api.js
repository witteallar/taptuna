const api = {
  async _request(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* ignore */ }
    if (!res.ok) {
      const err = (data && data.error) || {
        code: "http_" + res.status,
        message: res.statusText || "Ошибка запроса",
      };
      const e = new Error(err.message);
      e.code = err.code;
      e.details = err.details || {};
      throw e;
    }
    return data;
  },

  health()       { return this._request("GET",  "/api/health"); },
  listCaptures() { return this._request("GET",  "/api/capture/list"); },
  openCapture(path) {
    return this._request("POST", "/api/capture/open", { path });
  },
};