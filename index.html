// Link2Go Admin — متوافق مع السيرفر المحسّن
const SERVER_URL = "https://link2go-proxy.vercel.app";
const TOKEN_KEY = "link2go_admin_token";
const USERNAME_KEY = "link2go_admin_username";

// التوكن في sessionStorage (بيتمسح بقفل التاب) بدل localStorage
localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USERNAME_KEY);
let adminToken = sessionStorage.getItem(TOKEN_KEY) || "";
let adminUsername = sessionStorage.getItem(USERNAME_KEY) || "";
let allUsers = [], allPlans = {}, currentEditingUser = null;
let currentHistoryType = "links";
let allHistory = { links: [], otp: [], login: [] };
let refreshTimer = null;

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
const todayStr = () => new Date().toLocaleDateString("en-CA");

function showMsg(text, type = "ok") {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg show " + type;
  setTimeout(() => { m.className = "msg"; }, 4000);
}

// ---------- الجلسة ----------
function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USERNAME_KEY);
  adminToken = ""; adminUsername = "";
}
function showLoginScreen() {
  $("loginScreen").classList.remove("hidden");
  $("mainPanel").classList.remove("show");
}
function forceLogout() { stopRefresh(); clearSession(); showLoginScreen(); }

async function apiFetch(path, options = {}) {
  const r = await fetch(SERVER_URL + path, {
    ...options,
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken, ...(options.headers || {}) }
  });
  let d = {};
  try { d = await r.json(); } catch (_) {}
  if (r.status === 401) { forceLogout(); throw new Error(d.error || "انتهت الجلسة"); }
  if (r.status === 429) throw new Error(d.error || "طلبات كتير، استنى شوية");
  if (!r.ok || !d.success) throw new Error(d.error || `فشل الطلب (${r.status})`);
  return d;
}

// ---------- تسجيل الدخول / الخروج ----------
$("loginBtn").addEventListener("click", doLogin);
$("passwordInput").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
$("usernameInput").addEventListener("keydown", e => { if (e.key === "Enter") $("passwordInput").focus(); });

async function doLogin() {
  const username = $("usernameInput").value.trim();
  const password = $("passwordInput").value;
  const loginMsg = $("loginMsg");
  loginMsg.className = "login-msg";
  if (!username || !password) {
    loginMsg.textContent = "من فضلك اكتب البيانات";
    loginMsg.className = "login-msg show err";
    return;
  }
  const btn = $("loginBtn");
  btn.textContent = "جاري التحقق...";
  btn.disabled = true;
  try {
    const r = await fetch(SERVER_URL + "/admin-login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    let d = {};
    try { d = await r.json(); } catch (_) {}
    if (!r.ok || !d.success) throw new Error(d.error || "فشل تسجيل الدخول");

    adminToken = d.token; adminUsername = d.username;
    sessionStorage.setItem(TOKEN_KEY, adminToken);
    sessionStorage.setItem(USERNAME_KEY, adminUsername);
    $("passwordInput").value = "";
    $("loginScreen").classList.add("hidden");
    $("mainPanel").classList.add("show");
    $("welcomeText").textContent = "مرحباً " + adminUsername;
    startDashboard();
  } catch (e) {
    loginMsg.textContent = e.message;
    loginMsg.className = "login-msg show err";
  } finally {
    btn.textContent = "تسجيل الدخول";
    btn.disabled = false;
  }
}

$("logoutBtn").addEventListener("click", async () => {
  if (!confirm("هل أنت متأكد من تسجيل الخروج؟")) return;
  // السيرفر بيلغي التوكن فعلياً (مش بس بنمسحه من المتصفح)
  try { await fetch(SERVER_URL + "/admin-logout", { method: "POST", headers: { "Authorization": "Bearer " + adminToken } }); } catch (_) {}
  stopRefresh(); clearSession();
  location.reload();
});

async function checkAuth() {
  if (!adminToken) return false;
  try {
    const r = await fetch(SERVER_URL + "/admin-verify", { method: "POST", headers: { "Authorization": "Bearer " + adminToken } });
    if (!r.ok) { clearSession(); return false; }
    const d = await r.json();
    if (!d.success) { clearSession(); return false; }
    adminUsername = d.username || adminUsername;
    return true;
  } catch (_) { return false; }
}

// ---------- التابات ----------
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    $("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "users") loadUsers();
    if (tab.dataset.tab === "history") loadHistory();
  });
});

document.querySelectorAll(".sub-tab").forEach(st => {
  st.addEventListener("click", () => {
    document.querySelectorAll(".sub-tab").forEach(x => x.classList.remove("active"));
    st.classList.add("active");
    currentHistoryType = st.dataset.htype;
    $("historySearch").value = "";
    renderHistory();
  });
});

// ---------- المستخدمون ----------
// الباقة الفعلية: لو الباقة المدفوعة انتهت بنعتبرها مجانية (السيرفر بينزّلها تلقائياً أول ما المستخدم يدخل)
const isExpired = u => u.plan_id !== "free" && u.renewal_date && u.renewal_date < todayStr();
const effPlan = u => isExpired(u) ? "free" : u.plan_id;

async function loadUsers() {
  try {
    const d = await apiFetch("/users-list");
    allUsers = d.users || [];
    renderUsers(filterUsers());
    updateStats();
  } catch (e) {
    $("usersList").innerHTML = `<div class="empty">❌ ${esc(e.message)}</div>`;
  }
}

function updateStats() {
  $("statTotal").textContent = allUsers.length;
  ["free", "weekly", "monthly"].forEach(p => {
    const id = "stat" + p[0].toUpperCase() + p.slice(1);
    $(id).textContent = allUsers.filter(u => effPlan(u) === p).length;
  });
}

function filterUsers() {
  const q = $("userSearch").value.trim().toLowerCase();
  if (!q) return allUsers;
  return allUsers.filter(u => (u.username || "").toLowerCase().includes(q) || (u.phone || "").includes(q));
}

function renderUsers(users) {
  const container = $("usersList");
  if (!users.length) { container.innerHTML = `<div class="empty">مفيش مستخدمين</div>`; return; }
  container.innerHTML = "";
  users.forEach(u => {
    const el = document.createElement("div");
    el.className = "card";
    const plan = effPlan(u);
    const lim = u.limit ?? u.plan_limit ?? 0;
    const lis = u.listens_limit ?? u.plan_listens_limit ?? 0;
    const cls = plan === "monthly" ? "monthly" : plan === "weekly" ? "weekly" : "free";
    el.innerHTML = `
      <div class="card-head">
        <div style="flex:1;min-width:0;">
          <div class="card-title">${esc(u.username || "بدون اسم")}</div>
          <div class="card-phone">📱 ${esc(u.phone)}</div>
          <div style="display:flex;gap:5px;flex-wrap:wrap;">
            <span class="badge ${cls}">${esc(u.plan_name)}</span>
            ${isExpired(u) ? `<span class="badge cancelled">منتهية</span>` : ""}
            ${u.is_cancelled ? `<span class="badge cancelled">ملغي</span>` : ""}
            ${u.upgrade_requested ? `<span class="badge pending">طلب ترقية</span>` : ""}
          </div>
        </div>
        <div class="card-actions"><button class="card-btn primary" data-action="edit">تعديل</button></div>
      </div>
      <div class="meta-row">
        <span>📥 ${u.daily_downloads} / ${lim === -1 ? "∞" : lim}</span>
        <span>🎧 ${u.monthly_listens} / ${lis === -1 ? "∞" : lis}</span>
        ${u.renewal_date ? `<span>📅 ${esc(u.renewal_date)}</span>` : ""}
      </div>`;
    el.querySelector('[data-action="edit"]').addEventListener("click", () => openUserModal(u.phone));
    container.appendChild(el);
  });
}

$("userSearch").addEventListener("input", () => renderUsers(filterUsers()));
$("refreshUsersBtn").addEventListener("click", loadUsers);

async function loadPlans() {
  try {
    const r = await fetch(SERVER_URL + "/get-plans");
    const d = await r.json();
    if (r.ok && d.success) allPlans = d.plans || {};
  } catch (e) { console.error(e); }
}

// ---------- السجل ----------
async function loadHistory() {
  $("historyList").innerHTML = `<div class="loading"><div class="spinner"></div>جاري التحميل...</div>`;
  try {
    const d = await apiFetch("/history?type=all&limit=500");
    allHistory = Object.assign({ links: [], otp: [], login: [] }, d.data || {});
    renderHistory();
  } catch (e) {
    $("historyList").innerHTML = `<div class="empty">❌ ${esc(e.message)}</div>`;
  }
}

const LOGIN_ACTIONS = { admin_login: "🔑 دخول أدمن", otp_login: "📱 دخول مستخدم", signup: "🆕 تسجيل جديد", logout: "🚪 خروج" };
const ADMIN_ACTIONS = {
  set_plan: "تغيير باقة", delete_user: "حذف مستخدم", set_counters: "تعديل عدادات",
  set_listen_limit: "تعديل حد الاستماع", clear_history: "مسح السجل", delete_file: "حذف ملف"
};

function renderHistory(list = allHistory[currentHistoryType] || []) {
  const container = $("historyList");
  if (!list.length) { container.innerHTML = `<div class="empty">مفيش سجل</div>`; return; }
  container.innerHTML = "";
  const t = currentHistoryType;

  list.forEach(item => {
    const ok = item.status === "success";
    const st = ok ? ["success", "نجح"] : item.status === "quota" ? ["quota", "حد أقصى"] : ["failed", "فشل"];
    let title = "", phone = "", badges = "", lines = "";

    if (t === "links") {
      title = esc(item.username || "مجهول");
      phone = item.phone || "—";
      badges = `<span class="badge ${item.action === "stream" ? "stream" : "download"}">${item.action === "stream" ? "🎧 استماع" : "⬇️ تحميل"}</span>`;
      lines += `<span style="word-break:break-all;direction:ltr;text-align:right;color:#9fc4ff;font-size:10.5px;">${esc((item.url || "").slice(0, 80))}</span>`;
      if (item.error === "cache") badges += `<span class="badge success">⚡ من الكاش</span>`;
      else if (item.error) lines += `<span style="color:#ff9ca5;">⚠️ ${esc(item.error)}</span>`;
    } else if (t === "otp") {
      title = "📱 " + esc(item.phone || "—");
      badges = `<span class="badge video">${item.action === "send" ? "📤 إرسال" : "✅ تحقق"}</span>`;
      if (item.error) lines += `<span style="color:#ff9ca5;">⚠️ ${esc(item.error)}</span>`;
    } else {
      const raw = String(item.action || "");
      const base = raw.split(":")[0];
      const isAdminAction = raw.includes(":") && ADMIN_ACTIONS[base];
      title = esc(item.username || "—");
      phone = item.phone || "—";
      badges = `<span class="badge free">${isAdminAction ? "🛠️ " + ADMIN_ACTIONS[base] : (LOGIN_ACTIONS[raw] || esc(raw))}</span>`;
      if (isAdminAction) lines += `<span style="direction:ltr;text-align:right;color:#9fc4ff;font-size:10.5px;">${esc(raw.slice(base.length + 1))}</span>`;
      if (item.error) lines += `<span style="color:#ff9ca5;">⚠️ ${esc(item.error)}</span>`;
    }

    const el = document.createElement("div");
    el.className = "card";
    el.innerHTML = `
      <div class="card-head"><div style="flex:1;min-width:0;">
        <div class="card-title">${title}</div>
        ${phone ? `<div class="card-phone">📱 ${esc(phone)}</div>` : ""}
        <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px;">${badges}<span class="badge ${st[0]}">${st[1]}</span></div>
      </div></div>
      <div class="meta-row" style="flex-direction:column;gap:4px;">
        ${lines}
        <span>🕐 ${esc(item.timestamp || "—")}${item.ip ? " · 🌐 " + esc(item.ip) : ""}</span>
      </div>`;
    container.appendChild(el);
  });
}

$("refreshHistoryBtn").addEventListener("click", loadHistory);
$("historySearch").addEventListener("input", e => {
  const q = e.target.value.trim().toLowerCase();
  const list = allHistory[currentHistoryType] || [];
  renderHistory(q ? list.filter(i => JSON.stringify(i).toLowerCase().includes(q)) : list);
});

// زر مسح السجل (endpoint /history/clear)
(function addClearBtn() {
  const b = document.createElement("button");
  b.className = "sub-tab";
  b.style.cssText = "margin-inline-start:auto;color:#ff9ca5;";
  b.textContent = "🗑️ مسح";
  b.addEventListener("click", async () => {
    if (!confirm("مسح سجل هذا القسم نهائياً؟")) return;
    try {
      await apiFetch("/history/clear", { method: "POST", body: JSON.stringify({ type: currentHistoryType }) });
      showMsg("✅ تم مسح السجل");
      loadHistory();
    } catch (e) { showMsg("❌ " + e.message, "err"); }
  });
  document.querySelector(".sub-tabs").appendChild(b);
})();

// ---------- Modal: تعديل مستخدم ----------
async function openUserModal(phone) {
  $("userModal").classList.add("active");
  $("userModalTitle").textContent = "جاري التحميل...";
  $("userModalPhone").textContent = "";
  $("userModalMeta").innerHTML = "";
  try {
    const d = await apiFetch("/user/" + encodeURIComponent(phone));
    currentEditingUser = d.user;
    if (!Object.keys(allPlans).length) await loadPlans();
    renderUserModal(d.user);
  } catch (e) {
    $("userModalTitle").textContent = "خطأ";
    $("userModalPhone").textContent = e.message;
  }
}

function renderUserModal(u) {
  $("userModalTitle").textContent = u.username || "مستخدم";
  $("userModalPhone").textContent = "📱 " + u.phone;
  const meta = [];
  if (u.created_at) meta.push(`🗓️ ${esc(u.created_at)}`);
  if (u.last_login) meta.push(`🔐 ${esc(u.last_login)}`);
  $("userModalMeta").innerHTML = meta.map(p => `<span>${p}</span>`).join("");
  $("newPlanSelect").innerHTML = Object.keys(allPlans).map(pid =>
    `<option value="${esc(pid)}" ${pid === u.plan_id ? "selected" : ""}>${esc(allPlans[pid].name)}</option>`).join("");
  $("downloadsInput").value = u.daily_downloads || 0;
  $("listensInput").value = u.monthly_listens || 0;
  $("renewalDateInput").value = u.renewal_date || "";
  $("customListenInput").value = "";
  $("customListenInput").min = -1;
  $("customListenInput").placeholder = "مثال: 200  (-1 = بلا حدود)";
}

$("saveUserBtn").addEventListener("click", async () => {
  if (!currentEditingUser) return;
  const btn = $("saveUserBtn");
  btn.textContent = "جاري الحفظ...";
  btn.disabled = true;
  try {
    const phone = encodeURIComponent(currentEditingUser.phone);
    const newPlan = $("newPlanSelect").value;
    const planChanged = newPlan !== currentEditingUser.plan_id;
    if (planChanged) {
      await apiFetch(`/user/${phone}/set-plan`, { method: "POST", body: JSON.stringify({ plan: newPlan }) });
    }

    const body = {
      daily_downloads: parseInt($("downloadsInput").value) || 0,
      monthly_listens: parseInt($("listensInput").value) || 0
    };
    // لو الباقة اتغيرت والأدمن ما لمسش التاريخ، منبعتوش (عشان السيرفر حسب تاريخ التجديد الجديد وما نكتبش فوقه بالقديم)
    const dateVal = $("renewalDateInput").value || "";
    const dateEdited = dateVal !== (currentEditingUser.renewal_date || "");
    if (!planChanged || dateEdited) body.renewal_date = dateVal;

    const custom = parseInt($("customListenInput").value);
    if (!Number.isNaN(custom)) body.listens_limit = custom;

    await apiFetch(`/user/${phone}/set-counters`, { method: "POST", body: JSON.stringify(body) });
    showMsg("✅ تم حفظ التغييرات");
    closeUserModal();
    loadUsers();
  } catch (e) {
    showMsg("❌ " + e.message, "err");
  } finally {
    btn.textContent = "حفظ التغييرات";
    btn.disabled = false;
  }
});

$("deleteUserBtn").addEventListener("click", async () => {
  if (!currentEditingUser) return;
  const u = currentEditingUser;
  if (!confirm(`هل أنت متأكد من حذف المستخدم "${u.username || u.phone}"؟\nمش هينفع نرجعه تاني.`)) return;
  const btn = $("deleteUserBtn");
  btn.textContent = "جاري الحذف...";
  btn.disabled = true;
  try {
    await apiFetch(`/user/${encodeURIComponent(u.phone)}`, { method: "DELETE" });
    showMsg("✅ تم حذف المستخدم");
    closeUserModal();
    loadUsers();
  } catch (e) {
    showMsg("❌ " + e.message, "err");
  } finally {
    btn.textContent = "🗑️ حذف المستخدم";
    btn.disabled = false;
  }
});

function closeUserModal() {
  $("userModal").classList.remove("active");
  currentEditingUser = null;
}
$("userModal").addEventListener("click", e => { if (e.target.id === "userModal") closeUserModal(); });

// ---------- Modal: الفيديو (الملفات عامة بالـ ID العشوائي 64 حرف) ----------
function openVideoModal(fileId, filename, owner, phone, type, duration, size, date) {
  const el = document.createElement(type === "audio" ? "audio" : "video");
  el.controls = true; el.autoplay = true; el.playsInline = true;
  el.src = `${SERVER_URL}/file/${encodeURIComponent(fileId)}?inline=true`;
  $("videoTitle").textContent = filename;
  $("videoPlayerSlot").replaceChildren(el);
  $("videoInfo").innerHTML = `<span>👤 ${esc(owner)}</span><span>📱 ${esc(phone)}</span><span>⏱️ ${esc(duration)}</span><span>📦 ${esc(size)} MB</span><span>🕐 ${esc(date)}</span>`;
  $("videoModal").classList.add("active");
  document.body.style.overflow = "hidden";
}
function closeVideoModal() {
  $("videoModal").classList.remove("active");
  $("videoPlayerSlot").innerHTML = "";
  document.body.style.overflow = "";
}
$("videoModal").addEventListener("click", e => { if (e.target.id === "videoModal") closeVideoModal(); });

// ---------- تحديث تلقائي ----------
function startRefresh() {
  stopRefresh();
  refreshTimer = setInterval(() => {
    if (document.hidden || !adminToken) return;
    if (document.querySelector('.tab[data-tab="users"].active')) loadUsers();
  }, 30000);
}
function stopRefresh() { if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; } }

// ---------- تشغيل ----------
function startDashboard() { loadPlans(); loadUsers(); startRefresh(); }

(async function init() {
  if (await checkAuth()) {
    $("loginScreen").classList.add("hidden");
    $("mainPanel").classList.add("show");
    $("welcomeText").textContent = "مرحباً " + adminUsername;
    startDashboard();
  } else {
    showLoginScreen();
  }
})();
