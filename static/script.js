// ==================== CSRF PROTECTION (SECURITY FIX) ====================
// Awtomatikong idinaragdag ang CSRF token (mula sa <meta name="csrf-token">
// na nasa index.html) sa bawat outgoing fetch() na papunta sa /api/ gamit
// ang POST/PUT/PATCH/DELETE. Isang beses lang itong ise-setup dito, kaya
// hindi na kailangang baguhin ang bawat individual na fetch() call sa ibaba
// — walang epekto ito sa itsura/UI, "invisible" lang na proteksyon.
(function setupCsrfProtectedFetch() {
  const originalFetch = window.fetch.bind(window);
  const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const method = ((init && init.method) || (typeof input === 'object' && input.method) || 'GET').toUpperCase();
    if (url.startsWith('/api/') && unsafeMethods.has(method)) {
      const token = document.querySelector('meta[name="csrf-token"]')?.content || '';
      init = init || {};
      init.headers = new Headers(init.headers || {});
      init.headers.set('X-CSRF-Token', token);
    }
    return originalFetch(input, init);
  };
})();

// ==================== XSS PROTECTION (SECURITY FIX) ====================
// SECURITY HOLE na natagpuan: maraming lugar sa file na ito ang direktang
// naglalagay ng user-supplied na text (hal. full name, username, payment
// reference, product/expense name) sa loob ng innerHTML gamit ang template
// literals — nang walang escaping. Ibig sabihin, puwedeng maglagay ang isang
// account ng HTML/JavaScript bilang kanyang "pangalan" (sa Register) o
// "payment reference" (sa Subscription request) o product/expense na
// pangalan, at kapag binuksan ito ng ISANG PANG user — LALO NA ang ADMIN sa
// kanyang dashboard — awtomatikong tatakbo ang script na iyon sa browser
// nila (stored XSS). Sa admin dashboard mismo, puwede itong gamitin para
// nakawin ang session/CSRF token ng admin at gumawa ng mga admin action
// (hal. mag-approve ng sariling subscription). I-tawag ang function na ito
// bago i-interpolate ang kahit anong user-controlled text sa innerHTML.
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ==================== LANGUAGE / i18n ====================
// English ang priority/default na wika ng app. Sa unang pagkakataon lang na
// makapasok ang isang bagong user sa app (kaagad pagkatapos mag-verify ng
// account, o sa unang login kung wala pa siyang napiling wika dati),
// lalabas ang language picker modal — isang beses lang ito, dahil
// naka-tanda ang pagpili sa `language_set` column sa database. Pwede pa rin
// itong baguhin anumang oras gamit ang lang-pill sa tabi ng username sa
// itaas ng app.
const TRANSLATIONS = {
  en: {
    'topbar.dashboard': 'Home dashboard',
    'nav.dashboard': 'Dashboard',
    'nav.addExpense': 'Add expense',
    'nav.income': 'Income',
    'nav.records': 'View / search records',
    'nav.reports': 'Reports',
    'nav.support': 'Customer Service',
    'nav.subscribe': 'Subscribe',
    'nav.subscriptions': 'Subscriptions',
    'nav.logout': 'Log out',
    'dash.expectedSales': 'Expected Sales',
    'dash.actualIncome': 'Actual Income',
    'dash.totalExpenses': 'Total Expenses',
    'dash.netProfit': 'Net Profit',
    'dash.addProductBtn': '+ Add Product & Expenses',
    'dash.addIncomeBtn': '+ Add Actual Income',
    'dash.recentRecords': 'Recent records',
    'dash.viewAll': 'View all',
    'dash.sessionExplainer': 'A session is used each time you add a new Product & its Expenses. Logging Actual Income is always free. Once your sessions are used up, adding new products will be locked until you subscribe.',
    'dash.pendingPricingTitle': '⚠️ Some products still need a price',
    'dash.pendingPricingSub': 'These show ₱0.00 in your sales and reports until you set their pricing.',
    'dash.setPricingBtn': 'Set pricing',
    'auth.email': 'Email',
    'auth.password': 'Password',
    'auth.show': 'SHOW',
    'auth.hide': 'HIDE',
    'auth.forgotPassword': 'Forgot password?',
    'auth.logIn': 'Log in',
    'auth.noAccount': "Don't have an account?",
    'auth.registerHere': 'Register here',
  },
  tl: {
    'topbar.dashboard': 'Home dashboard',
    'nav.dashboard': 'Dashboard',
    'nav.addExpense': 'Magdagdag ng gastos',
    'nav.income': 'Kita',
    'nav.records': 'Tingnan / hanapin ang records',
    'nav.reports': 'Mga Ulat',
    'nav.support': 'Customer Service',
    'nav.subscribe': 'Mag-subscribe',
    'nav.subscriptions': 'Mga Subscription',
    'nav.logout': 'Mag-log out',
    'dash.expectedSales': 'Inaasahang Benta',
    'dash.actualIncome': 'Aktwal na Kita',
    'dash.totalExpenses': 'Kabuuang Gastos',
    'dash.netProfit': 'Netong Kita',
    'dash.addProductBtn': '+ Magdagdag ng Produkto at Gastos',
    'dash.addIncomeBtn': '+ Magdagdag ng Aktwal na Kita',
    'dash.recentRecords': 'Kamakailang mga record',
    'dash.viewAll': 'Tingnan lahat',
    'auth.email': 'Email',
    'auth.password': 'Password',
    'auth.show': 'IPAKITA',
    'auth.hide': 'ITAGO',
    'auth.forgotPassword': 'Nakalimutan ang password?',
    'auth.logIn': 'Mag-log in',
    'auth.noAccount': 'Wala ka pang account?',
    'auth.registerHere': 'Magrehistro dito',
    'dash.pendingPricingTitle': '⚠️ May mga produktong kailangan pa ng presyo',
    'dash.pendingPricingSub': "Nagpapakita ang mga ito ng \u20b10.00 sa benta at reports mo hangga't hindi mo naitatakda ang presyo nila.",
    'dash.setPricingBtn': 'Itakda ang presyo',
  },
};
let currentLanguage = localStorage.getItem('harvestly_lang') || 'en';

function applyLanguage(lang) {
  if (!TRANSLATIONS[lang]) lang = 'en';
  currentLanguage = lang;
  localStorage.setItem('harvestly_lang', lang);
  const dict = TRANSLATIONS[lang];
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) el.textContent = dict[key];
  });
  const pillLabel = document.getElementById('lang-pill-label');
  const adminPillLabel = document.getElementById('admin-lang-pill-label');
  const label = lang === 'tl' ? 'TL' : 'EN';
  if (pillLabel) pillLabel.textContent = label;
  if (adminPillLabel) adminPillLabel.textContent = label;
  document.querySelectorAll('.lang-choice-btn').forEach(btn => {
    btn.classList.toggle('selected', btn.dataset.lang === lang);
  });
  document.documentElement.setAttribute('lang', lang);
}

// Ise-save sa backend (naka-link sa account, hindi lang sa browser) ang
// napiling wika, tapos i-a-apply agad sa buong UI.
async function saveLanguagePreference(lang) {
  applyLanguage(lang);
  try {
    await fetch('/api/language', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language: lang })
    });
  } catch (e) {
    // Hindi kritikal — naka-apply na naman agad sa UI kahit mabigo ang save;
    // susubukan na lang ulit ma-persist sa susunod na pagpili/refresh.
  }
}

function openLanguageModal() {
  document.getElementById('language-modal-backdrop')?.classList?.add('active');
}
function closeLanguageModal() {
  document.getElementById('language-modal-backdrop')?.classList?.remove('active');
}
document.querySelectorAll('.lang-choice-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    saveLanguagePreference(btn.dataset.lang);
    closeLanguageModal();
  });
});
document.getElementById('btn-lang-switch')?.addEventListener('click', openLanguageModal);
document.getElementById('btn-admin-lang-switch')?.addEventListener('click', openLanguageModal);
// I-a-apply agad ang naka-cache na wika (kung meron) bago pa man mag-login,
// para tama na rin ang tingin ng splash/auth screens.
applyLanguage(currentLanguage);

// ==================== SLIDESHOW & PASSWORD TOGGLE ====================
function startSlideshow() {
  const splashSlides = document.querySelectorAll('.splash-farmbg .cornfield-bg-img');
  const authSlides = document.querySelectorAll('.auth-farmbg .cornfield-bg-img');
  setInterval(() => {
    splashSlides.forEach(slide => slide?.classList?.toggle('active-slide'));
    authSlides.forEach(slide => slide?.classList?.toggle('active-slide'));
  }, 5000);
}
startSlideshow();
document.querySelectorAll('.toggle-password-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const targetId = btn.getAttribute('data-target');
    const input = document.getElementById(targetId);
    if (input) {
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'HIDE';
      } else {
        input.type = 'password';
        btn.textContent = 'SHOW';
      }
    }
  });
});
// Avatar picker (Register) — simple preset selection, no upload needed
const avatarOptionBtns = document.querySelectorAll('.avatar-option');
avatarOptionBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    avatarOptionBtns.forEach(b => { b.classList.remove('selected'); b.setAttribute('aria-pressed', 'false'); });
    btn.classList.add('selected');
    btn.setAttribute('aria-pressed', 'true');
    selectedAvatar = btn.dataset.avatar;
  });
});
function resetAvatarPicker() {
  if (!avatarOptionBtns.length) return;
  avatarOptionBtns.forEach(b => { b.classList.remove('selected'); b.setAttribute('aria-pressed', 'false'); });
  avatarOptionBtns[0].classList.add('selected');
  avatarOptionBtns[0].setAttribute('aria-pressed', 'true');
  selectedAvatar = avatarOptionBtns[0].dataset.avatar;
}
function clearAuthFields() {
  const formLogin = document.getElementById('form-login');
  const formSignup = document.getElementById('form-signup');
  const formVerify = document.getElementById('form-verify');
  const formForgot = document.getElementById('form-forgot');
  const formReset = document.getElementById('form-reset');
  if (formLogin) formLogin.reset();
  if (formSignup) formSignup.reset();
  if (formVerify) formVerify.reset();
  if (formForgot) formForgot.reset();
  if (formReset) formReset.reset();
  const ids = ['login-identifier', 'login-password', 'signup-name', 'signup-username', 'signup-contact', 'signup-password', 'signup-confirm',
    'verify-email', 'verify-code', 'forgot-email', 'reset-email', 'reset-code', 'reset-new-password', 'reset-confirm-password'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const errIds = ['login-error', 'signup-error', 'verify-error', 'forgot-error', 'reset-error'];
  errIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
  });
  const infoIds = ['login-info', 'verify-info', 'forgot-info', 'reset-info'];
  infoIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
  });
  const verifyEmailDisplay = document.getElementById('verify-email-display');
  if (verifyEmailDisplay) verifyEmailDisplay.textContent = '-';
  const resetEmailDisplay = document.getElementById('reset-email-display');
  if (resetEmailDisplay) resetEmailDisplay.textContent = '-';
  const passInputs = ['login-password', 'signup-password', 'signup-confirm', 'reset-new-password', 'reset-confirm-password'];
  passInputs.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.type = 'password';
  });
  document.querySelectorAll('.toggle-password-btn').forEach(b => b.textContent = 'SHOW');
  resetAvatarPicker();
}
// Ipinapakita ang isang partikular na auth panel (login/signup/verify/forgot/reset)
// at itinatago ang lahat ng iba pa. Ginagamit ng mga auth-switch-link (via
// data-tab) at ng mga JS flow sa ibaba (hal. pagkatapos mag-signup gamit ng email).
function showAuthPanel(tab) {
  if (!tab) return;
  const panel = document.querySelector(`.auth-form[data-panel="${tab}"]`);
  if (!panel) return;
  document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
  panel.classList.add('active');
}
// ==================== GLOBAL VARIABLES ====================
let currentUser = null;
let currentRole = 'farmer';
let currentAvatar = '🌾';
let selectedAvatar = '🌾'; // avatar currently picked on the signup form
let usageStatus = { subscriptionStatus: 'free', cycleCount: 0, cycleLimit: 3, purchasedCycles: 0, totalAllowed: 3, locked: false, cycleProgress: { hasProduct: false, hasExpense: false, hasIncome: false } };
let selectedPlan = null; // plan key currently picked in the GCash plan picker
let records = [];
let actualIncomeHistory = [];
let currentActualIncome = 0;
let activeViewTab = 'produce';
let lastSavedType = 'produce'; // To handle dynamic modal buttons
// ==================== MONTH HELPERS ====================
const productsByMonthCache = new Map();

function rebuildProductsByMonthCache() {
  productsByMonthCache.clear();

  for (const record of records) {
    if (record.type !== 'produce') {
      continue;
    }

    const month = getMonthKey(record.date);

    if (!month) {
      continue;
    }

    if (!productsByMonthCache.has(month)) {
      productsByMonthCache.set(month, new Set());
    }

    productsByMonthCache.get(month).add(record.name);
  }
}

function getProductsForMonth(dateStr) {
  const monthKey = getMonthKey(dateStr);

  if (!monthKey) {
    return 'General Farm Income';
  }

  const products = productsByMonthCache.get(monthKey);

  if (!products || products.size === 0) {
    return 'General Farm Income';
  }

  return [...products].join(', ');
}
// Safe Element Selectors
const screenSplash = document.getElementById('screen-splash');
const screenAuth = document.getElementById('screen-auth');
const appShell = document.getElementById('app-shell');
const adminShell = document.getElementById('admin-shell');
const sidebar = document.getElementById('sidebar');
// Splash Enter Event
const btnSplashEnter = document.getElementById('btn-splash-enter');
if (btnSplashEnter) {
  btnSplashEnter.addEventListener('click', () => {
    clearAuthFields();
    screenSplash?.classList?.remove('active');
    screenAuth?.classList?.add('active');
  });
}
// About Us screen (accessible mula splash o auth, babalik sa pinanggalingan)
const screenAbout = document.getElementById('screen-about');
let aboutCameFrom = 'splash';
const btnAboutSplash = document.getElementById('btn-about-splash');
if (btnAboutSplash) {
  btnAboutSplash.addEventListener('click', () => {
    aboutCameFrom = 'splash';
    screenSplash?.classList?.remove('active');
    screenAbout?.classList?.add('active');
  });
}
const btnAboutAuth = document.getElementById('btn-about-auth');
if (btnAboutAuth) {
  btnAboutAuth.addEventListener('click', () => {
    aboutCameFrom = 'auth';
    screenAuth?.classList?.remove('active');
    screenAbout?.classList?.add('active');
  });
}
// Lahat ng back control sa About Us screen (icon sa taas + pill sa ibaba)
function goBackFromAbout() {
  screenAbout?.classList?.remove('active');
  if (aboutCameFrom === 'auth') screenAuth?.classList?.add('active');
  else screenSplash?.classList?.add('active');
}
document.querySelectorAll('.js-about-back').forEach(btn => {
  btn.addEventListener('click', goBackFromAbout);
});
// Escape key = back din, para mabilis lumabas sa About Us
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && screenAbout?.classList?.contains('active')) goBackFromAbout();
});
// Auth Switch Links (Login / Signup / Verify / Forgot / Reset Toggle)
// Tandaan: hindi lahat ng .auth-switch-link ay panel-switcher (hal. ang
// "Resend code" button ay may sarili niyang handler sa baba) — kaya kung
// walang data-tab ang na-click, wala itong ginagawa dito.
document.querySelectorAll('.auth-switch-link').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const tab = e.target.dataset.tab;
    if (!tab) return;
    showAuthPanel(tab);
  });
});
// ==================== AUTHENTICATION ====================
const formLogin = document.getElementById('form-login');
if (formLogin) {
  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const userVal = document.getElementById('login-identifier')?.value.trim() || '';
    const passVal = document.getElementById('login-password')?.value.trim() || '';
    const err = document.getElementById('login-error');
    if (!userVal || !passVal) {
      if (err) { err.textContent = 'Please enter your email and password.'; err.hidden = false; }
      return;
    }
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: userVal, password: passVal })
      });
      const data = await response.json();
      if (response.ok) {
        if (err) err.hidden = true;
        await enterAppAfterAuth(data);
      } else if (data.requiresVerification) {
        // Tama ang password pero hindi pa verified ang email — nagpadala na
        // ang backend ng verification code, ipakita na lang ang verify panel.
        if (err) err.hidden = true;
        const verifyEmailInput = document.getElementById('verify-email');
        const verifyEmailDisplay = document.getElementById('verify-email-display');
        const verifyInfo = document.getElementById('verify-info');
        if (verifyEmailInput) verifyEmailInput.value = data.email || '';
        if (verifyEmailDisplay) verifyEmailDisplay.textContent = data.email || '';
        if (verifyInfo) { verifyInfo.textContent = 'Kailangan mo munang i-verify ang email mo. Ipinadala ang code doon.'; verifyInfo.hidden = false; }
        showAuthPanel('verify');
      } else {
        if (err) { err.textContent = data.error || 'Invalid credentials.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server. Make sure app.py is running.'; err.hidden = false; }
    }
  });
}
const formSignup = document.getElementById('form-signup');
if (formSignup) {
  formSignup.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('signup-name')?.value.trim() || '';
    const userVal = document.getElementById('signup-username')?.value.trim() || '';
    const contactVal = document.getElementById('signup-contact')?.value.trim() || '';
    const passVal = document.getElementById('signup-password')?.value.trim() || '';
    const confirmVal = document.getElementById('signup-confirm')?.value.trim() || '';
    const err = document.getElementById('signup-error');
    if (!name || !userVal || !contactVal || !passVal) {
      if (err) { err.textContent = 'Please complete all fields.'; err.hidden = false; }
      return;
    }
    if (passVal !== confirmVal) {
      if (err) { err.textContent = 'Passwords do not match.'; err.hidden = false; }
      return;
    }
    try {
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, username: userVal, contact: contactVal, password: passVal, avatar: selectedAvatar })
      });
      const data = await response.json();
      if (response.ok && data.requiresVerification) {
        // Email ang ginamit sa Register — kailangan munang i-verify bago
        // makapasok sa app. Ipinadala na ng backend ang code.
        if (err) err.hidden = true;
        const verifyEmailInput = document.getElementById('verify-email');
        const verifyEmailDisplay = document.getElementById('verify-email-display');
        const verifyInfo = document.getElementById('verify-info');
        if (verifyEmailInput) verifyEmailInput.value = data.email || '';
        if (verifyEmailDisplay) verifyEmailDisplay.textContent = data.email || '';
        if (verifyInfo) { verifyInfo.textContent = 'Nagawa ang account! Ipinadala ang verification code sa email mo.'; verifyInfo.hidden = false; }
        showAuthPanel('verify');
      } else if (response.ok) {
        currentUser = data.username;
        currentAvatar = data.avatar || selectedAvatar;
        if (err) err.hidden = true;
        screenAuth?.classList?.remove('active');
        appShell?.classList?.add('active');
        const topbarUser = document.getElementById('topbar-username');
        if (topbarUser) topbarUser.textContent = currentUser;
        const topbarAvatar = document.getElementById('topbar-avatar');
        if (topbarAvatar) topbarAvatar.textContent = currentAvatar;
        initApp();
        await fetchUserDataFromBackend();
      } else {
        if (err) { err.textContent = data.error || 'Registration failed.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server.'; err.hidden = false; }
    }
  });
}
// ==================== EMAIL VERIFICATION ====================
// ==================== ONBOARDING TUTORIAL ====================
// Lalabas lang ito nang isang beses, kaagad pagkatapos matagumpay na
// mag-verify ang isang bagong account (tingnan ang tawag sa
// startOnboardingTutorial() sa loob ng form-verify submit handler sa
// itaas). Hindi ito lumalabas sa ordinaryong pag-login o session
// restore. Kada hakbang, dinadala rin nito ang user sa aktwal na
// screen na inilalarawan, may dim overlay lang sa ibabaw, kaya
// nakikita pa rin ang tunay na dashboard/form/report sa likod.
const TUTORIAL_STEPS = [
  {
    screen: 'dashboard',
    title: 'Dashboard',
    body: 'Dito mo makikita ang buod ng iyong ani: Expected Sales, Actual Income, Total Expenses, at Net Profit. May mabilisang buttons din dito para diretsong makapagdagdag ng produkto o ng aktwal na kita.',
    icon: '<rect x="3" y="3" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/><rect x="13" y="3" width="8" height="5" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/><rect x="13" y="10" width="8" height="11" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/><rect x="3" y="13" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/>'
  },
  {
    screen: 'add-expense',
    title: 'Add Expenses',
    body: 'Dito mo itatala ang bagong produce/ani mo kasama ang mga gastos na ginamit — hal. binhi, abono, o labor. Ang bawat produkto na naitala dito ay maaari mong i-link sa mga gastos nito.',
    icon: '<path d="M12 3v18M3 12h18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>'
  },
  {
    screen: 'actual-income',
    title: 'Add Income',
    body: 'Kapag nabenta na ang ani mo, dito mo ilalagay ang aktwal na natanggap mong kita. Awtomatiko itong ikukumpara sa computed/expected na kita batay sa mga naitala mong produkto at gastos.',
    icon: '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>'
  },
  {
    screen: 'records',
    title: 'View / Search Records',
    body: 'Kumpletong listahan ito ng lahat ng naitala mong produkto at gastos. Gamitin ang search para mabilis mahanap ang isang partikular na record.',
    icon: '<circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M20 20l-5-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>'
  },
  {
    screen: 'reports',
    title: 'Reports',
    body: 'Makikita dito ang buwanang buod ng benta, gastos, at kita, kasama ang breakdown per kategorya at per produkto — plus graph para mas madaling makita ang trend.',
    icon: '<path d="M4 20V10M11 20V4M18 20v-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>'
  },
  {
    screen: 'support',
    title: 'Customer Service',
    body: 'May tanong o concern ka ba tungkol sa app o account mo? Ipadala dito ang mensahe mo — makikita ito ng admin at makikita mo rin dito ang sagot nila.',
    icon: '<path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>'
  },
  {
    screen: 'subscribe',
    title: 'Subscribe',
    body: 'May 3 libreng sessions ka sa simula. Kapag naubos na ito, dito ka pipili ng plan at magbabayad via GCash para magpatuloy sa pagdagdag ng records.',
    icon: '<path d="M12 3l2.6 5.6 6.1.6-4.6 4.1 1.3 6-5.4-3.2-5.4 3.2 1.3-6-4.6-4.1 6.1-.6z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>'
  }
];
let tutStepIndex = 0;
let tutSkipTimer = null;

function tutClearNavHighlight() {
  document.querySelectorAll('.sidebar-nav .nav-item.tut-highlight').forEach(el => el.classList.remove('tut-highlight'));
}

function tutRenderStep() {
  const step = TUTORIAL_STEPS[tutStepIndex];
  if (!step) return;
  navigateToScreen(step.screen);
  tutClearNavHighlight();
  const navBtn = document.querySelector(`.sidebar-nav [data-screen="${step.screen}"]`);
  if (navBtn) navBtn.classList.add('tut-highlight');

  document.getElementById('tut-step-num').textContent = tutStepIndex + 1;
  document.getElementById('tut-step-total').textContent = TUTORIAL_STEPS.length;
  document.getElementById('tut-title').textContent = step.title;
  document.getElementById('tut-body').textContent = step.body;
  const iconBox = document.getElementById('tut-icon');
  if (iconBox) iconBox.innerHTML = `<svg viewBox="0 0 24 24" width="24" height="24">${step.icon}</svg>`;

  const dots = document.getElementById('tut-dots');
  if (dots) {
    dots.innerHTML = TUTORIAL_STEPS.map((_, i) => `<span class="${i === tutStepIndex ? 'active' : ''}"></span>`).join('');
  }

  const backBtn = document.getElementById('btn-tutorial-back');
  if (backBtn) backBtn.hidden = tutStepIndex === 0;
  const nextBtn = document.getElementById('btn-tutorial-next');
  if (nextBtn) nextBtn.textContent = (tutStepIndex === TUTORIAL_STEPS.length - 1) ? 'Tapusin' : 'Susunod';

  // 5-segundong countdown bago maging click-able ang "I-skip" — bawat
  // hakbang, nagre-reset ito para makita muna nang kaunti ang bawat screen.
  const skipBtn = document.getElementById('btn-tutorial-skip');
  const skipTimerLabel = document.getElementById('tut-skip-timer');
  if (tutSkipTimer) clearInterval(tutSkipTimer);
  let secondsLeft = 5;
  if (skipBtn) skipBtn.disabled = true;
  if (skipTimerLabel) skipTimerLabel.textContent = `(${secondsLeft})`;
  tutSkipTimer = setInterval(() => {
    secondsLeft -= 1;
    if (secondsLeft <= 0) {
      clearInterval(tutSkipTimer);
      tutSkipTimer = null;
      if (skipBtn) skipBtn.disabled = false;
      if (skipTimerLabel) skipTimerLabel.textContent = '';
    } else if (skipTimerLabel) {
      skipTimerLabel.textContent = `(${secondsLeft})`;
    }
  }, 1000);
}

function startOnboardingTutorial() {
  const overlay = document.getElementById('tutorial-overlay');
  if (!overlay) return;
  tutStepIndex = 0;
  overlay.classList.add('active');
  tutRenderStep();
}

function closeOnboardingTutorial() {
  if (tutSkipTimer) { clearInterval(tutSkipTimer); tutSkipTimer = null; }
  tutClearNavHighlight();
  document.getElementById('tutorial-overlay')?.classList?.remove('active');
  navigateToScreen('dashboard');
}

document.getElementById('btn-tutorial-next')?.addEventListener('click', () => {
  if (tutStepIndex >= TUTORIAL_STEPS.length - 1) {
    closeOnboardingTutorial();
    return;
  }
  tutStepIndex += 1;
  tutRenderStep();
});
document.getElementById('btn-tutorial-back')?.addEventListener('click', () => {
  if (tutStepIndex <= 0) return;
  tutStepIndex -= 1;
  tutRenderStep();
});
document.getElementById('btn-tutorial-skip')?.addEventListener('click', () => {
  closeOnboardingTutorial();
});

async function enterAppAfterAuth(data, opts) {
  opts = opts || {};
  currentUser = data.username;
  currentRole = data.role || 'farmer';
  currentAvatar = data.avatar || '🌾';
  // Gamitin ang wikang naka-save sa account (kung meron); kung wala pa
  // itong na-e-explicit na napili (bagong account), ipapakita ang picker
  // na ito isang beses lang — hanggang hindi pumipili ang user, English
  // (default) muna ang gagamitin.
  applyLanguage(data.language || currentLanguage || 'en');
  screenSplash?.classList?.remove('active');
  screenAuth?.classList?.remove('active');
  if (currentRole === 'admin') {
    await enterAdminApp();
    if (!data.languageSet) openLanguageModal();
    return;
  }
  appShell?.classList?.add('active');
  const topbarUser = document.getElementById('topbar-username');
  if (topbarUser) topbarUser.textContent = currentUser;
  const topbarAvatar = document.getElementById('topbar-avatar');
  if (topbarAvatar) topbarAvatar.textContent = currentAvatar;
  initApp();
  await fetchUserDataFromBackend();
  if (opts.showTutorial) startOnboardingTutorial();
  if (!data.languageSet) openLanguageModal();
}
// BAGO: "stay logged in" check. Tinatawag ito sa unang pag-load ng page
// (tingnan ang pagtawag dito sa ibaba) para malaman kung may valid session
// pa mula noong huling pag-login (hal. nag-refresh lang o binuksan ulit ang
// tab) — kasama na rito ang admin, para hindi na "nawawala"/nababalik sa
// login screen ang admin dashboard sa bawat refresh. Kung walang session,
// wala itong ginagawa — mananatiling naka-splash screen gaya ng dati.
async function restoreSessionIfAny() {
  try {
    const res = await fetch('/api/me');
    const data = await res.json();
    if (data && data.loggedIn) {
      await enterAppAfterAuth(data);
    }
  } catch (e) {
    // Walang session o hindi ma-reach ang server — normal lang, mananatili
    // sa splash screen gaya ng dati, walang epekto sa user.
  }
}
restoreSessionIfAny();
const formVerify = document.getElementById('form-verify');
if (formVerify) {
  formVerify.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('verify-email')?.value.trim() || '';
    const code = document.getElementById('verify-code')?.value.trim() || '';
    const err = document.getElementById('verify-error');
    const info = document.getElementById('verify-info');
    if (!email || !code) {
      if (err) { err.textContent = 'Ilagay ang verification code.'; err.hidden = false; }
      return;
    }
    try {
      const response = await fetch('/api/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code })
      });
      const data = await response.json();
      if (response.ok) {
        if (err) err.hidden = true;
        if (info) info.hidden = true;
        await enterAppAfterAuth(data, { showTutorial: true });
      } else {
        if (info) info.hidden = true;
        if (err) { err.textContent = data.error || 'Hindi na-verify ang email.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server.'; err.hidden = false; }
    }
  });
}
const btnResendCode = document.getElementById('btn-resend-code');
if (btnResendCode) {
  btnResendCode.addEventListener('click', async () => {
    const email = document.getElementById('verify-email')?.value.trim() || '';
    const err = document.getElementById('verify-error');
    const info = document.getElementById('verify-info');
    if (!email) return;
    try {
      const response = await fetch('/api/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await response.json();
      if (response.ok) {
        if (err) err.hidden = true;
        if (info) { info.textContent = data.message || 'Naipadala ang bagong code.'; info.hidden = false; }
      } else {
        if (info) info.hidden = true;
        if (err) { err.textContent = data.error || 'Hindi ma-resend ang code.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server.'; err.hidden = false; }
    }
  });
}
// ==================== FORGOT PASSWORD ====================
const formForgot = document.getElementById('form-forgot');
if (formForgot) {
  formForgot.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('forgot-email')?.value.trim() || '';
    const err = document.getElementById('forgot-error');
    const info = document.getElementById('forgot-info');
    if (!email) {
      if (err) { err.textContent = 'Ilagay ang email mo.'; err.hidden = false; }
      return;
    }
    try {
      const response = await fetch('/api/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: email })
      });
      const data = await response.json();
      if (response.ok) {
        if (err) err.hidden = true;
        const resetEmailInput = document.getElementById('reset-email');
        const resetEmailDisplay = document.getElementById('reset-email-display');
        const resetInfo = document.getElementById('reset-info');
        if (resetEmailInput) resetEmailInput.value = email;
        if (resetEmailDisplay) resetEmailDisplay.textContent = email;
        if (resetInfo) { resetInfo.textContent = data.message || 'Kung may account, naipadala ang reset code.'; resetInfo.hidden = false; }
        showAuthPanel('reset');
      } else {
        if (err) { err.textContent = data.error || 'Hindi maipadala ang reset code.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server.'; err.hidden = false; }
    }
  });
}
const formReset = document.getElementById('form-reset');
if (formReset) {
  formReset.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('reset-email')?.value.trim() || '';
    const code = document.getElementById('reset-code')?.value.trim() || '';
    const newPassword = document.getElementById('reset-new-password')?.value.trim() || '';
    const confirmPassword = document.getElementById('reset-confirm-password')?.value.trim() || '';
    const err = document.getElementById('reset-error');
    const info = document.getElementById('reset-info');
    if (!email || !code || !newPassword) {
      if (err) { err.textContent = 'Kumpletuhin ang lahat ng fields.'; err.hidden = false; }
      return;
    }
    if (newPassword !== confirmPassword) {
      if (err) { err.textContent = 'Hindi magkatugma ang password.'; err.hidden = false; }
      return;
    }
    try {
      const response = await fetch('/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, newPassword })
      });
      const data = await response.json();
      if (response.ok) {
        if (err) err.hidden = true;
        clearAuthFields();
        showAuthPanel('login');
        const loginInfo = document.getElementById('login-info');
        const loginIdentifier = document.getElementById('login-identifier');
        if (loginIdentifier) loginIdentifier.value = email;
        if (loginInfo) { loginInfo.textContent = data.message || 'Na-reset na ang password mo. Mag-login ka na.'; loginInfo.hidden = false; }
      } else {
        if (info) info.hidden = true;
        if (err) { err.textContent = data.error || 'Hindi na-reset ang password.'; err.hidden = false; }
      }
    } catch (error) {
      if (err) { err.textContent = 'Cannot connect to server.'; err.hidden = false; }
    }
  });
}
const btnLogout = document.getElementById('btn-logout');
if (btnLogout) {
  btnLogout.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    appShell?.classList?.remove('active');
    screenAuth?.classList?.add('active');
    currentUser = null;
    currentRole = 'farmer';
    currentAvatar = '🌾';
    records = [];
    actualIncomeHistory = [];
    clearAuthFields();
  });
}
const btnAdminLogout = document.getElementById('btn-admin-logout');
if (btnAdminLogout) {
  btnAdminLogout.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    if (adminShell) adminShell.style.display = 'none';
    screenAuth?.classList?.add('active');
    currentUser = null;
    currentRole = 'farmer';
    currentAvatar = '🌾';
    clearAuthFields();
  });
}
// ==================== ADMIN APP ====================
async function enterAdminApp() {
  if (adminShell) adminShell.style.display = 'flex';
  const adminTopbarUser = document.getElementById('admin-topbar-username');
  if (adminTopbarUser) adminTopbarUser.textContent = currentUser;
  const adminTopbarAvatar = document.getElementById('admin-topbar-avatar');
  if (adminTopbarAvatar) adminTopbarAvatar.textContent = currentAvatar;
  // Dashboard ang unang makikita; kinukuha pa rin ang support/subscriptions
  // list para lang sa badge counts.
  await renderAdminDashboard();
  await renderAdminSupportMessages();
  await renderAdminSubscriptions();
}
const btnAdminMenu = document.getElementById('btn-admin-menu');
if (btnAdminMenu) {
  btnAdminMenu.addEventListener('click', () => {
    document.getElementById('admin-sidebar')?.classList?.toggle('open');
  });
}
// ==================== CUSTOMER SERVICE (support tickets) ====================
// Farmer side: magpadala ng concern + makita ang sariling mga naipadala na
// kasama ang reply ng admin (kung meron na).
const formSupport = document.getElementById('form-support');
if (formSupport) {
  formSupport.addEventListener('submit', async (e) => {
    e.preventDefault();
    const subjectEl = document.getElementById('support-subject');
    const messageEl = document.getElementById('support-message');
    const errEl = document.getElementById('support-error');
    const okEl = document.getElementById('support-success');
    if (errEl) errEl.hidden = true;
    if (okEl) okEl.hidden = true;
    const subject = subjectEl?.value.trim() || '';
    const message = messageEl?.value.trim() || '';
    if (!message) {
      if (errEl) { errEl.textContent = 'Kailangan ng mensahe.'; errEl.hidden = false; }
      return;
    }
    try {
      const res = await fetch('/api/support', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, message })
      });
      const data = await res.json();
      if (res.ok) {
        if (okEl) { okEl.textContent = data.message || 'Naipadala!'; okEl.hidden = false; }
        formSupport.reset();
        renderMySupportMessages();
      } else {
        if (errEl) { errEl.textContent = data.error || 'May naganap na error.'; errEl.hidden = false; }
      }
    } catch (error) {
      if (errEl) { errEl.textContent = 'Cannot connect to server.'; errEl.hidden = false; }
    }
  });
}
async function renderMySupportMessages() {
  const listEl = document.getElementById('support-list');
  if (!listEl) return;
  try {
    const res = await fetch('/api/support');
    if (!res.ok) return;
    const data = await res.json();
    const msgs = data.messages || [];
    listEl.innerHTML = '';
    if (msgs.length === 0) {
      listEl.innerHTML = '<div class="empty-state">Wala ka pang naipadalang concern.</div>';
      return;
    }
    msgs.forEach(m => {
      const item = document.createElement('div');
      item.className = 'support-item';
      const badgeClass = m.status === 'replied' ? 'admin-badge--replied' : 'admin-badge--open';
      const badgeLabel = m.status === 'replied' ? 'Replied' : 'Open';
      item.innerHTML = `
        <div class="support-item-head">
          <span class="support-item-subject">${escapeHtml(m.subject || 'Concern')}</span>
          <span class="admin-badge ${badgeClass}">${badgeLabel}</span>
        </div>
        <p class="support-item-meta">${escapeHtml(m.createdAt)}</p>
        <p class="support-item-message">${escapeHtml(m.message)}</p>
        ${m.adminReply ? `
          <div class="support-reply-box">
            <p class="support-reply-box-label">Reply from admin${m.repliedAt ? ' • ' + escapeHtml(m.repliedAt) : ''}</p>
            <p>${escapeHtml(m.adminReply)}</p>
          </div>
        ` : '<p class="empty-state" style="padding:0;">Hinihintay pa ang reply ng admin.</p>'}
      `;
      listEl.appendChild(item);
    });
  } catch (e) {
    console.error('Error loading support messages:', e);
  }
}
// Admin side: makita LAHAT ng concerns mula sa mga farmer, at sagutin ang mga
// wala pang reply.
async function renderAdminSupportMessages() {
  const listEl = document.getElementById('admin-support-list');
  const badgeEl = document.getElementById('admin-support-badge');
  if (!listEl) return;
  try {
    const res = await fetch('/api/admin/support');
    if (!res.ok) return;
    const data = await res.json();
    const msgs = data.messages || [];
    const openCount = msgs.filter(m => m.status !== 'replied').length;
    if (badgeEl) {
      if (openCount > 0) { badgeEl.textContent = openCount; badgeEl.style.display = ''; }
      else { badgeEl.style.display = 'none'; }
    }
    listEl.innerHTML = '';
    if (msgs.length === 0) {
      listEl.innerHTML = '<div class="empty-state">Wala pang natatanggap na concern.</div>';
      return;
    }
    msgs.forEach(m => {
      const item = document.createElement('div');
      item.className = 'support-item';
      const badgeClass = m.status === 'replied' ? 'admin-badge--replied' : 'admin-badge--open';
      const badgeLabel = m.status === 'replied' ? 'Replied' : 'Open';
      const replySection = m.status === 'replied'
        ? `<div class="support-reply-box">
             <p class="support-reply-box-label">Your reply${m.repliedAt ? ' • ' + escapeHtml(m.repliedAt) : ''}</p>
             <p>${escapeHtml(m.adminReply)}</p>
           </div>`
        : `<form class="support-reply-form" data-id="${m.id}">
             <textarea placeholder="I-type ang reply mo dito..." required></textarea>
             <button type="submit" class="btn btn-primary btn-sm">Send reply</button>
           </form>`;
      item.innerHTML = `
        <div class="support-item-head">
          <span class="support-item-subject">${escapeHtml(m.subject || 'Concern')} <span class="empty-state" style="padding:0;">— ${escapeHtml(m.fullName)} (${escapeHtml(m.username)})</span></span>
          <span class="admin-badge ${badgeClass}">${badgeLabel}</span>
        </div>
        <p class="support-item-meta">${escapeHtml(m.createdAt)}</p>
        <p class="support-item-message">${escapeHtml(m.message)}</p>
        ${replySection}
      `;
      listEl.appendChild(item);
    });
    listEl.querySelectorAll('.support-reply-form').forEach(form => {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const textarea = form.querySelector('textarea');
        const reply = textarea?.value.trim() || '';
        if (!reply) return;
        await fetch(`/api/admin/support/${form.dataset.id}/reply`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reply })
        });
        renderAdminSupportMessages();
      });
    });
  } catch (e) {
    console.error('Error loading admin support messages:', e);
  }
}
// ==================== ADMIN DASHBOARD ====================
// Buod ng buong sistema para sa admin: halaga ng ani, gastos, net, bilang ng
// aktibong farmer, chart kada araw, at pinakabagong talaan ng lahat ng farmer.
// Read-only lahat — galing sa /api/admin/dashboard.
let adminRangeDays = 30;

function admPeso(n) {
  const v = Number(n) || 0;
  return '\u20B1' + v.toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function admShortDate(iso) {
  if (!iso) return '\u2014';
  const d = new Date(iso + 'T00:00:00');
  if (isNaN(d)) return iso;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// Naglalagay ng "+12.5%" na pill. null = walang mapagbatayan (bago pa lang).
function admSetDelta(elId, pct, opts) {
  const el = document.getElementById(elId);
  if (!el) return;
  const invert = opts && opts.invert;   // para sa gastos: pagtaas = hindi maganda
  el.classList.remove('adm-delta--down', 'adm-delta--muted');
  if (pct === null || pct === undefined || !isFinite(pct)) {
    el.classList.add('adm-delta--muted');
    el.textContent = 'walang datos noon';
    return;
  }
  const up = pct >= 0;
  const good = invert ? !up : up;
  if (!good) el.classList.add('adm-delta--down');
  const arrow = up ? '\u2197' : '\u2198';
  el.textContent = `${arrow} ${up ? '+' : ''}${pct}% vs nakaraan`;
}

// Gumagawa ng makinis na cubic path mula sa listahan ng values.
function admLinePath(vals, max, w, top, bottom) {
  const n = vals.length;
  if (!n) return '';
  const pts = vals.map((v, i) => [
    n === 1 ? w / 2 : (i / (n - 1)) * w,
    bottom - (max > 0 ? (Number(v) || 0) / max : 0) * (bottom - top)
  ]);
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 1; i < n; i++) {
    const [x0, y0] = pts[i - 1];
    const [x1, y1] = pts[i];
    const cx = (x0 + x1) / 2;
    d += ` C${cx.toFixed(1)},${y0.toFixed(1)} ${cx.toFixed(1)},${y1.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}

function admRenderChart(series) {
  const svg = document.getElementById('adm-chart');
  const wrap = document.getElementById('adm-chart-wrap');
  if (!svg || !wrap) return;
  const old = wrap.querySelector('.adm-chart-empty');
  if (old) old.remove();

  const produce = series.map(p => p.produce);
  const expense = series.map(p => p.expense);
  const max = Math.max(0, ...produce, ...expense);

  if (!series.length || max <= 0) {
    svg.innerHTML = '';
    svg.style.display = 'none';
    const empty = document.createElement('div');
    empty.className = 'adm-chart-empty';
    empty.textContent = 'Wala pang naitalang ani o gastos sa saklaw na ito.';
    wrap.prepend(empty);
    return;
  }
  svg.style.display = 'block';

  const W = 700, TOP = 14, BOT = 186;
  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map(t => `<line x1="0" y1="${(BOT - t * (BOT - TOP)).toFixed(1)}" x2="${W}" y2="${(BOT - t * (BOT - TOP)).toFixed(1)}" stroke="#252d38" stroke-width="1" stroke-dasharray="3 5" vector-effect="non-scaling-stroke"/>`)
    .join('');

  const pPath = admLinePath(produce, max, W, TOP, BOT);
  const ePath = admLinePath(expense, max, W, TOP, BOT);
  const area = `${pPath} L${W},${BOT} L0,${BOT} Z`;

  svg.innerHTML = `
    <defs>
      <linearGradient id="admFill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#3fb950" stop-opacity="0.26"/>
        <stop offset="100%" stop-color="#3fb950" stop-opacity="0"/>
      </linearGradient>
    </defs>
    ${grid}
    <path d="${area}" fill="url(#admFill)" stroke="none"/>
    <path d="${ePath}" fill="none" stroke="#e8a33d" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="5 4" vector-effect="non-scaling-stroke"/>
    <path d="${pPath}" fill="none" stroke="#3fb950" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>
  `;
}

function admRenderActivity(rows) {
  const box = document.getElementById('adm-activity');
  if (!box) return;
  if (!rows || !rows.length) {
    box.innerHTML = '<p class="adm-empty">Wala pang naitalang record ang mga farmer.</p>';
    return;
  }
  const labels = { produce: 'Ani', expense: 'Gastos', income: 'Kita' };
  box.innerHTML = rows.map(r => `
    <div class="adm-row">
      <span class="adm-avatar">${escapeHtml(r.avatar || '\u{1F33E}')}</span>
      <span class="adm-row-name">${escapeHtml(r.farmer || 'Unknown')}<small>${escapeHtml(r.item || '\u2014')}</small></span>
      <span class="adm-row-date">${escapeHtml(admShortDate(r.date))}</span>
      <span class="adm-row-amt">${admPeso(r.amount)}</span>
      <span class="adm-tag adm-tag--${r.type}">${labels[r.type] || 'Record'}</span>
    </div>
  `).join('');
}

async function renderAdminDashboard() {
  try {
    const res = await fetch(`/api/admin/dashboard?range=${adminRangeDays}`);
    if (!res.ok) return;
    const d = await res.json();
    if (d.error) return;

    const nameEl = document.getElementById('adm-greet-name');
    if (nameEl) nameEl.textContent = currentUser || 'Admin';

    const periodEl = document.getElementById('adm-period');
    if (periodEl) {
      periodEl.textContent = `Buod ng huling ${d.rangeDays} araw \u2022 ${admShortDate(d.periodStart)} \u2013 ${admShortDate(d.periodEnd)}`;
    }

    document.getElementById('adm-produce').textContent = admPeso(d.produceValue);
    document.getElementById('adm-expense').textContent = admPeso(d.expenses);
    document.getElementById('adm-net').textContent = admPeso(d.netValue);
    document.getElementById('adm-active').textContent = d.activeFarmers;
    document.getElementById('adm-logged').textContent = d.produceLogged;
    document.getElementById('adm-concerns').textContent = d.openConcerns;

    admSetDelta('adm-produce-delta', d.produceChange);
    admSetDelta('adm-active-delta', d.activeFarmersChange);
    admSetDelta('adm-logged-delta', d.produceLoggedChange);

    const concernNote = document.getElementById('adm-concerns-note');
    if (concernNote) {
      concernNote.classList.remove('adm-delta--muted', 'adm-delta--warn');
      if (d.openConcerns > 0) {
        concernNote.classList.add('adm-delta--warn');
        concernNote.textContent = 'kailangan ng sagot';
      } else {
        concernNote.classList.add('adm-delta--muted');
        concernNote.textContent = `${d.totalConcerns} total \u2022 sagot na lahat`;
      }
    }

    const farmersNote = document.getElementById('adm-farmers-note');
    if (farmersNote) {
      const rating = d.avgRating ? ` \u2022 \u2605 ${d.avgRating} avg rating` : '';
      farmersNote.textContent = `${d.totalFarmers} farmer \u2022 ${d.subscribedFarmers} may bayad na session${rating}`;
    }

    const axis = d.chart || [];
    if (axis.length) {
      document.getElementById('adm-axis-start').textContent = admShortDate(axis[0].date);
      document.getElementById('adm-axis-mid').textContent = admShortDate(axis[Math.floor(axis.length / 2)].date);
      document.getElementById('adm-axis-end').textContent = admShortDate(axis[axis.length - 1].date);
    }
    admRenderChart(axis);
    admRenderActivity(d.activity);
  } catch (e) {
    console.error('Error loading admin dashboard:', e);
  }
}

// Range toggle (7d / 30d / 90d)
document.querySelectorAll('.adm-range-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.adm-range-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    adminRangeDays = parseInt(btn.dataset.range, 10) || 30;
    renderAdminDashboard();
  });
});

const btnAdminNavDashboard = document.getElementById('btn-admin-nav-dashboard');
if (btnAdminNavDashboard) {
  btnAdminNavDashboard.addEventListener('click', () => {
    document.getElementById('admin-sidebar')?.classList?.remove('open');
    document.querySelectorAll('#admin-sidebar .nav-item').forEach(i => i.classList.remove('active'));
    btnAdminNavDashboard.classList.add('active');
    document.querySelectorAll('#admin-shell .main .screen').forEach(s => s.classList.remove('active'));
    document.getElementById('screen-admin-dashboard')?.classList.add('active');
    const adminTitle = document.getElementById('admin-topbar-title');
    if (adminTitle) adminTitle.textContent = 'Dashboard';
    renderAdminDashboard();
  });
}

const btnAdminNavSupport = document.getElementById('btn-admin-nav-support');
if (btnAdminNavSupport) {
  btnAdminNavSupport.addEventListener('click', () => {
    document.getElementById('admin-sidebar')?.classList?.remove('open');
    document.querySelectorAll('#admin-sidebar .nav-item').forEach(i => i.classList.remove('active'));
    btnAdminNavSupport.classList.add('active');
    document.querySelectorAll('#admin-shell .main .screen').forEach(s => s.classList.remove('active'));
    document.getElementById('screen-admin-support')?.classList.add('active');
    const adminTitle = document.getElementById('admin-topbar-title');
    if (adminTitle) adminTitle.textContent = 'Customer Service';
    renderAdminSupportMessages();
  });
}

const btnAdminNavSubscriptions = document.getElementById('btn-admin-nav-subscriptions');
if (btnAdminNavSubscriptions) {
  btnAdminNavSubscriptions.addEventListener('click', () => {
    document.getElementById('admin-sidebar')?.classList?.remove('open');
    document.querySelectorAll('#admin-sidebar .nav-item').forEach(i => i.classList.remove('active'));
    btnAdminNavSubscriptions.classList.add('active');
    document.querySelectorAll('#admin-shell .main .screen').forEach(s => s.classList.remove('active'));
    document.getElementById('screen-admin-subscriptions')?.classList.add('active');
    const adminTitle = document.getElementById('admin-topbar-title');
    if (adminTitle) adminTitle.textContent = 'Subscriptions';
    renderAdminSubscriptions();
  });
}

// ADMIN: Subscriptions review — dito na-close ang loophole na dating
// awtomatikong na-a-approve ang kahit anong self-reported na GCash
// reference number. Titingnan muna ng admin ang bawat request, susuriin
// ang payment reference, bago mag-approve o mag-reject.
async function renderAdminSubscriptions() {
  const listEl = document.getElementById('admin-subscriptions-list');
  const badgeEl = document.getElementById('admin-subscriptions-badge');
  if (!listEl) return;
  try {
    const res = await fetch('/api/admin/subscriptions');
    if (!res.ok) return;
    const data = await res.json();
    const reqs = data.requests || [];
    const pendingCount = reqs.filter(r => r.status === 'pending').length;
    if (badgeEl) {
      if (pendingCount > 0) { badgeEl.textContent = pendingCount; badgeEl.style.display = ''; }
      else { badgeEl.style.display = 'none'; }
    }
    listEl.innerHTML = '';
    if (reqs.length === 0) {
      listEl.innerHTML = '<div class="empty-state">Wala pang subscription requests.</div>';
      return;
    }
    const statusLabels = { pending: 'Pending', approved: 'Approved', rejected: 'Rejected' };
    const statusClass = { pending: 'admin-badge--pending', approved: 'admin-badge--approved', rejected: 'admin-badge--rejected' };
    reqs.forEach(r => {
      const item = document.createElement('div');
      item.className = 'support-item';
      const actions = r.status === 'pending'
        ? `<div class="sub-review-actions">
             <button type="button" class="btn btn-primary btn-sm" data-action="approve" data-id="${r.id}">Approve</button>
             <button type="button" class="btn btn-outline btn-sm" data-action="reject" data-id="${r.id}">Reject</button>
           </div>`
        : '';
      item.innerHTML = `
        <div class="support-item-head">
          <span class="support-item-subject">${escapeHtml(r.plan || '-')} — ${escapeHtml(r.sessionsGranted)} sessions <span class="empty-state" style="padding:0;">— ${escapeHtml(r.fullName)} (${escapeHtml(r.username)})</span></span>
          <span class="admin-badge ${statusClass[r.status] || ''}">${statusLabels[r.status] || r.status}</span>
        </div>
        <p class="support-item-meta">Requested: ${escapeHtml(r.requestedAt)}${r.reviewedAt ? ' • Reviewed: ' + escapeHtml(r.reviewedAt) : ''}</p>
        <p class="support-item-message">GCash reference: <strong>${escapeHtml(r.paymentReference || '-')}</strong> — i-verify ito laban sa aktwal na GCash transaction history bago i-approve.</p>
        ${actions}
      `;
      listEl.appendChild(item);
    });
    listEl.querySelectorAll('[data-action="approve"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Kumpirmado mo bang na-verify mo na ang GCash reference number na ito at totoo ang bayad?')) return;
        const res2 = await fetch(`/api/admin/subscriptions/${btn.dataset.id}/approve`, { method: 'POST' });
        const d2 = await res2.json().catch(() => ({}));
        if (!res2.ok) alert(d2.error || 'Error sa pag-approve.');
        renderAdminSubscriptions();
      });
    });
    listEl.querySelectorAll('[data-action="reject"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Sigurado ka bang i-reject ang request na ito?')) return;
        const res2 = await fetch(`/api/admin/subscriptions/${btn.dataset.id}/reject`, { method: 'POST' });
        const d2 = await res2.json().catch(() => ({}));
        if (!res2.ok) alert(d2.error || 'Error sa pag-reject.');
        renderAdminSubscriptions();
      });
    });
  } catch (e) {
    console.error('Error loading admin subscriptions:', e);
  }
}
// ==================== FETCH DATA FROM FLASK BACKEND ====================
async function fetchUserDataFromBackend() {
  try {
    const response = await fetch('/api/data');
    if (response.ok) {
      const data = await response.json();
      records = data.records || [];
actualIncomeHistory = data.incomeHistory || [];

rebuildProductsByMonthCache();

currentRole = data.role || 'farmer';
      usageStatus = data.usage || usageStatus;
      // Dashboard "Actual Income" should reflect ALL saved income entries combined,
      // not just the most recently added one — same as Sales, Expenses, and Profit.
      currentActualIncome = actualIncomeHistory.reduce((s, r) => s + (r.amount || 0), 0);
      updateDashboard();
      renderRecords();
      renderReports();
      renderIncomeHistoryTable();
      renderIncomeMonitoringByProduct();
      initComputationDropdowns();
      updateSubscriptionUI();
      hideDataLoadErrorBanner();
    } else {
      showDataLoadErrorBanner();
    }
  } catch (error) {
    console.error("Error loading data from backend:", error);
    showDataLoadErrorBanner();
  }
}
// Kapag nabigo ang /api/data (hal. cold start ng free-tier hosting, o
// network hiccup), ipinapakita ito nang malinaw sa halip na tahimik na
// mananatiling walang laman ang Dashboard/Reports nang hindi alam ng user.
function showDataLoadErrorBanner() {
  let banner = document.getElementById('data-load-error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'data-load-error-banner';
    banner.className = 'data-load-error-banner';
    banner.innerHTML = `
      <span>Hindi na-load ang datos mo. Baka mabagal lang mag-wake up ang server — subukan ulit.</span>
      <button type="button" id="btn-retry-data-load">Subukan Ulit</button>
    `;
    document.querySelector('.main')?.prepend(banner);
    document.getElementById('btn-retry-data-load')?.addEventListener('click', () => {
      fetchUserDataFromBackend();
    });
  }
  banner.style.display = 'flex';
}
function hideDataLoadErrorBanner() {
  const banner = document.getElementById('data-load-error-banner');
  if (banner) banner.style.display = 'none';
}
// Populates dropdown list of products for the Computation & Comparison (per product) view
function populateProductSelectDropdown() {
  const selectEl = document.getElementById('comp-product-select');
  if (!selectEl) return;
  const prevVal = selectEl.value;
  const productRecords = records.filter(r => r.type === 'produce');
  const uniqueProducts = [...new Set(productRecords.map(r => r.name))];
  if (uniqueProducts.length === 0) {
    selectEl.innerHTML = '<option value="">No products recorded yet</option>';
    return;
  }
  selectEl.innerHTML = '';
  uniqueProducts.forEach(prodName => {
    const opt = document.createElement('option');
    opt.value = prodName;
    opt.textContent = prodName;
    selectEl.appendChild(opt);
  });
  if (uniqueProducts.includes(prevVal)) selectEl.value = prevVal;
}
// Populates dropdown list of months for the Computation & Comparison (per product) view
function populateMonthSelectDropdown() {
  const selectEl = document.getElementById('comp-month-select');
  if (!selectEl) return;
  const prevVal = selectEl.value;
  const allDates = [...records.map(r => r.date), ...actualIncomeHistory.map(r => r.date)].filter(Boolean);
  const uniqueMonths = [...new Set(allDates.map(getMonthKey))].sort().reverse();
  if (uniqueMonths.length === 0) {
    selectEl.innerHTML = '<option value="">No data yet</option>';
    return;
  }
  selectEl.innerHTML = '';
  uniqueMonths.forEach(mKey => {
    const opt = document.createElement('option');
    opt.value = mKey;
    opt.textContent = getMonthLabel(mKey);
    selectEl.appendChild(opt);
  });
  if (uniqueMonths.includes(prevVal)) selectEl.value = prevVal;
}
/* COMPUTATION & COMPARISON: Per Month/Product only (general totals removed) */
function initComputationDropdowns() {
  populateProductSelectDropdown();
  populateMonthSelectDropdown();
}
document.getElementById('comp-product-select')?.addEventListener('change', () => {
  const noteEl = document.getElementById('comp-prod-status-note');
  if (noteEl) noteEl.textContent = 'Select a product and month, then tap Compute to see the sales vs. expenses comparison for it.';
});
let lastComputation = null; // { label, sales, expenses, net, when }
// Per Month/Product computation: kino-compute lang pag pinindot ang "Compute" button,
// tapos ang resulta ay lumalabas sa isang popup, at siya rin ang ipinapakita sa Dashboard.
function computeProductComparison() {
  const product = document.getElementById('comp-product-select')?.value || '';
  const month = document.getElementById('comp-month-select')?.value || '';
  const enteredExp = parseFloat(document.getElementById('comp-product-expenses')?.value) || 0;
  const noteEl = document.getElementById('comp-prod-status-note');
  if (!product) {
    if (noteEl) noteEl.textContent = 'Add a farm product record first to see its comparison.';
    return null;
  }
  const matchingSales = records.filter(r => r.type === 'produce' && r.name === product && (!month || getMonthKey(r.date) === month));
  const productSales = matchingSales.reduce((s, r) => s + r.amount, 0);
  const computedNet = productSales - enteredExp;
  return {
    product,
    month,
    sales: productSales,
    expenses: enteredExp,
    net: computedNet,
  };
}
const btnComputeComparison = document.getElementById('btn-compute-comparison');
if (btnComputeComparison) {
  btnComputeComparison.addEventListener('click', () => {
    const result = computeProductComparison();
    if (!result) return;
    const monthLabel = result.month ? getMonthLabel(result.month) : 'All months';
    const subEl = document.getElementById('comp-modal-sub');
    if (subEl) subEl.textContent = `${result.product} — ${monthLabel}`;
    document.getElementById('comp-modal-sales').textContent = `₱${result.sales.toFixed(2)}`;
    document.getElementById('comp-modal-exp').textContent = `₱${result.expenses.toFixed(2)}`;
    document.getElementById('comp-modal-net').textContent = `₱${result.net.toFixed(2)}`;
    document.getElementById('computation-modal-backdrop')?.classList?.add('active');
    lastComputation = {
      label: `${result.product} — ${monthLabel}`,
      sales: result.sales,
      expenses: result.expenses,
      net: result.net,
      when: new Date().toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
    };
    renderDashboardComputation();
    const noteEl = document.getElementById('comp-prod-status-note');
    if (noteEl) noteEl.textContent = `Computed for ${result.product} (${monthLabel}). Result posted to the Dashboard.`;
  });
}
const btnCompModalClose = document.getElementById('btn-comp-modal-close');
if (btnCompModalClose) {
  btnCompModalClose.addEventListener('click', () => {
    document.getElementById('computation-modal-backdrop')?.classList?.remove('active');
  });
}
function renderDashboardComputation() {
  const panel = document.getElementById('dashboard-latest-computation-panel');
  if (!panel || !lastComputation) return;
  panel.style.display = 'block';
  document.getElementById('dash-comp-label').textContent = lastComputation.label;
  document.getElementById('dash-comp-when').textContent = lastComputation.when;
  document.getElementById('dash-comp-sales').textContent = `₱${lastComputation.sales.toFixed(2)}`;
  document.getElementById('dash-comp-exp').textContent = `₱${lastComputation.expenses.toFixed(2)}`;
  document.getElementById('dash-comp-net').textContent = `₱${lastComputation.net.toFixed(2)}`;
}
// ==================== NAVIGATION ====================
const btnMenu = document.getElementById('btn-menu');
if (btnMenu) {
  btnMenu.addEventListener('click', () => {
    sidebar?.classList?.toggle('open');
  });
}
function navigateToScreen(targetScreen) {
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(i => i.classList.remove('active'));
  const activeNav = document.querySelector(`.sidebar-nav [data-screen="${targetScreen}"]`);
  if (activeNav) activeNav.classList.add('active');
  document.querySelectorAll('.main .screen').forEach(s => s.classList.remove('active'));
  const activeScreen = document.getElementById(`screen-${targetScreen}`);
  if (activeScreen) activeScreen.classList.add('active');
  const titleMap = {
    'dashboard': 'Home dashboard',
    'actual-income': 'Income (Actual vs Computed)',
    'add-expense': 'Add Product & Expenses',
    'records': 'View / Search Records',
    'reports': 'Reports',
    'support': 'Customer Service',
    'subscribe': 'Subscribe'
  };
  const topbarTitle = document.getElementById('topbar-title');
  if (topbarTitle) topbarTitle.textContent = titleMap[targetScreen] || 'Dashboard';
  sidebar?.classList?.remove('open');
  if (targetScreen === 'actual-income') {
    initComputationDropdowns();
    renderIncomeHistoryTable();
      renderIncomeMonitoringByProduct();
  }
  if (targetScreen === 'records') renderRecords();
  if (targetScreen === 'reports') renderReports();
  if (targetScreen === 'support') renderMySupportMessages();
  // Dashboard at Reports: laging kumuha ng FRESH data mula backend sa bawat
  // pagbisita dito, hindi lang umaasa sa huling naka-cache na `records` sa
  // memory. Nililinis nito ang tsansang magkaiba ang makikita sa Dashboard/
  // Reports kumpara sa View/Search kapag na-miss ang isang naunang fetch
  // (hal. dahil sa cold start ng free-tier hosting).
  if (targetScreen === 'dashboard' || targetScreen === 'reports') {
    fetchUserDataFromBackend();
  }
  if (targetScreen === 'subscribe') {
    loadGcashInfo();
    updateSubscribeStatusText();
  }
  if (targetScreen === 'dashboard' && pendingHarvestRatingIds.length > 0) {
    const idsToRate = pendingHarvestRatingIds;
    const nameToRate = pendingHarvestRatingName;
    pendingHarvestRatingIds = [];
    openHarvestRatingPopup(idsToRate, nameToRate);
  }
}
document.querySelectorAll('[data-screen]').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const target = e.currentTarget.dataset.screen;
    navigateToScreen(target);
  });
});
function initApp() {
  const today = new Date().toISOString().split('T')[0];
  const eDate = document.getElementById('expense-date');
  const aDate = document.getElementById('actual-income-date');
  if (eDate) eDate.value = today;
  if (aDate) aDate.value = today;
  resetExpenseForm();
  updateDashboard();
  renderRecords();
  renderIncomeHistoryTable();
      renderIncomeMonitoringByProduct();
}
/* DYNAMIC EXPENSE LOGIC */
const expenseContainer = document.getElementById('expense-rows-container');
const btnAddRow = document.getElementById('btn-add-expense-row');
function createExpenseRow() {
  if (!expenseContainer) return;
  const row = document.createElement('div');
  row.className = 'expense-row';
  row.innerHTML = `
    <select class="expense-cat">
      <option value="Seeds">Seeds</option>
      <option value="Fertilizer">Fertilizer</option>
      <option value="Pesticide">Pesticide</option>
      <option value="Labor / Wages">Labor / Wages</option>
      <option value="Utilities / Fuel">Utilities / Fuel</option>
      <option value="Transportation">Transportation</option>
      <option value="Other Expenses">Others (Misc)</option>
    </select>
    <input type="text" class="expense-desc" placeholder="Details">
    <div class="expense-row-price">
      <span>₱</span>
      <input type="number" class="expense-amount" min="0" step="0.01" placeholder="0.00">
    </div>
    <button type="button" class="btn-remove-row" title="Delete row">×</button>
  `;
  row.querySelector('.expense-amount')?.addEventListener('input', calculateTotalExpenseInput);
  row.querySelector('.btn-remove-row')?.addEventListener('click', () => {
    if (expenseContainer.children.length > 1) {
      row.remove();
      calculateTotalExpenseInput();
    } else {
      alert("At least one expense row is required.");
    }
  });
  expenseContainer.appendChild(row);
}
function resetExpenseForm() {
  if (!expenseContainer) return;
  expenseContainer.innerHTML = '';
  createExpenseRow();
  calculateTotalExpenseInput();
}
if (btnAddRow) {
  btnAddRow.addEventListener('click', () => {
    createExpenseRow();
  });
}
function calculateTotalExpenseInput() {
  let total = 0;

  if (!expenseContainer) {
    return 0;
  }

  for (const input of expenseContainer.querySelectorAll('.expense-amount')) {
    total += Number.parseFloat(input.value) || 0;
  }

  const totalDisplay = document.getElementById('expense-calculated-total');

  if (totalDisplay) {
    totalDisplay.textContent = `₱${total.toFixed(2)}`;
  }

  return total;
}
/* ACTUAL INCOME MONITORING LOGIC */
/* MODAL / ALERT NOTIFICATION HANDLER */
function showSuccessModal(title, subMessage, recordItem) {
  const backdrop = document.getElementById('modal-backdrop');
  lastSavedType = recordItem.type || 'produce';
  if (backdrop) {
    const elTitle = document.getElementById('modal-title');
    const elSub = document.getElementById('modal-sub');
    const elName = document.getElementById('modal-sum-name');
    const elDate = document.getElementById('modal-sum-date');
    const amountEl = document.getElementById('modal-sum-amount');
    const btnAddAnother = document.getElementById('btn-modal-add-another');
    if (elTitle) elTitle.textContent = title;
    if (elSub) elSub.textContent = subMessage;
    if (elName) elName.textContent = recordItem.name;
    if (elDate) elDate.textContent = recordItem.date;
    if (amountEl) {
      amountEl.className = 'modal-summary-val ' + (recordItem.type === 'expense' ? 'amount-exp' : 'amount-prod');
      amountEl.textContent = `${recordItem.type === 'expense' ? '-' : '+'}₱${recordItem.amount.toFixed(2)}`;
    }
    if (btnModalView) {
      btnModalView.textContent = lastSavedType === 'income' ? 'View Dashboard' : 'View Records';
    }
    if (btnAddAnother) {
      if (lastSavedType === 'expense') {
        btnAddAnother.textContent = '+ Add Another Expense';
      } else if (lastSavedType === 'income') {
        btnAddAnother.textContent = '+ Add Another Income';
      } else {
        btnAddAnother.textContent = '+ Add Another Product & Expenses';
      }
    }
    backdrop.classList.add('active');
  } else {
    alert(`SUCCESS: ${title}\n${subMessage}\nAmount: ₱${recordItem.amount.toFixed(2)}`);
  }
}
const btnModalView = document.getElementById('btn-modal-view');
if (btnModalView) {
  btnModalView.addEventListener('click', () => {
    document.getElementById('modal-backdrop')?.classList?.remove('active');
    if (lastSavedType === 'income') {
      navigateToScreen('dashboard');
    } else {
      navigateToScreen('records');
    }
  });
}
const btnModalAddAnother = document.getElementById('btn-modal-add-another');
if (btnModalAddAnother) {
  btnModalAddAnother.addEventListener('click', () => {
    document.getElementById('modal-backdrop')?.classList?.remove('active');
    if (lastSavedType === 'income') {
      navigateToScreen('actual-income');
    } else {
      navigateToScreen('add-expense');
    }
  });
}
/* SAVE ACTUAL INCOME TO DATABASE */
const formActualIncome = document.getElementById('form-actual-income');
if (formActualIncome) {
  formActualIncome.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (usageStatus.locked) {
      alert("You've used all your available sessions. Please subscribe from the Subscribe page to continue.");
      return;
    }
    const incInput = document.getElementById('actual-income-input');
    const incDate = document.getElementById('actual-income-date')?.value || new Date().toISOString().split('T')[0];
    const val = parseFloat(incInput?.value) || 0;
    if (val <= 0) {
      alert("Please enter a valid actual income amount.");
      return;
    }
    // General computation mode has been removed — laging gagamitin na ang
    // Per Month/Product na pinili sa Computation & Comparison panel.
    const selectedProduct = document.getElementById('comp-product-select')?.value || '';
    const selectedMonth = document.getElementById('comp-month-select')?.value || getMonthKey(incDate);
    const enteredExp = parseFloat(document.getElementById('comp-product-expenses')?.value) || 0;
    const matchedProduceRecords = records.filter(r => r.type === 'produce' && r.name === selectedProduct && (!selectedMonth || getMonthKey(r.date) === selectedMonth));
    const productSales = matchedProduceRecords.reduce((s, r) => s + r.amount, 0);
    const productName = selectedProduct || getProductsForMonth(incDate);
    const computedNet = productSales - enteredExp;
    const newIncomeRecord = {
      productName: productName,
      amount: val,
      computedNet: computedNet,
      discrepancy: val - computedNet,
      date: incDate
    };
    try {
      const res = await fetch('/api/income', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newIncomeRecord)
      });
      const resData = await res.json().catch(() => ({}));
      if (res.ok) {
        if (resData.usage) usageStatus = resData.usage;
        await fetchUserDataFromBackend();
        if (incInput) incInput.value = '';
        // Ang harvest ay tapos na (actual income na-record) — ihanda ang
        // rate-this-harvest popup na lalabas sa Dashboard. FIX: dati,
        // isang beses lang HABANG BUHAY ng account makaka-rate (kahit iba
        // na ang produkto/cycle), dahil global ang check. Ngayon, per-batch
        // ng mismong mga produce record na ito ang tinitignan — kung wala
        // pang rating ang mga specific na record na ito, ipapakita ang
        // rating popup, kahit nakapag-rate na dati ang ibang harvest.
        const thisHarvestAlreadyRated = matchedProduceRecords.length > 0 &&
          matchedProduceRecords.every(mr => {
            const fresh = records.find(r => String(r.id) === String(mr.id));
            return fresh && fresh.rating !== null && fresh.rating !== undefined;
          });
        if (matchedProduceRecords.length > 0 && !thisHarvestAlreadyRated) {
          pendingHarvestRatingIds = matchedProduceRecords.map(r => r.id);
          pendingHarvestRatingName = productName;
        }
        showSuccessModal('Actual Income Saved!', 'Income recorded to monitoring history.', {
          name: `Income (${productName})`,
          date: incDate,
          type: 'income',
          amount: val
        });
      } else if (resData.locked) {
        await fetchUserDataFromBackend();
        alert(resData.error || "You've reached the free usage limit.");
      }
    } catch (err) {
      alert("Error saving actual income to backend.");
    }
  });
}
function renderIncomeHistoryTable() {
  const tbody = document.getElementById('income-history-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (actualIncomeHistory.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No saved actual income records yet.</td></tr>';
    return;
  }
  // Group entries by month so each month shows which product(s) were recorded
  const grouped = {};
  actualIncomeHistory.forEach((item, idx) => {
    const mKey = getMonthKey(item.date);
    if (!grouped[mKey]) grouped[mKey] = [];
    grouped[mKey].push({ ...item, idx });
  });
  const sortedMonths = Object.keys(grouped).sort().reverse();
  sortedMonths.forEach(mKey => {
    const entries = grouped[mKey];
    const productsThisMonth = getProductsForMonth(entries[0].date);
    const headerRow = document.createElement('tr');
    headerRow.innerHTML = `<td colspan="6" style="background: var(--paper); font-weight: 700;">${getMonthLabel(mKey)} — Products: ${escapeHtml(productsThisMonth)}</td>`;
    tbody.appendChild(headerRow);
    entries.forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(item.date)}</strong></td>
        <td><span class="type-badge type-badge--produce">${escapeHtml(item.productName || productsThisMonth)}</span></td>
        <td class="align-right record-amount--positive">₱${item.amount.toFixed(2)}</td>
        <td class="align-right">₱${(item.computedNet || 0).toFixed(2)}</td>
        <td class="align-right">
          <span class="pct-badge ${(item.discrepancy || 0) >= 0 ? 'pct-badge--green' : 'pct-badge--red'}">
            ${(item.discrepancy || 0) >= 0 ? '+' : ''}₱${(item.discrepancy || 0).toFixed(2)}
          </span>
        </td>
        <td><button class="row-delete" onclick="deleteIncomeHistoryRecord(${item.idx})">Delete</button></td>
      `;
      tbody.appendChild(tr);
    });
  });
}
// Groups every saved actual-income entry by product, separate from the month-by-month history above
function renderIncomeMonitoringByProduct() {
  const tbody = document.getElementById('income-monitoring-product-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (actualIncomeHistory.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No saved actual income records yet.</td></tr>';
    return;
  }
  const productTotals = {};
  actualIncomeHistory.forEach(item => {
    const key = item.productName || getProductsForMonth(item.date);
    if (!productTotals[key]) {
      productTotals[key] = { actual: 0, computedNet: 0, discrepancy: 0, count: 0 };
    }
    productTotals[key].actual += item.amount || 0;
    productTotals[key].computedNet += item.computedNet || 0;
    productTotals[key].discrepancy += item.discrepancy || 0;
    productTotals[key].count += 1;
  });
  const sortedProducts = Object.keys(productTotals).sort((a, b) => productTotals[b].actual - productTotals[a].actual);
  sortedProducts.forEach(name => {
    const data = productTotals[name];
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(name)}</strong></td>
      <td class="align-right record-amount--positive">₱${data.actual.toFixed(2)}</td>
      <td class="align-right">₱${data.computedNet.toFixed(2)}</td>
      <td class="align-right">
        <span class="pct-badge ${data.discrepancy >= 0 ? 'pct-badge--green' : 'pct-badge--red'}">
          ${data.discrepancy >= 0 ? '+' : ''}₱${data.discrepancy.toFixed(2)}
        </span>
      </td>
      <td class="align-right">${data.count}</td>
    `;
    tbody.appendChild(tr);
  });
}
async function deleteIncomeHistoryRecord(index) {
  if (confirm("Are you sure you want to delete this income entry?")) {
    try {
      const res = await fetch(`/api/income/${index}`, { method: 'DELETE' });
      if (res.ok) {
        await fetchUserDataFromBackend();
      }
    } catch (e) {
      alert("Failed to delete record.");
    }
  }
}
/* SAVE FARM PRODUCT */
/* SAVE PRODUCT & ITS EXPENSES (merged form) */
const formExpense = document.getElementById('form-expense');
if (formExpense) {
  formExpense.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (usageStatus.locked) {
      alert("You've used all your available sessions. Please subscribe from the Subscribe page to continue.");
      return;
    }
    const name = document.getElementById('produce-name')?.value.trim();
    const date = document.getElementById('expense-date')?.value;
    if (!name) {
      alert("Please enter a valid product/crop name.");
      return;
    }
    const rows = document.querySelectorAll('.expense-row');
    const newExpenses = [];
    rows.forEach(row => {
      const cat = row.querySelector('.expense-cat')?.value;
      const desc = row.querySelector('.expense-desc')?.value.trim();
      const amt = parseFloat(row.querySelector('.expense-amount')?.value) || 0;
      if (amt > 0) {
        newExpenses.push({
          type: 'expense',
          name: desc ? `${cat} (${desc})` : cat,
          category: cat,
          amount: amt,
          date: date
        });
      }
    });
    if (newExpenses.length === 0) {
      alert("Please enter at least one valid expense amount.");
      return;
    }
    // Pricing ay itatakda na lang mamaya sa "View Expenses for this Product"
    // (View / search records) — default muna sa kg, profit margin na lang ang
    // magtatakda kung magkano ang presyo per kilo.
    const produceRecord = {
      type: 'produce',
      name: name,
      qty: 0,
      unit: 'kg',
      pricePerUnit: 0,
      amount: 0,
      date: date
    };
    // Isang batch request: produce record muna, susundan ng mga expense —
    // awtomatiko itong ma-li-link sa backend gamit ang bagong produce id.
    const batch = [produceRecord, ...newExpenses];
    try {
      const res = await fetch('/api/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batch)
      });
      const resData = await res.json().catch(() => ({}));
      if (res.ok) {
        if (resData.usage) usageStatus = resData.usage;
        await fetchUserDataFromBackend();
        formExpense.reset();
        resetExpenseForm();
        document.getElementById('expense-date').value = date;
        showSuccessModal('Product & Expenses Saved!', `${name} and ${newExpenses.length} expense item(s) have been recorded. Set its Pricing from View / search records → View Expenses for this Product.`, {
          name: name,
          date: date,
          type: 'produce',
          amount: 0
        });
      } else if (resData.locked) {
        await fetchUserDataFromBackend();
        alert(resData.error || "You've reached the free usage limit.");
      } else {
        alert(resData.error || "Error saving record.");
      }
    } catch (err) {
      alert("Error saving product and expenses.");
    }
  });
}
// Pricing calculator updates (ngayon ay nasa loob ng "View Expenses for this
// Product" modal — base sa mga expense na naka-link sa kasalukuyang produce).
// Quantity at Unit ay tinanggal na — ang Profit Margin na lang ang bahala
// mag-compute ng Total Sales Target. Dahil hindi natin alam ang eksaktong
// bilang ng kilo na aanihin, nagpapakita tayo ng ilang KARANIWANG bilang ng
// kilo (10/20/50/100) kasama ang katumbas na presyo per kilo sa bawat isa —
// base lang sa SARILING gastos + margin (hindi sa presyo sa palengke), para
// tiyak na mababawi ng user ang puhunan niya. Pipili ang user ng row na
// pinaka-malapit sa inaasahan niyang ani bago mag-Save Pricing.
const PRICING_KILO_OPTIONS = [10, 20, 50, 100];
let selectedPricingKilo = null;
// Kapag naitala na ang Actual Income ng isang product, itinuturing na tapos na
// ang harvest cycle nito — hindi na dapat ma-edit ang expenses/pricing nito.
let currentProduceIsLocked = false;
function hasActualIncomeForProduct(productName) {
  return actualIncomeHistory.some(inc => inc.productName === productName);
}
function updatePricingCalculator() {
  const margin = parseFloat(document.getElementById('produce-profit-margin')?.value) || 10;
  let totalExpenses = 0;
  if (currentProduceDetailId) {
    totalExpenses = records.filter(r => r.type === 'expense' && String(r.produceId) === String(currentProduceDetailId)).reduce((s, r) => s + r.amount, 0);
  }
  const expDisp = document.getElementById('pricing-guide-expenses');
  const marginDisp = document.getElementById('pricing-margin-display');
  const targetSalesDisp = document.getElementById('pricing-target-sales');
  const targetProfitDisp = document.getElementById('pricing-target-profit');
  if (expDisp) expDisp.textContent = `₱${totalExpenses.toFixed(2)}`;
  if (marginDisp) marginDisp.textContent = `${margin}%`;
  const targetSales = totalExpenses * (1 + margin / 100);
  const targetProfit = targetSales - totalExpenses;
  if (targetSalesDisp) targetSalesDisp.textContent = `₱${targetSales.toFixed(2)}`;
  if (targetProfitDisp) targetProfitDisp.textContent = `₱${targetProfit.toFixed(2)}`;
  selectedPricingKilo = null;
  renderPricingKiloTable(targetSales);
  updateSavePricingButtonState();
}
function renderPricingKiloTable(targetSales) {
  const wrap = document.getElementById('pricing-kilo-table');
  if (!wrap) return;
  wrap.innerHTML = PRICING_KILO_OPTIONS.map(kg => {
    const pricePerKilo = kg > 0 ? targetSales / kg : 0;
    return `<div class="pricing-kilo-row${currentProduceIsLocked ? ' pricing-kilo-row--disabled' : ''}" data-kg="${kg}">
      <span class="pricing-kilo-label">${kg} kilo</span>
      <span class="pricing-kilo-price">₱${pricePerKilo.toFixed(2)}/kilo</span>
    </div>`;
  }).join('');
  if (currentProduceIsLocked) return;
  wrap.querySelectorAll('.pricing-kilo-row').forEach(row => {
    row.addEventListener('click', () => {
      selectedPricingKilo = parseInt(row.dataset.kg, 10);
      wrap.querySelectorAll('.pricing-kilo-row').forEach(r => r.classList.toggle('pricing-kilo-row--selected', parseInt(r.dataset.kg, 10) === selectedPricingKilo));
      updateSavePricingButtonState();
    });
  });
}
function updateSavePricingButtonState() {
  const btn = document.getElementById('btn-pd-save-pricing');
  if (btn) btn.disabled = currentProduceIsLocked || !selectedPricingKilo;
}
document.getElementById('produce-profit-margin')?.addEventListener('input', updatePricingCalculator);
const btnPdSavePricing = document.getElementById('btn-pd-save-pricing');
if (btnPdSavePricing) {
  btnPdSavePricing.addEventListener('click', async () => {
    if (currentProduceIsLocked || !currentProduceDetailId || !selectedPricingKilo) return;
    const margin = parseFloat(document.getElementById('produce-profit-margin')?.value) || 10;
    const totalExpenses = records.filter(r => r.type === 'expense' && String(r.produceId) === String(currentProduceDetailId)).reduce((s, r) => s + r.amount, 0);
    const targetSales = totalExpenses * (1 + margin / 100);
    const pricePerUnit = targetSales / selectedPricingKilo;
    try {
      const res = await fetch(`/api/records/${currentProduceDetailId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ unit: 'kg', pricePerUnit, amount: targetSales })
      });
      if (res.ok) {
        await fetchUserDataFromBackend();
        const item = records.find(r => String(r.id) === String(currentProduceDetailId));
        if (item) {
          document.getElementById('pd-price').textContent = `₱${(item.pricePerUnit || 0).toFixed(2)}`;
          document.getElementById('pd-total').textContent = `₱${item.amount.toFixed(2)}`;
        }
        openPricingSavedPopup(pricePerUnit, selectedPricingKilo);
      } else {
        alert("Error saving pricing.");
      }
    } catch (err) {
      alert("Error saving pricing.");
    }
  });
}
function openPricingSavedPopup(pricePerUnit, kg) {
  const backdrop = document.getElementById('pricing-saved-backdrop');
  if (!backdrop) return;
  const priceEl = document.getElementById('pricing-saved-price');
  const kgEl = document.getElementById('pricing-saved-kg');
  if (priceEl) priceEl.textContent = `₱${pricePerUnit.toFixed(2)}`;
  if (kgEl) kgEl.textContent = `${kg} kilo`;
  backdrop.classList.add('active');
}
document.getElementById('btn-pricing-saved-close')?.addEventListener('click', () => {
  document.getElementById('pricing-saved-backdrop')?.classList.remove('active');
});
// Dashboard Update
// USABILITY FIX: kapag hindi na-set ng farmer ang presyo ng isang produkto
// (nananatiling ₱0.00 ang amount hangga't hindi binisita ang "View Expenses
// for this Product"), permanenteng ₱0 lang ang record na iyon sa lahat ng
// reports/dashboard nang hindi niya alam — kaya nilalagyan natin ito ng
// palaging nakikitang paalala sa Dashboard.
function renderPendingPricingReminder() {
  const banner = document.getElementById('pending-pricing-banner');
  const listEl = document.getElementById('pending-pricing-list');
  if (!banner || !listEl) return;
  const unpriced = records.filter(r => r.type === 'produce' && (!r.pricePerUnit || r.pricePerUnit <= 0));
  if (unpriced.length === 0) {
    banner.style.display = 'none';
    listEl.innerHTML = '';
    return;
  }
  banner.style.display = 'block';
  listEl.innerHTML = unpriced.map(item => `
    <div class="pending-pricing-item">
      <span>
        <span class="pending-pricing-item-name">${escapeHtml(item.name || '')}</span>
        <span class="pending-pricing-item-date">${escapeHtml(item.date || '')}</span>
      </span>
      <button type="button" class="btn btn-outline btn-sm" onclick="openProduceDetail('${item.id}')" data-i18n="dash.setPricingBtn">Set pricing</button>
    </div>
  `).join('');
  applyLanguage(currentLanguage);
}

function updateDashboard() {
  let sales = 0;
  let expenses = 0;

  for (const record of records) {
    const amount = Number(record.amount) || 0;

    if (record.type === 'produce') {
      sales += amount;
    } else if (record.type === 'expense') {
      expenses += amount;
    }
  }

  const profit = currentActualIncome - expenses;

  renderPendingPricingReminder();

  const statSales = document.getElementById('stat-sales');
  const statExpenses = document.getElementById('stat-expenses');
  const statActual = document.getElementById('stat-actual-income');
  const statProfit = document.getElementById('stat-profit');

  if (statSales) {
    statSales.textContent = `₱${sales.toFixed(2)}`;
  }

  if (statExpenses) {
    statExpenses.textContent = `₱${expenses.toFixed(2)}`;
  }

  if (statActual) {
    statActual.textContent = `₱${currentActualIncome.toFixed(2)}`;
  }

  if (statProfit) {
    statProfit.textContent = `₱${profit.toFixed(2)}`;

    const card = document.getElementById('stat-profit-card');

    if (card) {
      card.classList.toggle('negative', profit < 0);
    }
  }

  const recentList = document.getElementById('recent-list');

  if (!recentList) {
    return;
  }

  recentList.innerHTML = '';

  // Ang API ay nagbabalik na ng records mula latest hanggang oldest.
  const recent = records.slice(0, 5);

  if (recent.length === 0) {
    recentList.innerHTML =
      '<div class="empty-state">No records added yet.</div>';
    return;
  }

  const fragment = document.createDocumentFragment();

  for (const item of recent) {
    const row = document.createElement('div');
    row.className = 'record-row';

    const amount = Number(item.amount) || 0;
    const isProduce = item.type === 'produce';

    row.innerHTML = `
      <span class="record-dot record-dot--${isProduce ? 'produce' : 'expense'}"></span>
      <div class="record-name">
        ${escapeHtml(item.name || '')}
        <span class="record-meta">
          • ${escapeHtml(item.date || '')}
        </span>
      </div>
      <div class="record-amount ${
        isProduce
          ? 'record-amount--positive'
          : 'record-amount--negative'
      }">
        ${isProduce ? '+' : '-'}₱${amount.toFixed(2)}
      </div>
    `;

    fragment.appendChild(row);
  }

  recentList.appendChild(fragment);
}
// ==================== SUBSCRIPTION / USAGE LIMIT ====================
// BAGO: ang free-plan progress banner ay lumalabas lang sa Dashboard habang
// 'free' pa ang subscriptionStatus. Sa sandaling maka-subscribe na ang user
// (status = 'active'), nawawala na ito sa Dashboard — doon na lang sa bagong
// "Subscribe" screen (nasa ilalim ng Customer Service sa sidebar) makikita
// ang plan picker at GCash payment form.
let subscribePopupShown = false;
function updateSubscriptionUI() {
  const banner = document.getElementById('subscription-banner');
  const cycleLabel = document.getElementById('cycle-count-label');
  const totalLabel = document.getElementById('cycle-total-label');
  if (banner) {
    banner.style.display = usageStatus.subscriptionStatus === 'free' ? 'block' : 'none';
  }
  if (cycleLabel) cycleLabel.textContent = usageStatus.cycleCount;
  if (totalLabel) totalLabel.textContent = usageStatus.totalAllowed;
  updateSubscribeStatusText();
  // Kapag naubos na ang mga sessions (free trial man o binayarang plan),
  // awtomatikong lumalabas ang popup para pumili ng plan — isang beses lang
  // kada "lock event" (hindi paulit-ulit kada fetch).
  if (usageStatus.locked) {
    loadGcashInfo();
    if (!subscribePopupShown) {
      subscribePopupShown = true;
      document.getElementById('subscribe-choice-backdrop')?.classList?.add('active');
    }
  } else {
    subscribePopupShown = false;
  }
  // Lock the add-forms once the free/purchased sessions are used up
  ['form-expense', 'form-actual-income'].forEach(id => {
    const form = document.getElementById(id);
    if (!form) return;
    const submitBtn = form.querySelector('button[type="submit"], .btn-primary');
    if (usageStatus.locked) {
      form.classList.add('form-locked');
      if (submitBtn) { submitBtn.disabled = true; }
    } else {
      form.classList.remove('form-locked');
      if (submitBtn) { submitBtn.disabled = false; }
    }
  });
}
// Status text na ipinapakita sa itaas ng "Subscribe" screen.
function updateSubscribeStatusText() {
  const el = document.getElementById('subscribe-status-text');
  if (!el) return;
  // FIX: dating agad na-a-activate ang bayad; ngayon "pending" muna hangga't
  // hindi ito na-verify/na-a-approve ng admin — ipinapakita ito rito para
  // hindi mag-akalang bug ang farmer kung bakit hindi pa dumadagdag ang
  // sessions niya agad-agad.
  if (usageStatus.hasPendingSubscription) {
    el.textContent = 'May pending ka pang subscription request — hinihintay pa ang pag-verify at pag-approve ng admin sa GCash reference number mo. Aabisuhan ka rito sa app kapag na-approve na.';
    return;
  }
  if (usageStatus.subscriptionStatus === 'active') {
    const remaining = Math.max(0, usageStatus.totalAllowed - usageStatus.cycleCount);
    el.textContent = usageStatus.locked
      ? `Naubos na ang mga sessions mo (${usageStatus.cycleCount} / ${usageStatus.totalAllowed} nagamit na). Pumili ng plan sa ibaba para magdagdag ng sessions.`
      : `Aktibo ang subscription mo — ${remaining} session(s) pa ang natitira (${usageStatus.cycleCount} / ${usageStatus.totalAllowed} nagamit na).`;
  } else {
    el.textContent = `Free trial — ${usageStatus.cycleCount} / ${usageStatus.totalAllowed} sessions ginamit na.` +
      (usageStatus.locked ? ' Naubos na ang free sessions — pumili ng plan sa ibaba para magpatuloy.' : '');
  }
}
const btnSubscribeChoiceClose = document.getElementById('btn-subscribe-choice-close');
if (btnSubscribeChoiceClose) {
  btnSubscribeChoiceClose.addEventListener('click', () => {
    document.getElementById('subscribe-choice-backdrop')?.classList?.remove('active');
  });
}
// Ang mga plan button sa popup ay hindi direktang nagbabayad — dinadala nila
// ang user sa Subscribe screen at pinipili doon ang parehong plan, para
// iisa lang ang GCash payment form sa buong app.
document.querySelectorAll('#subscribe-choice-plans .plan-option').forEach(btn => {
  btn.addEventListener('click', () => {
    document.getElementById('subscribe-choice-backdrop')?.classList?.remove('active');
    const plan = btn.dataset.plan;
    navigateToScreen('subscribe');
    const target = document.querySelector(`#plan-picker .plan-option[data-plan="${plan}"]`);
    if (target) {
      target.click();
      setTimeout(() => target.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50);
    }
  });
});
let gcashInfoLoaded = false;
async function loadGcashInfo() {
  if (gcashInfoLoaded) return;
  try {
    const res = await fetch('/api/gcash-info');
    if (!res.ok) return;
    const data = await res.json();
    gcashInfoLoaded = true;
    const nameEl = document.getElementById('gcash-display-name');
    const numEl = document.getElementById('gcash-display-number');
    if (nameEl) nameEl.textContent = data.gcashName || 'Admin';
    if (numEl) numEl.textContent = data.gcashNumber || 'Not set — contact admin';
    // BAGO: QR code image (opsyonal). Kung wala pang na-upload na
    // static/gcash-qr.png, itago na lang nang tahimik ang QR section sa
    // halip na ipakita ang broken image icon.
    const qrWrap = document.getElementById('gcash-qr-wrap');
    const qrImg = document.getElementById('gcash-qr-img');
    if (qrWrap && qrImg) {
      qrImg.addEventListener('error', () => { qrWrap.style.display = 'none'; }, { once: true });
      qrImg.addEventListener('load', () => { qrWrap.style.display = 'block'; }, { once: true });
      // Force a check kung na-cache/wala man lang nag-trigger sa events pa
      if (qrImg.complete) {
        if (qrImg.naturalWidth === 0) qrWrap.style.display = 'none';
        else qrWrap.style.display = 'block';
      }
    }
  } catch (e) {
    console.error('Error loading GCash info:', e);
  }
}
document.querySelectorAll('#plan-picker .plan-option').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#plan-picker .plan-option').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    selectedPlan = btn.dataset.plan;
    const amountLabel = document.getElementById('gcash-selected-amount');
    if (amountLabel) amountLabel.textContent = `₱${btn.dataset.price}`;
    const gcashBox = document.getElementById('gcash-payment-box');
    if (gcashBox) gcashBox.style.display = 'block';
  });
});
const btnRequestSubscription = document.getElementById('btn-request-subscription');
if (btnRequestSubscription) {
  btnRequestSubscription.addEventListener('click', async () => {
    const paymentRefInput = document.getElementById('subscription-payment-ref');
    const paymentReference = paymentRefInput?.value.trim() || '';
    if (!selectedPlan) {
      alert('Pumili muna ng plan.');
      return;
    }
    if (!paymentReference) {
      alert('Ilagay ang GCash reference number ng bayad mo.');
      return;
    }
    try {
      const res = await fetch('/api/subscription/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: selectedPlan, paymentReference })
      });
      const data = await res.json();
      if (res.ok) {
        if (data.usage) usageStatus = data.usage;
        if (paymentRefInput) paymentRefInput.value = '';
        selectedPlan = null;
        document.querySelectorAll('.plan-option').forEach(b => b.classList.remove('selected'));
        const gcashBox = document.getElementById('gcash-payment-box');
        if (gcashBox) gcashBox.style.display = 'none';
        updateSubscriptionUI();
        alert(data.message || 'Successfully subscribed!');
      } else {
        alert(data.error || 'Could not process subscription.');
      }
    } catch (e) {
      alert('Could not send subscription request. Please try again.');
    }
  });
}
// Records rendering
function renderRecords() {
  const pTbody = document.getElementById('produce-tbody');
  const search = document.getElementById('records-search')?.value.toLowerCase() || '';

  if (!pTbody) return;

  pTbody.innerHTML = '';

  const prodRecords = records.filter(
    r => r.type === 'produce' && (r.name || '').toLowerCase().includes(search)
  );

  if (prodRecords.length === 0) {
    pTbody.innerHTML =
      '<tr><td colspan="6" class="empty-state">No product / expense records found.</td></tr>';
    return;
  }

  const fragment = document.createDocumentFragment();

  prodRecords.forEach((item) => {
    const tr = document.createElement('tr');

    const pricePerUnit = Number(item.pricePerUnit) || 0;
    const amount = Number(item.amount) || 0;

    tr.innerHTML = `
      <td><strong>${escapeHtml(item.name || '')}</strong></td>
      <td class="align-right">₱${pricePerUnit.toFixed(2)}</td>
      <td class="align-right record-amount--positive">₱${amount.toFixed(2)}</td>
      <td class="align-right">₱${(amount * 0.1).toFixed(2)}</td>
      <td>${escapeHtml(item.date || '')}</td>
      <td class="row-actions-cell">
        <button
          class="btn-view-details"
          onclick="openProduceDetail('${item.id}')">
          View Expenses for this Product
        </button>
        <button
          class="row-delete"
          onclick="deleteRecord('${item.id}')">
          Delete
        </button>
      </td>
    `;

    fragment.appendChild(tr);
  });

  pTbody.appendChild(fragment);
}

document.getElementById('records-search')?.addEventListener('input', renderRecords);
async function deleteRecord(id) {
  if (!confirm('Delete this record?')) {
    return;
  }

  try {
    const res = await fetch(`/api/records/${id}`, {
      method: 'DELETE'
    });

    if (!res.ok) {
      alert('Error deleting record.');
      return;
    }

    // Tanggalin agad sa local data para hindi na i-download
    // muli ang buong records list.
    records = records.filter(
      record => String(record.id) !== String(id)
    );

    rebuildProductsByMonthCache();
    updateDashboard();
    renderRecords();
    renderReports();
    initComputationDropdowns();
  } catch (e) {
    alert('Error deleting record.');
  }
}
// ==================== PRODUCE VIEW DETAILS: HARVEST COUNTDOWN + LINKED EXPENSES ====================
// Karaniwang bilang ng buwan bago ma-harvest, per crop (estimate lang, PH farming reference)
const HARVEST_MONTHS_REFERENCE = [
  { match: ['corn', 'mais'], months: 3.5 },
  { match: ['rice', 'palay'], months: 4 },
  { match: ['tomato', 'kamatis'], months: 2.5 },
  { match: ['eggplant', 'talong'], months: 2.8 },
  { match: ['okra'], months: 2 },
  { match: ['cabbage', 'repolyo'], months: 2.5 },
  { match: ['sitaw', 'string bean', 'yard long bean'], months: 1.7 },
  { match: ['ampalaya', 'bitter gourd'], months: 2 },
  { match: ['onion', 'sibuyas'], months: 3.5 },
  { match: ['garlic', 'bawang'], months: 3.8 },
  { match: ['sweet potato', 'kamote'], months: 3.5 },
  { match: ['cassava', 'kamoteng kahoy'], months: 9 },
  { match: ['peanut', 'mani'], months: 3.2 },
  { match: ['mungbean', 'monggo', 'mung bean'], months: 2.2 },
  { match: ['watermelon', 'pakwan'], months: 2.8 },
  { match: ['squash', 'kalabasa'], months: 3.5 },
  { match: ['banana', 'saging'], months: 10 },
  { match: ['pechay', 'bok choy', 'pak choi'], months: 1.2 },
  { match: ['lettuce'], months: 1.5 },
  { match: ['carrot', 'karot'], months: 3 },
  { match: ['ginger', 'luya'], months: 8 },
];
const DEFAULT_HARVEST_MONTHS = 3; // fallback kapag walang match sa crop name
// Expense category list na muling ginamit sa Add Expense screen (para sync ang mga label)
const PD_EXPENSE_CATEGORIES = ['Fertilizer', 'Seeds', 'Pesticide', 'Labor / Wages', 'Utilities / Fuel', 'Transportation', 'Other Expenses'];
function getEstimatedHarvestMonths(cropName) {
  const lower = (cropName || '').toLowerCase();
  const found = HARVEST_MONTHS_REFERENCE.find(entry => entry.match.some(keyword => lower.includes(keyword)));
  return found ? found.months : DEFAULT_HARVEST_MONTHS;
}
let currentProduceDetailId = null;
function openProduceDetail(produceId) {
  const item = records.find(r => String(r.id) === String(produceId) && r.type === 'produce');
  if (!item) return;
  currentProduceDetailId = item.id;
  currentProduceIsLocked = hasActualIncomeForProduct(item.name);
  const backdrop = document.getElementById('produce-detail-backdrop');
  if (!backdrop) return;
  const lockedBanner = document.getElementById('pd-locked-banner');
  if (lockedBanner) lockedBanner.style.display = currentProduceIsLocked ? 'flex' : 'none';
  document.getElementById('pd-title').textContent = item.name;
  document.getElementById('pd-crop-name').textContent = item.name;
  document.getElementById('pd-price').textContent = `₱${(item.pricePerUnit || 0).toFixed(2)}`;
  document.getElementById('pd-total').textContent = `₱${item.amount.toFixed(2)}`;
  document.getElementById('pd-date').textContent = item.date || '-';
  // ---- Harvest countdown ----
  const months = getEstimatedHarvestMonths(item.name);
  document.getElementById('pd-harvest-months').textContent = `${months} month${months === 1 ? '' : 's'}`;
  const countdownEl = document.getElementById('pd-countdown');
  const harvestDateEl = document.getElementById('pd-harvest-date');
  if (currentProduceIsLocked) {
    // Tapos na ang cycle na ito dahil naitala na ang Actual Income —
    // ihinto na ang countdown at ipakita na tapos na.
    countdownEl.textContent = 'Tapos na (naitala na ang Actual Income)';
    countdownEl.classList.remove('pd-countdown--overdue');
    countdownEl.classList.add('pd-countdown--done');
    if (harvestDateEl) harvestDateEl.textContent = harvestDateEl.textContent || '-';
  } else if (item.date) {
    const baseDate = new Date(item.date + 'T00:00:00');
    if (!isNaN(baseDate.getTime())) {
      const targetDate = new Date(baseDate.getTime());
      targetDate.setDate(targetDate.getDate() + Math.round(months * 30.4));
      harvestDateEl.textContent = targetDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
      const now = new Date();
      const msRemaining = targetDate.getTime() - now.getTime();
      const daysRemaining = Math.ceil(msRemaining / (1000 * 60 * 60 * 24));
      if (daysRemaining > 0) {
        countdownEl.textContent = `${daysRemaining} day${daysRemaining === 1 ? '' : 's'} remaining`;
        countdownEl.classList.remove('pd-countdown--overdue', 'pd-countdown--done');
      } else {
        countdownEl.textContent = `Estimated harvest window has passed (${Math.abs(daysRemaining)} day${Math.abs(daysRemaining) === 1 ? '' : 's'} ago)`;
        countdownEl.classList.remove('pd-countdown--done');
        countdownEl.classList.add('pd-countdown--overdue');
      }
    } else {
      harvestDateEl.textContent = '-';
      countdownEl.textContent = '-';
      countdownEl.classList.remove('pd-countdown--overdue', 'pd-countdown--done');
    }
  } else {
    harvestDateEl.textContent = '-';
    countdownEl.textContent = '-';
    countdownEl.classList.remove('pd-countdown--overdue', 'pd-countdown--done');
  }
  renderProduceLinkedExpenses(item.id);
  // ---- Add-expense form: naka-disable kapag naka-lock na ang product ----
  const addExpenseForm = document.getElementById('form-pd-add-expense');
  if (addExpenseForm) {
    addExpenseForm.querySelectorAll('input, select, button').forEach(el => { el.disabled = currentProduceIsLocked; });
  }
  // ---- Pricing Calculator (prefill with current saved values) ----
  const marginInput = document.getElementById('produce-profit-margin');
  if (marginInput) {
    marginInput.value = marginInput.value || 10;
    marginInput.disabled = currentProduceIsLocked;
  }
  updatePricingCalculator();
  backdrop.classList.add('active');
}
// ==================== HARVEST RATING POPUP ====================
// Lalabas na lang ang star rating sa Dashboard, pagkatapos malagyan ng
// user ng Actual Income (ibig sabihin, tapos na ang harvest ng produce na ito).
let pendingHarvestRatingIds = [];
let pendingHarvestRatingName = '';
function setHarvestStarDisplay(rating) {
  const starWrap = document.getElementById('harvest-star-rating');
  if (!starWrap) return;
  starWrap.dataset.rating = rating;
  starWrap.querySelectorAll('.star-btn').forEach(btn => {
    const val = parseInt(btn.dataset.value, 10);
    btn.classList.toggle('star-btn--filled', val <= rating);
  });
}
function openHarvestRatingPopup(produceIds, productName) {
  const backdrop = document.getElementById('harvest-rating-backdrop');
  if (!backdrop || !produceIds || produceIds.length === 0) return;
  pendingHarvestRatingIds = produceIds;
  pendingHarvestRatingName = productName || '';
  const nameEl = document.getElementById('harvest-rating-product-name');
  if (nameEl) nameEl.textContent = productName || 'this product';
  setHarvestStarDisplay(0);
  backdrop.classList.add('active');
}
document.querySelectorAll('#harvest-star-rating .star-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    if (pendingHarvestRatingIds.length === 0) return;
    const val = parseInt(btn.dataset.value, 10);
    setHarvestStarDisplay(val);
    try {
      await Promise.all(pendingHarvestRatingIds.map(id => fetch(`/api/records/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rating: val })
      })));
      await fetchUserDataFromBackend();
    } catch (err) {
      // silent fail, rating still shows selected visually
    }
    document.getElementById('harvest-rating-backdrop')?.classList?.remove('active');
    pendingHarvestRatingIds = [];
  });
});
const btnHarvestRatingClose = document.getElementById('btn-harvest-rating-close');
if (btnHarvestRatingClose) {
  btnHarvestRatingClose.addEventListener('click', () => {
    document.getElementById('harvest-rating-backdrop')?.classList?.remove('active');
    pendingHarvestRatingIds = [];
  });
}
function renderProduceLinkedExpenses(produceId) {
  const listEl = document.getElementById('pd-expense-list');
  const totalEl = document.getElementById('pd-expense-total');
  if (!listEl) return;
  const linked = records.filter(r => r.type === 'expense' && String(r.produceId) === String(produceId));
  const total = linked.reduce((s, r) => s + r.amount, 0);
  if (totalEl) totalEl.textContent = `₱${total.toFixed(2)}`;
  if (linked.length === 0) {
    listEl.innerHTML = '<div class="empty-state">Wala pang naka-link na expense. Mag-add sa ibaba.</div>';
    return;
  }
  listEl.innerHTML = '';
  linked.forEach(exp => {
    const row = document.createElement('div');
    row.className = 'pd-expense-item';
    row.innerHTML = `
      <div>
        <div class="pd-expense-item-name">${escapeHtml(exp.name)}</div>
        <div class="pd-expense-item-meta">${escapeHtml(exp.date || '')}</div>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <span class="pd-expense-item-amount">₱${exp.amount.toFixed(2)}</span>
        ${currentProduceIsLocked ? '' : `<button type="button" class="row-delete" onclick="deleteProduceLinkedExpense('${exp.id}')">Delete</button>`}
      </div>
    `;
    listEl.appendChild(row);
  });
}
async function deleteProduceLinkedExpense(expenseId) {
  if (currentProduceIsLocked) return;
  if (!confirm("Bawasin/tanggalin ang expense entry na ito? Mababawas ito agad sa total expenses ng produce na ito.")) return;
  try {
    const res = await fetch(`/api/records/${expenseId}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchUserDataFromBackend();
      if (currentProduceDetailId) renderProduceLinkedExpenses(currentProduceDetailId);
    }
  } catch (e) {
    alert("Error deleting linked expense.");
  }
}
const formPdAddExpense = document.getElementById('form-pd-add-expense');
if (formPdAddExpense) {
  formPdAddExpense.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentProduceDetailId) return;
    if (currentProduceIsLocked) {
      alert("Tapos na ang harvest cycle ng product na ito (naitala na ang Actual Income) — hindi na ito maaaring baguhin.");
      return;
    }
    if (usageStatus.locked) {
      alert("You've used all your available sessions. Please subscribe from the Subscribe page to continue.");
      return;
    }
    const category = document.getElementById('pd-expense-category')?.value || 'Fertilizer';
    const amountInput = document.getElementById('pd-expense-amount');
    const amount = parseFloat(amountInput?.value) || 0;
    const produceItem = records.find(r => String(r.id) === String(currentProduceDetailId));
    if (amount <= 0) {
      alert("Please enter a valid expense amount.");
      return;
    }
    const newExpense = {
      type: 'expense',
      name: category,
      category: category,
      description: produceItem ? `Dagdag na ${category} para sa ${produceItem.name}` : category,
      amount: amount,
      date: new Date().toISOString().split('T')[0],
      produceId: currentProduceDetailId
    };
    try {
      const res = await fetch('/api/records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newExpense)
      });
      const resData = await res.json().catch(() => ({}));
      if (res.ok) {
        if (resData.usage) usageStatus = resData.usage;
        await fetchUserDataFromBackend();
        if (amountInput) amountInput.value = '';
        if (currentProduceDetailId) renderProduceLinkedExpenses(currentProduceDetailId);
      } else if (resData.locked) {
        await fetchUserDataFromBackend();
        alert(resData.error || "You've reached the free usage limit.");
      } else {
        alert(resData.error || "Error adding expense.");
      }
    } catch (err) {
      alert("Error saving expense to backend.");
    }
  });
}
const btnPdClose = document.getElementById('btn-pd-close');
if (btnPdClose) {
  btnPdClose.addEventListener('click', () => {
    document.getElementById('produce-detail-backdrop')?.classList?.remove('active');
    currentProduceDetailId = null;
  });
}
// ==================== REPORTS ====================
function populateReportMonthFilter() {
  const selectEl = document.getElementById('report-month-filter');
  if (!selectEl) return;
  const prevVal = selectEl.value;
  const allDates = [...records.map(r => r.date), ...actualIncomeHistory.map(r => r.date)].filter(Boolean);
  const uniqueMonths = [...new Set(allDates.map(getMonthKey))].sort().reverse();
  selectEl.innerHTML = '<option value="all">All Months</option>';
  uniqueMonths.forEach(mKey => {
    const opt = document.createElement('option');
    opt.value = mKey;
    opt.textContent = getMonthLabel(mKey);
    selectEl.appendChild(opt);
  });
  if (prevVal && (uniqueMonths.includes(prevVal) || prevVal === 'all')) selectEl.value = prevVal;
}
document.getElementById('report-month-filter')?.addEventListener('change', renderReports);
function renderReports() {
  populateReportMonthFilter();
  const filterVal = document.getElementById('report-month-filter')?.value || 'all';
  const allDates = [...records.map(r => r.date), ...actualIncomeHistory.map(r => r.date)].filter(Boolean);
  let monthsToShow = [...new Set(allDates.map(getMonthKey))].sort();
  if (filterVal !== 'all') {
    monthsToShow = monthsToShow.filter(m => m === filterVal);
  }
  // ---- 1. Monthly Financial Monitoring Overview ----
  const mBody = document.getElementById('monthly-monitoring-tbody');
  if (mBody) {
    mBody.innerHTML = '';
    if (monthsToShow.length === 0) {
      mBody.innerHTML = '<tr><td colspan="4" class="empty-state">No records yet.</td></tr>';
    } else {
      monthsToShow.forEach(mKey => {
        const monthSales = records.filter(r => r.type === 'produce' && getMonthKey(r.date) === mKey).reduce((s, r) => s + r.amount, 0);
        const monthExpenses = records.filter(r => r.type === 'expense' && getMonthKey(r.date) === mKey).reduce((s, r) => s + r.amount, 0);
        const monthActualIncome = actualIncomeHistory.filter(r => getMonthKey(r.date) === mKey).reduce((s, r) => s + r.amount, 0);
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${getMonthLabel(mKey)}</strong></td>
          <td class="align-right record-amount--positive">₱${monthSales.toFixed(2)}</td>
          <td class="align-right record-amount--negative">₱${monthExpenses.toFixed(2)}</td>
          <td class="align-right">₱${monthActualIncome.toFixed(2)}</td>
        `;
        mBody.appendChild(tr);
      });
    }
  }
  // ---- 2. Monthly Trend Bar Graph (Sales vs Expenses) ----
  renderMonthlyBarGraph(monthsToShow);
  // ---- 3. Expense Breakdown by Category ----
  const catBody = document.getElementById('monthly-expense-cat-tbody');
  const catTotalEl = document.getElementById('monthly-expense-total-val');
  if (catBody) {
    catBody.innerHTML = '';
    const filteredExpenses = records.filter(r => r.type === 'expense' && (filterVal === 'all' || getMonthKey(r.date) === filterVal));
    const catTotals = {};
    filteredExpenses.forEach(r => {
      const cat = r.name.split(' (')[0];
      catTotals[cat] = (catTotals[cat] || 0) + r.amount;
    });
    const grandTotal = Object.values(catTotals).reduce((s, v) => s + v, 0);
    if (Object.keys(catTotals).length === 0) {
      catBody.innerHTML = '<tr><td colspan="3" class="empty-state">No expense records found.</td></tr>';
    } else {
      Object.entries(catTotals).forEach(([cat, amt]) => {
        const share = grandTotal > 0 ? ((amt / grandTotal) * 100).toFixed(1) : '0.0';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(cat)}</td>
          <td class="align-right record-amount--negative">₱${amt.toFixed(2)}</td>
          <td class="align-right">${share}%</td>
        `;
        catBody.appendChild(tr);
      });
    }
    if (catTotalEl) catTotalEl.textContent = `₱${grandTotal.toFixed(2)}`;
  }
  // ---- 4. Merged Product Financial Summary ----
  const prodBody = document.getElementById('monthly-products-tbody');
  if (prodBody) {
    prodBody.innerHTML = '';
    const filteredProduce = records.filter(r => r.type === 'produce' && (filterVal === 'all' || getMonthKey(r.date) === filterVal));
    const filteredExpAll = records.filter(r => r.type === 'expense' && (filterVal === 'all' || getMonthKey(r.date) === filterVal));
    const totalExpAll = filteredExpAll.reduce((s, r) => s + r.amount, 0);
    const totalSalesAll = filteredProduce.reduce((s, r) => s + r.amount, 0);
    const prodTotals = {};
    filteredProduce.forEach(r => {
      if (!prodTotals[r.name]) prodTotals[r.name] = { qty: 0, unit: r.unit, sales: 0 };
      prodTotals[r.name].qty += r.qty;
      prodTotals[r.name].sales += r.amount;
    });
    if (Object.keys(prodTotals).length === 0) {
      prodBody.innerHTML = '<tr><td colspan="6" class="empty-state">No product records found.</td></tr>';
    } else {
      Object.entries(prodTotals).forEach(([name, data]) => {
        const estExpenses = totalSalesAll > 0 ? totalExpAll * (data.sales / totalSalesAll) : 0;
        const profitMargin = data.sales > 0 ? (((data.sales - estExpenses) / data.sales) * 100).toFixed(1) : '0.0';
        const salesShare = totalSalesAll > 0 ? ((data.sales / totalSalesAll) * 100).toFixed(1) : '0.0';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(name)}</strong></td>
          <td class="align-right">${data.qty} ${escapeHtml(data.unit || '')}</td>
          <td class="align-right record-amount--positive">₱${data.sales.toFixed(2)}</td>
          <td class="align-right record-amount--negative">₱${estExpenses.toFixed(2)}</td>
          <td class="align-right">${profitMargin}%</td>
          <td class="align-right">${salesShare}%</td>
        `;
        prodBody.appendChild(tr);
      });
    }
  }
}
// Renders Sales vs Expenses as a grouped bar chart (SVG) inside #line-graph-box
function renderMonthlyBarGraph(monthsToShow) {
  const box = document.getElementById('line-graph-box');
  if (!box) return;
  box.innerHTML = '';
  if (!monthsToShow || monthsToShow.length === 0) {
    box.innerHTML = '<div class="empty-state">No data yet to plot.</div>';
    return;
  }
  const data = monthsToShow.map(mKey => {
    const sales = records.filter(r => r.type === 'produce' && getMonthKey(r.date) === mKey).reduce((s, r) => s + r.amount, 0);
    const expenses = records.filter(r => r.type === 'expense' && getMonthKey(r.date) === mKey).reduce((s, r) => s + r.amount, 0);
    return { label: getMonthLabel(mKey), sales, expenses };
  });
  const width = 700, height = 220, padding = { top: 15, right: 15, bottom: 40, left: 60 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const maxVal = Math.max(1, ...data.map(d => Math.max(d.sales, d.expenses)));
  const groupWidth = chartW / data.length;
  const barWidth = Math.min(28, groupWidth / 3);
  let bars = '';
  let labels = '';
  let gridLines = '';
  const steps = 4;
  for (let i = 0; i <= steps; i++) {
    const val = (maxVal / steps) * i;
    const y = padding.top + chartH - (chartH * (i / steps));
    gridLines += `<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="var(--border)" stroke-width="1"/>`;
    gridLines += `<text x="${padding.left - 8}" y="${y + 4}" font-size="10" text-anchor="end" fill="var(--muted)">₱${Math.round(val)}</text>`;
  }
  data.forEach((d, i) => {
    const groupX = padding.left + i * groupWidth;
    const salesH = (d.sales / maxVal) * chartH;
    const expH = (d.expenses / maxVal) * chartH;
    const salesX = groupX + groupWidth / 2 - barWidth - 3;
    const expX = groupX + groupWidth / 2 + 3;
    bars += `<rect x="${salesX}" y="${padding.top + chartH - salesH}" width="${barWidth}" height="${salesH}" fill="var(--forest)" rx="2"/>`;
    bars += `<rect x="${expX}" y="${padding.top + chartH - expH}" width="${barWidth}" height="${expH}" fill="var(--red)" rx="2"/>`;
    labels += `<text x="${groupX + groupWidth / 2}" y="${height - 12}" font-size="10.5" text-anchor="middle" fill="var(--ink)">${d.label}</text>`;
  });
  box.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
      ${gridLines}
      ${bars}
      ${labels}
    </svg>
  `;
}``
