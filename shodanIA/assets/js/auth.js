
(function () {
  const STORAGE_KEY = "app.auth.token";
  const USER_KEY = "app.auth.user";
  const LOGIN_ENDPOINT = "http://localhost:8000/auth/login";
  const DASHBOARD_URL  = "/dashboard/index.html";
  const LOGIN_URL      = "/index.html";
  const SHODAN_SEARCH = "/shodan/search";

  function getToken() {
    return localStorage.getItem(STORAGE_KEY);
  }

  function setToken(token) {
    if (typeof token !== "string" || !token.length) return;
    localStorage.setItem(STORAGE_KEY, token);
  }

  function setUser(user) {
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(user || null));
    } catch (e) { /* ignore */ }
  }

  function getUser() {
    try {
      const v = localStorage.getItem(USER_KEY);
      return v ? JSON.parse(v) : null;
    } catch (e) {
      return null;
    }
  }

  function clearAuth() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function isAuthenticated() {
    const token = getToken();
    return !!token;
  }

  function redirectToLogin(withNext = true) {
    const url = new URL(LOGIN_URL, window.location.origin);
    if (withNext) {
      const next = window.location.pathname + window.location.search + window.location.hash;
      if (next && next !== LOGIN_URL) url.searchParams.set("next", next);
    }
    window.location.replace(url.toString());
  }

  function requireAuth() {
    if (!isAuthenticated()) {
      redirectToLogin(true);
    }
  }

  async function authFetch(input, init = {}) {
    const token = getToken();
    const headers = new Headers(init.headers || {});
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(input, { ...init, headers });
  }

  /**
   * initLoginForm: engancha un form para login
   * @param {string|HTMLElement} formSelector
   * @param {object} options { onSuccess(user), onError(message) }
   */
  function initLoginForm(formSelector, options = {}) {
    const form = typeof formSelector === "string" ? document.querySelector(formSelector) : formSelector;
    if (!form) {
      console.warn("[auth.js] No se encontró el formulario de login", formSelector);
      return;
    }

    const submitBtn = form.querySelector("[type=submit]");
    const alertBox = form.querySelector("[data-login-alert]"); 
    
    function setLoading(loading) {
      if (submitBtn) {
        submitBtn.disabled = loading;
        submitBtn.dataset.originalText = submitBtn.dataset.originalText || submitBtn.innerText;
        submitBtn.innerText = loading ? "Ingresando..." : submitBtn.dataset.originalText;
      }
    }

    function showError(msg) {
      if (alertBox) {
        alertBox.classList.remove("d-none");
        alertBox.classList.add("alert", "alert-danger");
        alertBox.textContent = msg || "Error de autenticación.";
      } else {
        alert(msg || "Error de autenticación.");
      }
    }

    function hideError() {
      if (alertBox) {
        alertBox.classList.add("d-none");
        alertBox.textContent = "";
      }
    }

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      hideError();
      setLoading(true);

      const formData = new FormData(form);
      const email = (formData.get("email") || "").toString().trim();
      const password = (formData.get("password") || "").toString();

      if (!email || !password) {
        setLoading(false);
        showError("Por favor ingresa correo y contraseña.");
        return;
      }

      try {
        const res = await fetch(LOGIN_ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: email, password: password }),
        });

        // Si tu backend responde con { token, user: { ... } }
        if (!res.ok) {
          const msg = (await res.text()) || "Credenciales inválidas.";
          throw new Error(msg);
        }

        const data = await res.json();
        if (!data.token) throw new Error("Respuesta inválida del servidor (falta token).");

        setToken(data.token);
        if (data.user) setUser(data.user);

        if (typeof options.onSuccess === "function") {
          options.onSuccess(data.user || null);
        }

        // Redirigir al "next" o al dashboard
        const url = new URL(window.location.href);
        const next = url.searchParams.get("next") || DASHBOARD_URL;
        window.location.replace(next);
      } catch (e) {
        console.error(e);
        showError(e.message || "Error al iniciar sesión.");
        if (typeof options.onError === "function") options.onError(e);
      } finally {
        setLoading(false);
      }
    });

    // Si ya está autenticado y entra a login, llévalo al dashboard
    if (isAuthenticated()) {
      const url = new URL(window.location.href);
      const next = url.searchParams.get("next");
      window.location.replace(next || DASHBOARD_URL);
    }
  }

  /**
   * logout: utilidad para poner en un botón "Cerrar sesión"
   */
  function logout() {
    clearAuth();
    redirectToLogin(false);
  }

  // Exponer helpers en window para que puedas usarlos en tus HTML
  window.Auth = {
    initLoginForm,
    requireAuth,
    authFetch,
    isAuthenticated,
    getToken,
    getUser,
    logout,
    clearAuth,
  };
})();
