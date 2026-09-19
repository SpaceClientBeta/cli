/*
 * Мост "сайт ⇄ лаунчер".
 * Когда лаунчер открывает сайт по кнопке "Войти" (?launcher=1&callback=...&nonce=...),
 * этот файл сразу пытается завершить вход без лишних кликов:
 *  - если на сайте уже есть активная сессия — сразу отдаёт тикет и кидает браузер
 *    обратно на локальный callback лаунчера (лаунчер это подхватывает мгновенно);
 *  - если сессии нет — открывает окно входа и, как только пользователь войдёт,
 *    автоматически продолжает и возвращает в лаунчер — второй раз кликать никуда не нужно.
 * Существующий script.js не трогаем: подключаемся к его глобальным функциям
 * (apiFetch/setSession/openModal/toastMsg), которые объявлены как обычные function
 * в script.js и поэтому доступны на window.
 */
(function () {
  "use strict";

  var params = new URLSearchParams(window.location.search);
  var isLauncher = params.get("launcher") === "1";
  var callback = params.get("callback") || "";
  var nonce = params.get("nonce") || "";
  var validCallback = /^http:\/\/127\.0\.0\.1:\d+\/callback$/.test(callback);

  function ready(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }

  if (isLauncher && validCallback && nonce) {
    var handedOff = false;
    var attempting = false;

    function setLauncherModalCopy() {
      var title = document.getElementById("modalTitle");
      var desc = document.getElementById("modalDescription");
      if (title) title.textContent = "Вход для лаунчера";
      if (desc) desc.textContent = "Войди в аккаунт — после входа мы автоматически вернём тебя в Space Client Launcher.";
    }

    async function tryHandoff() {
      if (handedOff || attempting) return;
      var session = typeof getSession === "function" ? getSession() : null;
      if (!session) {
        if (typeof openModal === "function") { openModal("login"); setLauncherModalCopy(); }
        return;
      }
      attempting = true;
      try {
        var data = await apiFetch("/api/launcher/authorize", {
          method: "POST",
          body: JSON.stringify({ callback: callback, nonce: nonce })
        });
        if (data && data.ok && data.redirect) {
          handedOff = true;
          if (typeof toastMsg === "function") toastMsg("Возвращаемся в Space Client Launcher…");
          setTimeout(function () { window.location.href = data.redirect; }, 250);
        }
      } catch (e) {
        // Сессия сайта не подошла (истекла/забанен и т.п.) — просим войти ещё раз.
        if (typeof clearSession === "function") clearSession();
        if (typeof updateAccount === "function") updateAccount();
        if (typeof openModal === "function") { openModal("login"); setLauncherModalCopy(); }
        if (typeof toastMsg === "function" && e && e.message) toastMsg(e.message, "error");
      } finally {
        attempting = false;
      }
    }

    ready(function () {
      document.body.classList.add("launcher-mode");
      tryHandoff();
      // Как только пользователь успешно войдёт/зарегистрируется на сайте (setSession),
      // сразу же пробуем передать тикет обратно лаунчеру — без повторного клика.
      var originalSetSession = window.setSession;
      if (typeof originalSetSession === "function") {
        window.setSession = function (token, user) {
          originalSetSession(token, user);
          tryHandoff();
        };
      }
    });
  }

  // Запрет правой кнопки мыши на сайте — как и просили в лаунчере.
  document.addEventListener("contextmenu", function (e) { e.preventDefault(); });
})();
