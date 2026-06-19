"use strict";
// Add a show/hide toggle to every password field on the page.
document.querySelectorAll('input[type="password"]').forEach(function (input) {
  if (input.dataset.revealable) return;
  input.dataset.revealable = "1";

  const wrap = document.createElement("span");
  wrap.className = "pwd-wrap";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "reveal-btn";
  btn.setAttribute("aria-label", "Show or hide password");
  btn.textContent = "👁";
  wrap.appendChild(btn);

  btn.addEventListener("click", function () {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    btn.textContent = hidden ? "🙈" : "👁";
  });
});
