(function () {
  const ttBox = document.getElementById("tt-demo-box");
  if (!ttBox) return;

  if (window.trustedTypes && typeof window.trustedTypes.createPolicy === "function") {
    const policy = trustedTypes.createPolicy("bankPolicy", {
      createHTML(input) {
        return input;
      }
    });

    ttBox.innerHTML = policy.createHTML(`
      <div class="tt-runtime-card">
        <span class="tt-runtime-badge">Trusted Types Policy</span>
        <h4>bankPolicy is active</h4>
        <p>
          This High-level page only allows approved Trusted Types HTML objects
          for sensitive DOM injection sinks.
        </p>
      </div>
    `);
  } else {
    ttBox.textContent =
      "Trusted Types is not available in this browser. Use a current Chrome or Edge version for the full High-level demo.";
  }
})();