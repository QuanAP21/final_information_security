(function () {
  const root = document.getElementById("domXssLabRoot");
  const mount = document.getElementById("domNoticeMount");

  if (!root || !mount) return;

  const securityLevel = root.dataset.securityLevel || "low";
  const hash = window.location.hash || "";

  // #domxss:<attackId>:<base64_payload>
  if (!hash.startsWith("#domxss:")) return;

  const raw = hash.slice("#domxss:".length);
  const firstColon = raw.indexOf(":");
  if (firstColon === -1) return;

  const attackId = raw.slice(0, firstColon);
  const encodedPayload = raw.slice(firstColon + 1);

  let decodedHtml = "";
  try {
    decodedHtml = atob(decodeURIComponent(encodedPayload));
  } catch (err) {
    console.error("DOM XSS payload decode failed:", err);
    return;
  }

  // High mode: render safely and do not execute
  if (securityLevel === "high") {
    mount.textContent = decodedHtml;

    const body = new URLSearchParams({ attackId });

    fetch("/dom-attack-neutralized", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      credentials: "include",
      body: body.toString()
    }).catch((err) => {
      console.error("DOM attack neutralize callback failed:", err);
    });

    return;
  }

  // Low / Medium: vulnerable sink
  mount.innerHTML = decodedHtml;
})();