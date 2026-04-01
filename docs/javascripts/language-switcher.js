document.addEventListener("DOMContentLoaded", () => {
  const header = document.querySelector(".md-header__inner");
  if (!header || document.querySelector(".aca-header-lang")) {
    return;
  }

  const container = document.createElement("div");
  container.className = "aca-header-lang";

  const label = document.createElement("label");
  label.className = "aca-header-lang__label";
  label.setAttribute("for", "aca-header-lang-select");
  label.textContent = "Language";

  const select = document.createElement("select");
  select.id = "aca-header-lang-select";
  select.className = "aca-select";

  const options = [
    { value: "en", label: "English" },
    { value: "zh", label: "中文" },
  ];

  const path = window.location.pathname.replace(/index\.html$/, "");
  const currentLanguage = path.includes("/zh/") ? "zh" : "en";

  for (const option of options) {
    const element = document.createElement("option");
    element.value = option.value;
    element.textContent = option.label;
    if (option.value === currentLanguage) {
      element.selected = true;
    }
    select.appendChild(element);
  }

  select.addEventListener("change", () => {
    const nextLanguage = select.value;
    let nextPath = path;

    if (path.includes("/en/")) {
      nextPath = path.replace("/en/", `/${nextLanguage}/`);
    } else if (path.includes("/zh/")) {
      nextPath = path.replace("/zh/", `/${nextLanguage}/`);
    } else {
      const base = path.endsWith("/") ? path : `${path}/`;
      nextPath = `${base}${nextLanguage}/`;
    }

    window.location.assign(`${nextPath}${window.location.search}${window.location.hash}`);
  });

  container.appendChild(label);
  container.appendChild(select);
  header.appendChild(container);
});
