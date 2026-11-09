// H3 accessibility projection, evaluated in the render evidence content world.
//
// The render window is deliberately offscreen and has no accessibility client,
// so AppKit does not materialise a native WKWebView AX tree for it. This script
// is the documented host-side equivalent: it projects the same semantic roles,
// accessible names, heading levels, landmarks, table headers, and alternatives
// that a native AX walk would expose. The manifest records the source label
// `host-js-aria-snapshot-v1`; it is never presented as a native AX capture.
(() => {
  "use strict";

  const MAX_NODES = 500;
  const NAME_LIMIT = 200;

  const nodes = [];

  const visible = (element) => {
    if (!(element instanceof Element)) return false;
    if (element.getAttribute("aria-hidden") === "true") return false;
    if (element.getClientRects().length === 0) return false;
    const style = getComputedStyle(element);
    return style.visibility !== "hidden" && style.display !== "none";
  };

  const textOf = (element) => (element.textContent || "").replace(/\s+/g, " ").trim();

  function accessibleName(element, role) {
    const labelledBy = element.getAttribute("aria-labelledby");
    if (labelledBy) {
      const names = labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((target) => textOf(target))
        .filter(Boolean);
      if (names.length > 0) return names.join(" ").slice(0, NAME_LIMIT);
    }
    const label = element.getAttribute("aria-label");
    if (label) return label.trim().slice(0, NAME_LIMIT);
    if (role === "img") {
      const alt = element.getAttribute("alt");
      if (alt) return alt.trim().slice(0, NAME_LIMIT);
    }
    if (role === "table") {
      const caption = element.querySelector("caption");
      if (caption) return textOf(caption).slice(0, NAME_LIMIT);
    }
    if (role === "button" || role === "link" || role === "heading" || role === "caption") {
      const text = textOf(element);
      if (text) return text.slice(0, NAME_LIMIT);
    }
    if (element.tagName === "INPUT" || element.tagName === "TEXTAREA" || element.tagName === "SELECT") {
      const id = element.getAttribute("id");
      if (id) {
        const explicit = document.querySelector(`label[for="${CSS.escape(id)}"]`);
        if (explicit) return textOf(explicit).slice(0, NAME_LIMIT);
      }
      const closest = element.closest("label");
      if (closest) return textOf(closest).slice(0, NAME_LIMIT);
      return String(element.getAttribute("placeholder") || element.getAttribute("value") || "").slice(
        0,
        NAME_LIMIT,
      );
    }
    const title = element.getAttribute("title");
    if (title) return title.trim().slice(0, NAME_LIMIT);
    const text = textOf(element);
    return text ? text.slice(0, NAME_LIMIT) : "";
  }

  function implicitRole(element) {
    const explicit = element.getAttribute("role");
    if (explicit) return explicit.trim().split(/\s+/)[0];
    const tag = element.tagName.toLowerCase();
    if (/^h[1-6]$/.test(tag)) return "heading";
    switch (tag) {
      case "a":
        return element.hasAttribute("href") ? "link" : null;
      case "button":
        return "button";
      case "nav":
        return "navigation";
      case "main":
        return "main";
      case "header":
        return element.closest("article, section, main") ? null : "banner";
      case "footer":
        return element.closest("article, section, main") ? null : "contentinfo";
      case "aside":
        return "complementary";
      case "section": {
        const name = element.getAttribute("aria-label") || element.getAttribute("aria-labelledby");
        return name ? "region" : null;
      }
      case "table":
        return "table";
      case "caption":
        return "caption";
      case "thead":
        return "rowgroup";
      case "tbody":
        return "rowgroup";
      case "tr":
        return "row";
      case "th":
        return element.getAttribute("scope") === "row" ? "rowheader" : "columnheader";
      case "td":
        return "cell";
      case "ul":
      case "ol":
        return "list";
      case "li":
        return "listitem";
      case "figure":
        return "figure";
      case "figcaption":
        return "caption";
      case "img":
        return "img";
      case "svg":
        return element.getAttribute("role") === "img" ? "img" : null;
      case "form": {
        const name = element.getAttribute("aria-label") || element.getAttribute("aria-labelledby");
        return name ? "form" : null;
      }
      case "input": {
        const type = String(element.getAttribute("type") || "text").toLowerCase();
        if (type === "checkbox") return "checkbox";
        if (type === "radio") return "radio";
        if (type === "range") return "slider";
        if (type === "button" || type === "submit" || type === "reset") return "button";
        return "textbox";
      }
      case "select":
        return "combobox";
      case "textarea":
        return "textbox";
      case "p":
        return "paragraph";
      case "pre":
      case "code":
        return "code";
      default:
        return null;
    }
  }

  function visit(element, depth) {
    if (nodes.length >= MAX_NODES || !visible(element)) return;
    const role = implicitRole(element);
    if (role) {
      const entry = {
        role,
        name: accessibleName(element, role),
        tag: element.tagName.toLowerCase(),
        depth,
      };
      if (role === "heading") {
        entry.level = Number(element.tagName.slice(1));
      }
      if (role === "cell" || role === "columnheader" || role === "rowheader") {
        entry.scope = element.getAttribute("scope") || "";
        entry.column = Array.from(element.parentElement ? element.parentElement.children : []).indexOf(
          element,
        );
      }
      if (role === "img") {
        entry.alt = element.getAttribute("alt") || "";
      }
      nodes.push(entry);
    }
    for (const child of Array.from(element.children)) {
      visit(child, role ? depth + 1 : depth);
    }
  }

  if (document.body) visit(document.body, 0);

  const counts = {
    heading: 0,
    landmark: 0,
    link: 0,
    img: 0,
    table: 0,
    list: 0,
    total: nodes.length,
  };
  for (const node of nodes) {
    if (node.role === "heading") counts.heading += 1;
    if (["banner", "main", "navigation", "contentinfo", "complementary", "region", "form"].includes(node.role)) {
      counts.landmark += 1;
    }
    if (node.role === "link") counts.link += 1;
    if (node.role === "img") counts.img += 1;
    if (node.role === "table") counts.table += 1;
    if (node.role === "list") counts.list += 1;
  }

  return JSON.stringify({
    source: "host-js-aria-snapshot-v1",
    note:
      "Host-side ARIA projection. The render window is offscreen and has no accessibility client, so this is not a native WKWebView AX tree capture.",
    language: document.documentElement.lang || "",
    counts,
    nodes,
  });
})()
