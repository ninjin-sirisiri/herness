// H3 render metrics, evaluated in the dedicated `h3-render-evidence` content
// world so candidate page scripts cannot replace the DOM helpers used here.
// The script returns a JSON string; the native bridge stores that exact object
// in the versioned manifest. It never contacts the network.
(() => {
  "use strict";

  const MAX_OVERFLOW_SAMPLES = 50;
  const MAX_OVERLAP_PAIRS = 20;
  const MAX_BLOCK_SAMPLES = 200;
  const MAX_CONTRAST_SAMPLES = 30;

  const visible = (element) => {
    if (!(element instanceof Element)) return false;
    if (element.getClientRects().length === 0) return false;
    const style = getComputedStyle(element);
    return style.visibility !== "hidden" && Number(style.opacity || "1") > 0;
  };

  const rectOf = (element) => {
    const rect = element.getBoundingClientRect();
    return {
      x: round(rect.x),
      y: round(rect.y),
      width: round(rect.width),
      height: round(rect.height),
      top: round(rect.top),
      left: round(rect.left),
      bottom: round(rect.bottom),
      right: round(rect.right),
    };
  };

  function round(value) {
    return Math.round(value * 100) / 100;
  }

  function selectorOf(element) {
    if (element.id) return `#${element.id}`;
    const tag = element.tagName.toLowerCase();
    const className = String(element.className || "")
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .join(".");
    return className ? `${tag}.${className}` : tag;
  }

  function parseColor(value) {
    const match = String(value || "").match(
      /rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/i,
    );
    if (!match) return null;
    return {
      r: Number(match[1]),
      g: Number(match[2]),
      b: Number(match[3]),
      a: match[4] === undefined ? 1 : Number(match[4]),
    };
  }

  function composite(top, bottom) {
    if (!top) return bottom;
    const alpha = top.a + bottom.a * (1 - top.a);
    if (alpha <= 0) return { r: 0, g: 0, b: 0, a: 0 };
    return {
      r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
      g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
      b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
      a: alpha,
    };
  }

  function backgroundOf(element) {
    let current = element;
    let background = { r: 255, g: 255, b: 255, a: 1 };
    const layers = [];
    while (current) {
      const color = parseColor(getComputedStyle(current).backgroundColor);
      if (color && color.a > 0) layers.push(color);
      current = current.parentElement;
    }
    for (let index = layers.length - 1; index >= 0; index -= 1) {
      background = composite(layers[index], background);
    }
    return background;
  }

  function luminance(color) {
    const channel = (value) => {
      const normalized = value / 255;
      return normalized <= 0.04045
        ? normalized / 12.92
        : Math.pow((normalized + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b);
  }

  function contrastRatio(foreground, background) {
    const front = luminance(composite(foreground, background));
    const back = luminance(background);
    const lighter = Math.max(front, back);
    const darker = Math.min(front, back);
    return (lighter + 0.05) / (darker + 0.05);
  }

  function fontSizeOf(element) {
    const value = getComputedStyle(element).fontSize || "0px";
    return Number.parseFloat(value) || 0;
  }

  function lineHeightRatio(element, fontSize) {
    const style = getComputedStyle(element);
    if (!fontSize) return 0;
    if (style.lineHeight === "normal") return 1.2;
    const lineHeight = Number.parseFloat(style.lineHeight);
    return Number.isFinite(lineHeight) ? round(lineHeight / fontSize) : 0;
  }

  const elementCount = document.querySelectorAll("*").length;
  const textLength = (document.body ? document.body.innerText || "" : "").length;
  const images = Array.from(document.images || []);
  const failedImages = images.filter((image) => image.complete && image.naturalWidth === 0);
  const svgElements = document.querySelectorAll("svg, svg *").length;
  let styleSheetRules = 0;
  for (const sheet of Array.from(document.styleSheets || [])) {
    try {
      styleSheetRules += sheet.cssRules ? sheet.cssRules.length : 0;
    } catch (_error) {
      styleSheetRules += 0;
    }
  }

  const overflowSamples = [];
  let overflowingElements = 0;
  for (const element of Array.from(document.querySelectorAll("body *"))) {
    if (!visible(element)) continue;
    const style = getComputedStyle(element);
    const horizontal = element.scrollWidth > element.clientWidth + 1;
    const vertical = element.scrollHeight > element.clientHeight + 1;
    if (!horizontal && !vertical) continue;
    overflowingElements += 1;
    if (overflowSamples.length < MAX_OVERFLOW_SAMPLES) {
      overflowSamples.push({
        selector: selectorOf(element),
        horizontal,
        vertical,
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
        overflowX: style.overflowX,
        overflowY: style.overflowY,
      });
    }
  }

  const pageHorizontal =
    document.documentElement.scrollWidth > window.innerWidth + 1 ||
    (document.body ? document.body.scrollWidth > window.innerWidth + 1 : false);

  const overlapCandidates = Array.from(
    document.querySelectorAll("main > section, main > figure, main > table, .cards > .card, footer"),
  ).filter(visible);
  const overlaps = [];
  for (let left = 0; left < overlapCandidates.length; left += 1) {
    for (let right = left + 1; right < overlapCandidates.length; right += 1) {
      const a = overlapCandidates[left];
      const b = overlapCandidates[right];
      if (a.contains(b) || b.contains(a)) continue;
      const first = a.getBoundingClientRect();
      const second = b.getBoundingClientRect();
      const width = Math.min(first.right, second.right) - Math.max(first.left, second.left);
      const height = Math.min(first.bottom, second.bottom) - Math.max(first.top, second.top);
      if (width > 1 && height > 1) {
        overlaps.push({
          first: selectorOf(a),
          second: selectorOf(b),
          area: round(width * height),
        });
      }
    }
  }

  const textSelectors = "p, li, h1, h2, h3, h4, h5, h6, td, th, small, code, figcaption, a";
  let minFontSize = Number.POSITIVE_INFINITY;
  let minLineHeight = Number.POSITIVE_INFINITY;
  let smallTextCount = 0;
  let contrastFailures = 0;
  const contrastSamples = [];
  const readabilitySamples = [];
  for (const element of Array.from(document.querySelectorAll(textSelectors))) {
    if (!visible(element)) continue;
    const text = (element.textContent || "").trim();
    if (!text) continue;
    const fontSize = fontSizeOf(element);
    if (fontSize <= 0) continue;
    const ratio = lineHeightRatio(element, fontSize);
    minFontSize = Math.min(minFontSize, fontSize);
    minLineHeight = Math.min(minLineHeight, ratio);
    const background = backgroundOf(element);
    const foreground = parseColor(getComputedStyle(element).color);
    const contrast = foreground ? contrastRatio(foreground, background) : 21;
    const bold = Number(getComputedStyle(element).fontWeight || "400") >= 700;
    const large = fontSize >= 24 || (bold && fontSize >= 18.66);
    const threshold = large ? 3 : 4.5;
    if (fontSize < 12) {
      smallTextCount += 1;
      if (readabilitySamples.length < MAX_CONTRAST_SAMPLES) {
        readabilitySamples.push({
          selector: selectorOf(element),
          reason: "small_text",
          fontSizePx: round(fontSize),
        });
      }
    }
    if (contrast + 0.05 < threshold) {
      contrastFailures += 1;
      if (contrastSamples.length < MAX_CONTRAST_SAMPLES) {
        contrastSamples.push({
          selector: selectorOf(element),
          contrast: round(contrast),
          threshold,
          fontSizePx: round(fontSize),
        });
      }
    }
  }
  if (!Number.isFinite(minFontSize)) minFontSize = 0;
  if (!Number.isFinite(minLineHeight)) minLineHeight = 0;

  const blockSelectors = ["header", "nav", "main", "h1", "table", "figure", ".cards", "footer"];
  const blocks = [];
  for (const selector of blockSelectors) {
    const element = document.querySelector(selector);
    if (element && visible(element) && blocks.length < MAX_BLOCK_SAMPLES) {
      blocks.push({ selector, rect: rectOf(element) });
    }
  }

  const focusable = Array.from(
    document.querySelectorAll(
      'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])',
    ),
  ).filter(visible);
  const outlineHeadings = Array.from(document.querySelectorAll("h1, h2, h3, h4, h5, h6"))
    .filter(visible)
    .map((heading) => ({
      level: Number(heading.tagName.slice(1)),
      text: (heading.textContent || "").replace(/\s+/g, " ").trim().slice(0, 200),
      selector: selectorOf(heading),
    }));
  const landmarks = Array.from(
    document.querySelectorAll("header, nav, main, aside, footer, form, section[aria-label], section[aria-labelledby]"),
  )
    .filter(visible)
    .map((landmark) => ({
      tag: landmark.tagName.toLowerCase(),
      name:
        landmark.getAttribute("aria-label") ||
        (landmark.getAttribute("aria-labelledby") || "")
          .split(/\s+/)
          .map((id) => document.getElementById(id))
          .filter(Boolean)
          .map((target) => (target.textContent || "").trim())
          .join(" ")
          .slice(0, 200),
      selector: selectorOf(landmark),
    }));

  const resources = Array.from(performance.getEntriesByType("resource") || [])
    .slice(0, 100)
    .map((entry) => ({
      name: entry.name,
      initiatorType: entry.initiatorType,
      transferSize: entry.transferSize,
      durationMs: round(entry.duration),
    }));

  return JSON.stringify({
    scriptVersion: "h3-render-metrics-v1",
    url: document.URL,
    title: document.title,
    lang: document.documentElement.lang || "",
    readyState: document.readyState,
    navigator: {
      userAgent: navigator.userAgent,
      appVersion: navigator.appVersion,
      platform: navigator.platform,
      language: navigator.language,
      languages: Array.from(navigator.languages || []),
      hardwareConcurrency: navigator.hardwareConcurrency || null,
    },
    viewport: {
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      devicePixelRatio: window.devicePixelRatio,
      scrollWidth: document.documentElement.scrollWidth,
      scrollHeight: document.documentElement.scrollHeight,
      screenWidth: window.screen ? window.screen.width : null,
      screenHeight: window.screen ? window.screen.height : null,
    },
    document: {
      elementCount,
      textLength,
      imageCount: images.length,
      failedImages: failedImages.length,
      svgElements,
      styleSheets: (document.styleSheets || []).length,
      styleSheetRules,
      fontStatus: document.fonts ? document.fonts.status : "unavailable",
    },
    overflow: {
      pageHorizontal,
      elementCount: overflowingElements,
      elements: overflowSamples,
    },
    overlap: {
      count: overlaps.length,
      pairs: overlaps.slice(0, MAX_OVERLAP_PAIRS),
    },
    readability: {
      minFontSizePx: round(minFontSize),
      minLineHeightRatio: round(minLineHeight),
      smallTextCount,
      contrastFailures,
      failures: smallTextCount + contrastFailures,
      samples: readabilitySamples,
      contrastSamples,
    },
    blocks,
    outline: {
      headings: outlineHeadings,
      landmarks,
    },
    keyboard: {
      focusableCount: focusable.length,
      tabOrder: focusable.slice(0, 50).map((element) => selectorOf(element)),
    },
    resources,
    candidateProbe: window.__H3_CANDIDATE_PROBE__ || null,
  });
})()
