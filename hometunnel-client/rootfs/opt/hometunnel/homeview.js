"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById("homeview-" + id);
  const form = $("form");
  const entities = $("entities");
  const services = $("services");
  const results = $("results");
  const kinds = {
    ha_api: "Home Assistant API reachability",
    entity_availability: "Available, unavailable or unknown",
    entity_contact: "Open or closed",
    entity_light: "Light on or off",
    entity_switch: "Switch on or off",
    entity_connectivity: "Connected or disconnected",
    battery_binary: "Battery low or normal",
    battery_percent: "Battery percentage",
    tcp_service: "Local TCP reachability",
  };
  const statuses = {
    off: "Monitoring is off.",
    stopping: "Local checks have stopped. Waiting to update the portal.",
    portal_off: "Waiting for the portal owner to enable monitoring.",
    owner_confirmation_required: "Waiting for the portal owner to enable monitoring.",
    paused: "Monitoring is paused in the portal.",
    deleted: "Monitoring data was deleted in the portal.",
    never_enabled: "Waiting for authorization to enable monitoring.",
    waiting_portal: "Waiting for the portal.",
    reporting: "Selected checks are reporting to HomeTunnel.",
    unsupported: "Homeview is unavailable on this portal.",
    v2_required: "These checks require a Homeview V2 portal.",
    pairing_required: "Check this add-on’s pairing in HomeTunnel.",
    clock_error: "Check the Home Assistant system clock.",
    review_labels: "Review your shared labels to resume reporting. Remove any addresses or private identifiers.",
  };
  const errors = {
    permission_denied: "Homeview requires an administrator signed in through Home Assistant.",
    core_unavailable: "Home Assistant is unavailable. Try again when Core is running.",
    inventory_too_large: "The Home Assistant inventory exceeds the discovery limit.",
    inventory_expired: "The device list expired. Refresh it and select the entity again.",
    selection_changed: "Pairing or settings changed. Review the current checks before sharing.",
    v2_required: "The portal must support Homeview V2 to save these checks.",
    no_checks: "Choose at least one entity, TCP service, or Home Assistant API check.",
    invalid_settings: "Review the check labels, entity selections, and TCP addresses or ports.",
    address_in_label: "Remove IP addresses or hostnames from shared labels.",
  };
  let selected;
  let preview;
  let busy = false;
  let pickerRequest;
  let pickerTimer;
  let pageStart = 0;
  let nextPage = null;
  let candidates = new Map();
  const entityRows = new Map();

  async function call(method, path = "", body, signal) {
    const response = await fetch("./api/homeview/local" + path, {
      method, signal, cache: "no-store",
      headers: { "X-Homeview-UI": "1", "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error);
    return payload;
  }

  function discardPreview() {
    preview = null;
    $("preview").hidden = true;
    $("shared").replaceChildren();
  }

  function input(value, attributes = {}) {
    const node = document.createElement("input");
    Object.assign(node, { value: value ?? "", autocomplete: "off", ...attributes });
    return node;
  }

  function field(parent, text, control) {
    const label = document.createElement("label");
    const span = document.createElement("span");
    span.textContent = text;
    label.append(span, control);
    parent.append(label);
  }

  function item(parent, title, onRemove) {
    const row = document.createElement("div");
    row.className = "homeview-item";
    const heading = document.createElement("div");
    heading.textContent = title;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "secondary";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      onRemove?.();
      row.remove();
      discardPreview();
    });
    row.append(heading, remove);
    parent.append(row);
    return row;
  }

  function entityRow(key, name, monitors, candidate) {
    const row = item(entities, name, () => entityRows.delete(key));
    const label = input(monitors[0]?.label, { required: true, maxLength: 64 });
    field(row, "Shared label", label);
    const typed = monitors.find((m) => m.kind !== "entity_availability");
    const availability = monitors.find((m) => m.kind === "entity_availability");
    const kind = typed?.kind ?? candidate?.kind;
    const value = input("", { type: "checkbox", checked: Boolean(typed) });
    if (kind) field(row, "Share " + kinds[kind].toLowerCase(), value);
    const threshold = kind === "battery_percent"
      ? input(typed?.lowThreshold, { type: "number", min: "0", max: "95", placeholder: "20", disabled: !value.checked })
      : null;
    if (threshold) {
      field(row, "Low battery threshold (%)", threshold);
      value.addEventListener("change", () => { threshold.disabled = !value.checked; });
    }
    const read = () => {
      const checks = [];
      const labelText = label.value.trim();
      if (availability || candidate) {
        checks.push({ kind: "entity_availability", label: labelText,
          ...(availability ? { saved: availability.id } : { key: candidate.key }) });
      }
      if (kind && value.checked) {
        checks.push({ kind, label: labelText, ...(typed ? { saved: typed.id } : { key: candidate.key }),
          ...(threshold?.value ? { lowThreshold: Number(threshold.value) } : {}) });
      }
      return checks;
    };
    entityRows.set(key, { row, read, monitors });
  }

  function tcpRow(check = {}) {
    const row = item(services, "TCP service");
    const label = input(check.label, { required: true, maxLength: 64 });
    const ip = input(check.ip, { required: true, maxLength: 15, placeholder: "192.168.1.50" });
    const port = input(check.port, { type: "number", min: "1", max: "65535", required: true });
    field(row, "Shared label", label);
    field(row, "Private IPv4 address", ip);
    field(row, "TCP port", port);
    row.homeviewRead = () => ({ kind: "tcp_service", label: label.value.trim(), ip: ip.value.trim(), port: Number(port.value) });
    return label;
  }

  function displayStatus(state) {
    $("status").textContent = state.paired ? statuses[state.status] || statuses.waiting_portal
      : "Pair this add-on with HomeTunnel to set up Homeview.";
    $("portal-help").textContent = state.activationAvailable ? "The portal owner has authorized activation from this add-on."
      : state.protocol === 1 ? "This portal uses Homeview V1. Keep the Home Assistant API check enabled. Contact, light and switch values require V2."
      : "If monitoring is paused or needs approval, enable it for this home in the HomeTunnel portal.";
  }

  function updateHa() {
    $("ha-label-row").hidden = !$("ha").checked;
    $("ha-label").required = $("ha").checked;
  }

  function render(state) {
    selected = state;
    displayStatus(state);
    entities.replaceChildren();
    services.replaceChildren();
    entityRows.clear();
    const groups = new Map();
    const ha = state.monitors.find((monitor) => monitor.kind === "ha_api");
    $("ha").checked = Boolean(ha);
    $("ha-label").value = ha?.label ?? "Home Assistant";
    updateHa();
    for (const monitor of state.monitors) {
      if (monitor.kind === "tcp_service") tcpRow(monitor);
      else if (monitor.kind !== "ha_api") {
        const group = monitor.selector || monitor.entityGroupId || monitor.id;
        const checks = groups.get(group) ?? [];
        checks.push(monitor);
        groups.set(group, checks);
      }
    }
    for (const [key, monitors] of groups) entityRow(key, monitors[0].label, monitors);
    $("disable").hidden = !state.enabled;
    $("open-picker").disabled = $("add-tcp").disabled = $("review").disabled = !state.paired;
    $("apply").textContent = state.enabled ? "Save and share these checks" : "Enable and share these checks";
    $("picker").hidden = true;
    pickerRequest?.abort();
    discardPreview();
  }

  async function load(reset = false) {
    if (busy || (!reset && document.hidden)) return;
    try {
      const state = await call("GET");
      if (busy) return;
      if (!selected || reset || state.revision !== selected.revision) render(state);
      else {
        selected = state;
        displayStatus(state);
      }
    } catch (error) {
      $("status").textContent = errors[error.message] || "Monitoring settings are unavailable.";
      if (error.message === "permission_denied") {
        render({ paired: false, monitors: [], status: "off" });
        $("status").textContent = errors.permission_denied;
      }
    }
  }

  async function discover(offset) {
    pickerRequest?.abort();
    const request = new AbortController();
    pickerRequest = request;
    $("picker-status").textContent = "Loading available entities…";
    $("pick").disabled = $("previous").disabled = $("next").disabled = true;
    try {
      const params = new URLSearchParams({ q: $("search").value, offset });
      const page = await call("GET", "/discovery?" + params, undefined, request.signal);
      if (request.signal.aborted) return;
      pageStart = offset;
      nextPage = page.next;
      candidates = new Map(page.items.map((candidate) => [candidate.key, candidate]));
      results.replaceChildren(new Option("Choose an entity", ""));
      const groups = new Map();
      for (const candidate of page.items) {
        if (!groups.has(candidate.group)) {
          const group = document.createElement("optgroup");
          group.label = candidate.device;
          groups.set(candidate.group, group);
          results.append(group);
        }
        groups.get(candidate.group).append(new Option(candidate.name + " · " + candidate.hint, candidate.key));
      }
      $("previous").disabled = !pageStart;
      $("next").disabled = nextPage === null;
      $("picker-status").textContent = page.items.length ? "" : "No available entities match this search.";
    } catch (error) {
      if (request.signal.aborted) return;
      $("picker-status").textContent = errors[error.message] || "Unable to load available entities.";
      candidates.clear();
      results.replaceChildren();
    }
  }

  $("open-picker").addEventListener("click", () => {
    $("picker").hidden = false;
    $("search").focus();
    void discover(0);
  });
  $("search").addEventListener("input", () => {
    pickerRequest?.abort();
    $("pick").disabled = $("previous").disabled = $("next").disabled = true;
    clearTimeout(pickerTimer);
    pickerTimer = setTimeout(() => void discover(0), 250);
  });
  $("previous").addEventListener("click", () => void discover(Math.max(0, pageStart - 40)));
  $("next").addEventListener("click", () => { if (nextPage !== null) void discover(nextPage); });
  results.addEventListener("change", () => { $("pick").disabled = !candidates.has(results.value); });
  $("pick").addEventListener("click", () => {
    const candidate = candidates.get(results.value);
    if (!candidate) return;
    const existing = entityRows.get(candidate.key);
    if (existing && !existing.monitors.length) return;
    existing?.row.remove();
    entityRow(candidate.key, candidate.device + " · " + candidate.name, existing?.monitors ?? [], candidate);
    discardPreview();
  });

  async function change(body) {
    if (busy) return;
    busy = true;
    $("apply").disabled = $("disable").disabled = true;
    $("error").textContent = "";
    try {
      render(await call("POST", "", body));
    } catch (error) {
      discardPreview();
      $("error").textContent = errors[error.message] || "Unable to save Homeview settings.";
    } finally {
      busy = false;
      $("apply").disabled = $("disable").disabled = false;
    }
  }

  function readForm() {
    const monitors = [];
    if ($("ha").checked) monitors.push({ kind: "ha_api", label: $("ha-label").value.trim() });
    for (const selection of entityRows.values()) monitors.push(...selection.read());
    for (const row of services.children) monitors.push(row.homeviewRead());
    return monitors;
  }

  $("ha").addEventListener("change", updateHa);
  $("add-tcp").addEventListener("click", () => { tcpRow().focus(); discardPreview(); });
  form.addEventListener("input", discardPreview);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !selected?.paired) return;
    discardPreview();
    $("error").textContent = "";
    const monitors = readForm();
    if (!monitors.length || monitors.length > selected.maxMonitors) {
      $("error").textContent = monitors.length ? "Choose up to " + selected.maxMonitors + " checks." : errors.no_checks;
      return;
    }
    const revision = selected.revision;
    const currentForm = JSON.stringify(monitors);
    let formChanged = false;
    const invalidate = () => { formChanged = true; };
    form.addEventListener("input", invalidate);
    busy = true;
    try {
      const result = await call("POST", "/preview", { revision, monitors });
      if (formChanged || revision !== selected?.revision) return;
      // Adding or removing rows can occur without firing an input event.
      if (JSON.stringify(readForm()) !== currentForm) return;
      preview = result.preview;
      for (const check of result.monitors) {
        const line = document.createElement("li");
        const threshold = check.kind === "battery_percent" ? " · threshold " + (check.lowThreshold ?? 20) + "%" : "";
        line.textContent = check.label + " · " + kinds[check.kind] + threshold;
        $("shared").append(line);
      }
      $("preview").hidden = false;
      $("apply").focus();
    } catch (error) {
      $("error").textContent = errors[error.message] || "Unable to preview sharing.";
    } finally {
      form.removeEventListener("input", invalidate);
      busy = false;
    }
  });
  $("apply").addEventListener("click", () => { if (preview) void change({ preview }); });
  $("disable").addEventListener("click", () => void change({ enabled: false }));
  $("details").addEventListener("toggle", () => { if ($("details").open) void load(false); });
  void load(true);
  window.setInterval(() => { if ($("details").open) void load(); }, 15000);
});
