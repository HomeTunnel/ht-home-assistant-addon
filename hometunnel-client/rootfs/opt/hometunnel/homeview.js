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
    over_limit: "Monitoring is paused. Choose up to 5 devices and 3 TCP services, then review and confirm sharing to resume.",
    review_labels: "Remove addresses or private identifiers from shared labels, then review and confirm sharing.",
    review_settings: "HomeTunnel rejected these monitoring settings. Review your shared labels and checks, then confirm any corrections.",
  };
  const errors = {
    permission_denied: "Homeview requires an administrator signed in through Home Assistant.",
    core_unavailable: "Home Assistant is unavailable. Select Review sharing again when Core is running. Your draft is still here.",
    inventory_too_large: "The Home Assistant inventory exceeds the discovery limit.",
    selection_changed: "Pairing or settings changed. Review the current checks before sharing.",
    confirmation_expired: "The confirmation expired. Select Review sharing to review your draft again.",
    device_limit: "Choose up to 5 devices. Remove all selected entities from a device to free a slot.",
    tcp_limit: "Choose up to 3 local TCP services.",
    entity_changed: "This entity is no longer available for this device. Remove this row and use the picker to select it again.",
    check_changed: "This entity no longer supports the chosen value check. Turn off that check or select the entity again.",
    custom_label_required: "The suggested device name cannot be shared. Select Customize shared label and enter a label of 1 to 64 characters without addresses or identifiers.",
    v2_required: "The portal must support Homeview V2 to save these checks.",
    no_checks: "Choose at least one entity, TCP service, or Home Assistant API check.",
    invalid_settings: "Review the check labels, entity selections, and TCP addresses or ports.",
    invalid_label: "Enter a shared label of 1 to 64 characters. Remove leading or trailing whitespace, credentials, and private identifiers.",
    address_in_label: "Remove IP addresses, hostnames or network URLs from shared labels.",
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
    if (!response.ok) throw Object.assign(new Error(payload.error), { rows: payload.rowErrors });
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
      draftChanged();
    });
    const error = document.createElement("p");
    error.className = "muted";
    error.setAttribute("role", "alert");
    error.hidden = true;
    row.homeviewError = error;
    row.append(heading, remove, error);
    parent.append(row);
    return row;
  }

  function entityRow(key, name, monitors, candidate, previous = {}) {
    const row = item(entities, name, () => entityRows.delete(key));
    const group = candidate?.group ?? monitors[0].deviceSlot;
    const typed = monitors.find((m) => m.kind !== "entity_availability");
    const availability = monitors.find((m) => m.kind === "entity_availability");
    const custom = input("", { type: "checkbox", checked: previous.custom ?? Boolean(monitors.length) });
    if (candidate) field(row, "Customize shared label", custom);
    const label = input(previous.label ?? availability?.label ?? typed?.label ?? candidate?.device, { maxLength: 64 });
    field(row, "Shared label", label);
    const available = input("", { type: "checkbox", checked: previous.available ?? (Boolean(availability) || !monitors.length) });
    if (availability || candidate) field(row, "Share availability", available);
    const kind = typed?.kind ?? candidate?.kind;
    const value = input("", { type: "checkbox", checked: previous.value ?? Boolean(typed) });
    if (kind) field(row, "Share " + kinds[kind].toLowerCase(), value);
    // Older settings may have separate approved labels for the two checks.
    const separate = typed && availability && typed.label !== availability.label;
    const valueLabel = separate ? input(previous.valueLabel ?? typed.label, { maxLength: 64 }) : null;
    if (valueLabel) field(row, "Shared label for value", valueLabel);
    const threshold = kind === "battery_percent"
      ? input(previous.threshold ?? typed?.lowThreshold, { type: "number", min: "0", max: "95", placeholder: "20" })
      : null;
    if (threshold) field(row, "Low battery threshold (%)", threshold);
    function updateFields() {
      label.disabled = Boolean(candidate && !custom.checked);
      label.required = !label.disabled && (available.checked || (value.checked && !valueLabel));
      if (valueLabel) {
        valueLabel.disabled = label.disabled || !value.checked;
        valueLabel.required = !valueLabel.disabled;
      }
      if (threshold) threshold.disabled = !value.checked;
    }
    updateFields();
    let suggestion = candidate?.device;
    function showSuggestion() {
      label.value = suggestion;
      if (valueLabel) valueLabel.value = suggestion;
    }
    custom.addEventListener("input", () => {
      if (!custom.checked) showSuggestion();
      updateFields();
    });
    function toggleCheck(event) {
      const control = event.currentTarget;
      const otherChecked = control === available ? Boolean(kind && value.checked) : available.checked;
      if (control.checked && !otherChecked && deviceLimitReached(usage(row).groups, group)) {
        control.checked = false;
        row.homeviewError.textContent = errors.device_limit;
        row.homeviewError.hidden = false;
        event.stopPropagation();
        return;
      }
      updateFields();
    }
    available.addEventListener("input", toggleCheck);
    value.addEventListener("input", toggleCheck);
    const read = () => {
      const checks = [];
      const usesSuggestion = candidate && !custom.checked;
      const fields = (saved, control) => ({
        ...(candidate ? { key: candidate.key } : { saved: saved.id }),
        ...(usesSuggestion ? {} : { label: control.value }),
      });
      if (available.checked) {
        checks.push({ kind: "entity_availability", ...fields(availability, label) });
      }
      if (kind && value.checked) {
        checks.push({ kind, ...fields(typed, valueLabel ?? label),
          ...(threshold?.value ? { lowThreshold: Number(threshold.value) } : {}) });
      }
      return checks;
    };
    const draft = () => ({ custom: custom.checked, label: label.value, available: available.checked, value: value.checked,
      valueLabel: valueLabel?.value, threshold: threshold?.value });
    const updateSuggestion = (reviewedLabel) => {
      if (candidate && !custom.checked) {
        suggestion = reviewedLabel;
        showSuggestion();
      }
    };
    const active = () => available.checked || Boolean(kind && value.checked);
    entityRows.set(key, { row, read, monitors, candidate, draft, updateSuggestion, active,
      group, legacy: monitors[0]?.legacyDevice });
  }

  function tcpRow(check = {}) {
    const row = item(services, "TCP service");
    const label = input(check.label, { required: true, maxLength: 64 });
    const ip = input(check.ip, { required: true, maxLength: 15, placeholder: "192.168.1.50" });
    const port = input(check.port, { type: "number", min: "1", max: "65535", required: true });
    field(row, "Shared label", label);
    field(row, "Private IPv4 address", ip);
    field(row, "TCP port", port);
    row.homeviewRead = () => ({ kind: "tcp_service", label: label.value, ip: ip.value.trim(), port: Number(port.value) });
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
    for (const [key, monitors] of groups) {
      const { label, hint } = monitors[0];
      entityRow(key, hint ? label + " · " + hint : label, monitors);
    }
    $("disable").hidden = !state.enabled;
    $("open-picker").disabled = $("review").disabled = !state.paired;
    $("apply").textContent = state.enabled ? "Save and share these checks" : "Enable and share these checks";
    $("picker").hidden = true;
    pickerRequest?.abort();
    clearTimeout(pickerTimer);
    updateCounts();
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
    results.disabled = $("pick").disabled = $("previous").disabled = $("next").disabled = true;
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
      results.disabled = false;
      $("picker-status").textContent = page.items.length ? "" : "No available entities match this search.";
    } catch (error) {
      if (request.signal.aborted) return;
      $("picker-status").textContent = error.message === "core_unavailable"
        ? "Home Assistant is unavailable. Try finding an entity again when Core is running."
        : errors[error.message] || "Unable to load available entities.";
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
    results.disabled = $("pick").disabled = $("previous").disabled = $("next").disabled = true;
    clearTimeout(pickerTimer);
    pickerTimer = setTimeout(() => void discover(0), 250);
  });
  $("previous").addEventListener("click", () => void discover(Math.max(0, pageStart - 40)));
  $("next").addEventListener("click", () => { if (nextPage !== null) void discover(nextPage); });
  function usage(excludedRow) {
    const active = [...entityRows.values()].filter((selection) => selection.row !== excludedRow && selection.active());
    return { groups: new Set(active.map((selection) => selection.group)),
      legacy: active.some((selection) => selection.legacy), tcp: services.children.length };
  }

  function deviceLimitReached(groups, group) {
    return groups.size >= selected.maxDevices && !groups.has(group);
  }

  function updatePicker(groups) {
    const candidate = candidates.get(results.value);
    const alreadySelected = candidate && entityRows.get(candidate.key)?.candidate;
    const atLimit = candidate && deviceLimitReached(groups, candidate.group);
    $("pick").disabled = !candidate || Boolean(alreadySelected || atLimit);
    if (candidate) {
      $("picker-status").textContent = alreadySelected ? "This entity is already selected."
        : atLimit ? "The device limit is reached. You can still add entities from selected devices." : "";
    }
  }

  function updateCounts() {
    const { groups, legacy, tcp } = usage();
    $("device-count").textContent = groups.size + " of " + (selected.maxDevices ?? 5) + " devices selected";
    $("tcp-count").textContent = tcp + " of " + (selected.maxTcpServices ?? 3) + " services selected";
    $("legacy-devices").hidden = !legacy;
    $("add-tcp").disabled = !selected.paired || tcp >= selected.maxTcpServices;
    if (!$("picker").hidden && !results.disabled) updatePicker(groups);
  }

  function draftChanged() {
    discardPreview();
    updateCounts();
  }

  results.addEventListener("change", () => updatePicker(usage().groups));
  $("pick").addEventListener("click", () => {
    const candidate = candidates.get(results.value);
    if (!candidate || $("pick").disabled) return;
    const existing = entityRows.get(candidate.key);
    existing?.row.remove();
    entityRow(candidate.key, candidate.device + " · " + candidate.name, existing?.monitors ?? [], candidate, existing?.draft());
    draftChanged();
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
      if (error.message === "confirmation_expired") $("review").focus();
    } finally {
      busy = false;
      $("apply").disabled = $("disable").disabled = false;
    }
  }

  function readForm() {
    const entries = [];
    const add = (row, check, updateSuggestion) => entries.push({ row, check, updateSuggestion });
    if ($("ha").checked) add($("ha-label-row"), { kind: "ha_api", label: $("ha-label").value });
    for (const selection of entityRows.values()) {
      for (const check of selection.read()) add(selection.row, check, selection.updateSuggestion);
    }
    for (const row of services.children) add(row, row.homeviewRead());
    return entries;
  }

  $("ha").addEventListener("change", updateHa);
  $("add-tcp").addEventListener("click", () => { tcpRow().focus(); draftChanged(); });
  form.addEventListener("input", (event) => {
    if ($("picker").contains(event.target)) return;
    const alert = event.target.closest(".homeview-item")?.homeviewError;
    if (alert) alert.hidden = true;
    draftChanged();
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !selected?.paired) return;
    discardPreview();
    $("error").textContent = "";
    const entries = readForm();
    const monitors = entries.map(({ check }) => check);
    for (const { row } of entries) {
      if (row.homeviewError) {
        row.homeviewError.hidden = true;
        row.homeviewError.textContent = "";
      }
    }
    if (!monitors.length || monitors.length > selected.maxMonitors) {
      $("error").textContent = monitors.length ? "Choose up to " + selected.maxMonitors + " checks." : errors.no_checks;
      return;
    }
    const { groups, tcp } = usage();
    if (groups.size > selected.maxDevices || tcp > selected.maxTcpServices) {
      $("error").textContent = groups.size > selected.maxDevices ? errors.device_limit : errors.tcp_limit;
      return;
    }
    const revision = selected.revision;
    const currentForm = JSON.stringify(monitors);
    let formChanged = false;
    const invalidate = (event) => { if (!$("picker").contains(event.target)) formChanged = true; };
    form.addEventListener("input", invalidate);
    const stillCurrent = () => !formChanged && revision === selected?.revision
      && JSON.stringify(readForm().map(({ check }) => check)) === currentForm;
    busy = true;
    try {
      const result = await call("POST", "/preview", { revision, monitors });
      if (!stillCurrent()) return;
      preview = result.preview;
      for (const [index, check] of result.monitors.entries()) {
        entries[index]?.updateSuggestion?.(check.label);
        const line = document.createElement("li");
        const threshold = check.kind === "battery_percent" ? " · threshold " + (check.lowThreshold ?? 20) + "%" : "";
        line.textContent = check.label + " · " + kinds[check.kind] + threshold;
        $("shared").append(line);
      }
      $("preview").hidden = false;
      $("apply").focus();
    } catch (error) {
      if (!stillCurrent()) return;
      let inline = false;
      for (const [index, code] of Object.entries(error.rows ?? {})) {
        const alert = entries[index]?.row.homeviewError;
        if (alert) {
          if (!alert.textContent) alert.textContent = errors[code];
          alert.hidden = false;
          inline = true;
        }
      }
      $("error").textContent = inline ? "Review the highlighted checks before sharing."
        : errors[error.message] || "Unable to preview sharing.";
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
