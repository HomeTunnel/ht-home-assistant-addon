"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const $ = (name) => document.getElementById("homeview-" + name);
  const form = $("form");
  const rows = $("checks");
  const details = $("details");
  const kinds = {
    ha_api: "Home Assistant API",
    entity_availability: "Entity availability",
    entity_connectivity: "Connectivity binary sensor",
    battery_percent: "Battery percentage sensor",
    battery_binary: "Low battery binary sensor",
    tcp_service: "Local TCP port",
  };
  const statuses = {
    off: "Monitoring is off.",
    stopping: "Local checks have stopped. Waiting to update the portal.",
    portal_off: "Waiting for Homeview to be enabled for this home in the portal.",
    waiting_portal: "Waiting for the portal.",
    reporting: "Selected checks are reporting to HomeTunnel.",
    unsupported: "Homeview is unavailable on this portal.",
    pairing_required: "Check this add-on’s pairing in HomeTunnel.",
    clock_error: "Check the Home Assistant system clock.",
  };
  let selected = null;
  let preview = null;
  let busy = false;

  const call = (method, body) => fetch("./api/homeview/local", {
    method,
    cache: "no-store",
    headers: { "X-Homeview-UI": "1", "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  function notice(state) {
    $("status").textContent = state.paired
      ? (state.enabled && state.status === "off" ? statuses.waiting_portal : statuses[state.status] || statuses.off)
      : "Pair this add-on with HomeTunnel to set up Homeview.";
  }

  function discardPreview() {
    preview = null;
    $("preview").hidden = true;
  }

  function field(row, title, input) {
    const label = document.createElement("label");
    label.append(title, input);
    row.append(label);
    return label;
  }

  function input(name, value, type = "text") {
    const el = document.createElement("input");
    el.name = name;
    el.type = type;
    el.value = value ?? "";
    el.autocomplete = "off";
    return el;
  }

  function rowFor(check) {
    const row = document.createElement("fieldset");
    const legend = document.createElement("legend");
    legend.textContent = check.kind === "ha_api" ? kinds.ha_api : "Selected check";
    row.append(legend);
    const label = input("label", check.label);
    label.maxLength = 64;
    label.required = true;
    field(row, "Shared label", label);
    const kind = document.createElement("select");
    kind.name = "kind";
    for (const [value, title] of Object.entries(kinds)) {
      if ((check.kind === "ha_api") !== (value === "ha_api")) continue;
      kind.add(new Option(title, value));
    }
    kind.value = check.kind;
    field(row, "Check type", kind);

    if (check.kind !== "ha_api") {
      const entity = input("entity", check.entity);
      entity.placeholder = "sensor.example_battery";
      entity.maxLength = 255;
      const address = input("ip", check.ip);
      address.placeholder = "192.168.1.50";
      address.inputMode = "decimal";
      address.maxLength = 15;
      const port = input("port", check.port, "number");
      port.min = 1;
      port.max = 65535;
      const threshold = input("lowThreshold", check.lowThreshold, "number");
      threshold.min = 0;
      threshold.max = 95;
      threshold.placeholder = "20";
      const entityLabel = field(row, "Home Assistant entity ID", entity);
      const addressLabel = field(row, "Local IPv4 address", address);
      const portLabel = field(row, "TCP port", port);
      const thresholdLabel = field(row, "Low battery % (optional)", threshold);
      function updateFields() {
        const tcp = kind.value === "tcp_service";
        entityLabel.hidden = entity.disabled = tcp;
        addressLabel.hidden = portLabel.hidden = address.disabled = port.disabled = !tcp;
        thresholdLabel.hidden = threshold.disabled = kind.value !== "battery_percent";
        entity.required = !tcp;
        address.required = port.required = tcp;
      }
      kind.addEventListener("change", updateFields);
      updateFields();
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "secondary";
      remove.textContent = "Remove check";
      remove.addEventListener("click", () => {
        discardPreview();
        row.remove();
        $("add").disabled = false;
      });
      row.append(remove);
    }
    rows.append(row);
    return label;
  }

  function render(state) {
    selected = state;
    notice(state);
    rows.replaceChildren();
    for (const check of state.monitors) rowFor(check);
    $("disable").hidden = !state.enabled;
    $("add").disabled = !state.paired || rows.children.length >= 50;
    $("review").disabled = !state.paired;
    $("apply").textContent = state.enabled ? "Save and share these checks" : "Enable and share these checks";
    discardPreview();
  }

  async function load(reset = false) {
    if (busy || (!reset && document.hidden)) return;
    try {
      const res = await call("GET");
      if (!res.ok) throw Error();
      const state = await res.json();
      if (busy) return;
      if (!selected || reset) render(state);
      else notice(state);
    } catch {
      $("status").textContent = "Monitoring settings are unavailable.";
    }
  }

  async function save(body) {
    if (busy) return;
    busy = true;
    $("disable").disabled = $("apply").disabled = true;
    $("error").textContent = "";
    try {
      const result = await call("POST", body);
      if (result.status === 409) {
        $("error").textContent = "Settings changed in another tab. Reopen this panel to reload them.";
        return;
      }
      if (!result.ok) {
        $("error").textContent = body.enabled
          ? "Check the entity IDs, local addresses, ports, and approved labels."
          : "Unable to save the setting. Try stopping Homeview again.";
        return;
      }
      render(await result.json());
    } catch {
      $("error").textContent = "Unable to save Homeview settings.";
    } finally {
      busy = false;
      $("disable").disabled = $("apply").disabled = false;
    }
  }

  $("add").addEventListener("click", () => {
    if (!selected?.paired || rows.children.length >= 50) return;
    discardPreview();
    rowFor({ kind: "entity_availability" }).focus();
    $("add").disabled = rows.children.length >= 50;
  });
  form.addEventListener("input", discardPreview);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!selected?.paired || busy) return;
    const monitors = Array.from(rows.children, (row) => {
      const raw = (name) => row.querySelector("[name=" + name + "]")?.value.trim() || "";
      const kind = raw("kind");
      const check = { kind, label: raw("label") };
      if (kind === "tcp_service") {
        check.ip = raw("ip");
        check.port = Number(raw("port"));
      } else if (kind !== "ha_api") {
        check.entity = raw("entity");
        const low = raw("lowThreshold");
        if (kind === "battery_percent" && low !== "") check.lowThreshold = Number(low);
      }
      return check;
    });
    preview = { enabled: true, revision: selected.revision, monitors };
    $("shared").replaceChildren(...monitors.map((check) => {
      const li = document.createElement("li");
      li.textContent = check.label + " · " + kinds[check.kind] +
        (check.lowThreshold === undefined ? "" : " · low at " + check.lowThreshold + "%");
      return li;
    }));
    $("preview").hidden = false;
    $("apply").focus();
  });
  $("apply").addEventListener("click", () => { if (preview) void save(preview); });
  $("disable").addEventListener("click", () => void save({ enabled: false }));
  details.addEventListener("toggle", () => { if (details.open) void load(true); });
  void load(true);
  window.setInterval(() => { if (details.open) void load(); }, 10000);
});
