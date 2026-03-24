---
layout: post
title: "FiveM Is a Real Attack Surface"
date: 2026-03-24
---

Reframe the threat model: most owners think security = anticheat. A FiveM server is a networked application stack
— it deserves to be treated like one.

---
# Section 1 — Unvalidated Server Events

FiveM scripts are typically split into two layers: server-side and client-side. Because the server
runs in a controlled environment, it is easy to assume it is also a safe one — isolated from threat
actors and untrusted input. That assumption is where things break down.

The two layers communicate through events. A client triggers a named event; the server listens for
it and acts. The problem is that **any connected client can fire any registered server event by
name**, with any arguments they choose.

Consider this:
```lua
-- server.lua
RegisterNetEvent('bank:withdraw')
AddEventHandler('bank:withdraw', function(amount)
    local src = source
    removeMoney(src, amount)
end)
```
We can see here a simple withdrawing function running the server-side. This snippet can be called by the client in a functions that looks like:
```lua
-- client.lua

-- Function called when the player confirms a withdrawal in the banking UI
function OnWithdrawConfirmed(amount)
    TriggerServerEvent('bank:withdraw', amount)
end
```

- How the event system works: any connected client can trigger any registered server event by name
- What gets abused: economy manipulation, privilege escalation, state corruption
- Why it happens: devs trust client-supplied arguments
- Mitigation: validate every argument server-side — type, range, plausibility, player state

---
# Section 2 — The NUI / Web Layer

- NUI is a Chromium-based browser embedded in the client with a bridge to Lua
- Risk: XSS in NUI executes in a privileged context with access to the message bridge
- Common pattern: resources rendering player-controlled strings (names, messages) via innerHTML
- Mitigation: textContent over innerHTML, Content Security Policy, minimal NUI bridge exposure

---
# Section 3 — Supply Chain Risk from Community Scripts

- Most servers run unaudited third-party code from GitHub/forums/resellers
- What malicious scripts do: backdoors (hidden event handlers), data exfiltration via HTTP, delayed payloads
- Reseller risk: modified copies without visible history
- Mitigation: read server-side files before install, audit PerformHttpRequest calls, check for hardcoded key
  patterns, prefer auditable repos, minimal OS permissions for the server process

---
Pre-Install Checklist

A short checklist (7 items) covering HTTP calls, event handlers, NUI innerHTML, hardcoded keys, commit history,
source integrity, and staging test.

---
Closing

Low attacker bar, soft targets, simple fixes. Reframe: the gap between exposed and defensible is attention, not
expertise.

---