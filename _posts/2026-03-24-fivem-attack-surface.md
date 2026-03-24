---
layout: post
title: "FiveM Is a Real Attack Surface"
date: 2026-03-24
---

Reframe the threat model: most owners think security = anticheat. A FiveM server is a networked application stack
— it deserves to be treated like one.

---
# Section 1 — Unvalidated Server Events

Events: the basis of matter... No really!

FiveM scripts are pieces of code that are (usualy) split in two: server-side and client-side. While the server side is away from clients it can easely be thought of as a safe environement, away from threat actors and user-induced bugs; same cannot be said for the client code, that runs directly on the client machine and is therefore inherently unsafe.
Events are the basis of communication between these two layers, alowing the client and the server to speak relatively freely (based on common contracts).

Let's take this example:
```lua
-- server.lua
RegisterNetEvent('bank:withdraw')
AddEventHandler('bank:withdraw', function(amount)
    local src = source
    removeMoney(src, amount)
end)
```
We can see here

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