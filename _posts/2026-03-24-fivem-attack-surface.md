---
layout: post
title: "FiveM Is a Real Attack Surface"
date: 2026-03-24
toc: true
tags: [
  fivem, fivem-security, gta-roleplay, cfx,
  lua, lua-security, server-events, event-validation,
  nui, xss, web-security,
  supply-chain, supply-chain-security, third-party-scripts,
  game-server-security, game-server-hardening,
  security-awareness, red-team, penetration-testing,
  input-validation, client-server, roleplay-server
]
---

Why anticheats are useless — and why a cheater breaking your economy is the best outcome you can get. Most
owners frame security as anticheat. A FiveM server is a networked application stack, and it deserves to be
treated like one.

---

# Section 1 — Unvalidated Server Events

FiveM scripts are typically split into two layers: *server-side* and *client-side*. Client code runs on
the player's machine — meaning the player owns it and can do whatever they want with it. This is generally
well understood. What is less often considered is the implication for the server side: because the server
runs in a controlled environment, it is easy to assume it is also a safe one — isolated from threat actors
and untrusted input. That assumption is where things break down.

The two layers communicate through events. A client triggers a named event; the server listens for it and
acts. The problem is that **any connected client can fire any registered server event by name**, with any
arguments they choose.

## Case study

Consider this:

```lua
-- server.lua
RegisterNetEvent('bank:withdraw')
AddEventHandler('bank:withdraw', function(amount)
    local src = source
    removeMoney(src, amount)
end)
```

```lua
-- client.lua
function OnWithdrawConfirmed(amount) -- Called when player confirms a withdrawal
    TriggerServerEvent('bank:withdraw', amount)
end
```

This pattern is common across free and paid scripts on the *CFx forums*, *GitHub*, and the *Tebex*
marketplace. The server listens for the `bank:withdraw` event; when the client wants to withdraw, it fires
the event with `amount` as the argument. The caller's identity (`src`) is resolved server-side, so that
part is safe. The assumption being made — fatally — is that `amount` can be trusted. In a legitimate flow,
the client call is wrapped in checks at the client level:

- Is the user at a bank?
- Does the user have enough money?
- Is the user authorized to withdraw?

None of those checks exist on the server. They live on the client, where the attacker already has full
control.

Now let's put on our hacker hoodies and think red: what happens if we call the event directly,
bypassing the UI entirely?

> **Note:** The examples below are intentionally vague. The goal is not a hacking tutorial — these are
> well-known techniques in the offensive world, but the focus here is awareness, not execution.

By calling `bank:withdraw(100)` outside the normal UI flow, the withdrawal goes through without issue.
The character receives the money. The logs show a clean, legitimate transaction — performed from the
middle of the Sandy Shores desert. The service[^1] is vulnerable. So we keep digging.

```lua
-- server.lua
RegisterNetEvent('bank:transfer')
AddEventHandler('bank:transfer', function(usr1, usr2, amount)
    removeMoney(usr1, amount)
    addMoney(usr2, amount)
end)
```

Jackpot! `bank:transfer`, just a few lines below, has the same problem — and this time the attacker
controls both ends of the transaction. Run it in a loop across all players and the money flows to a
single account. The logs flag nothing; every entry looks like a legitimate transfer request. Only a
manual review would catch it, and only if the attacker was loud about it[^2].

Server events **can be called from anywhere, by anyone, with any arguments**. Think about what that means in practice.

- Your logs are empty
- Your paid anticheat didn't trigger
- Your staff doesn't realize

This is full compromise; in red teaming, this would be a failed audit.

## Remediation

👏 DON'T 👏 TRUST 👏 THE 👏 USER 👏

### Client files should contain the bare minimum

#### Scope your client code

Client code should only perform actions within its own scope — the client. Showing a visual effect on
the player's screen? Client code. Spawning a car, moving money, updating a database record? Server
code. If your client is doing more than presenting state and sending requests, something is wrong.[^3]

#### Treat every request as hostile

The client asks the server to perform a withdrawal with the given arguments. The server checks,
decides, and either acts or rejects. Assume every incoming request is malicious — voluntarily or not.

#### Validate arguments

Check type, range, and plausibility — server-side, before any action is taken. A withdrawal request
with a negative value? A string where a number is expected? SQL fragments or escape sequences in a
name field? Reject immediately.

#### Log smart

Logging every action and reviewing it after the fact is not security — it is archaeology. The
questions should be asked in real time. A player running more than five transactions per minute? Flag
it. An account receiving transfers from twenty different players in thirty seconds? Flag it.

> **Note:** With the growth of AI and the rise of consumer-level big data systems, it'd be very
> interesting to see what can be done with the mass treatment of logs across servers: training AI
> models to scan logs for anomalies the same way it's done in tax offices to hunt money laundering.

---

# Section 2 — The NUI / Web Layer

FiveM's NUI system is a Chromium browser running inside the game client. Developers build custom UIs
with HTML, CSS, and JavaScript — inventory menus, HUDs, admin panels, ticket queues. The stack is
standard. The attack surface is standard. If you have done web security before, you already know the
attack. The question is what the context makes possible.

## Web security in a game is worse

In a normal browser, XSS is bounded. The sandbox limits system access. Same-origin policy restricts
what injected JavaScript can reach. Exfiltrating a session cookie is the ceiling for most web XSS.

NUI does not have that ceiling. The Chromium instance runs inside a process that has direct, designed
access to the game engine. There is no boundary between the web layer and the game layer — that
boundary was intentionally removed so that JavaScript can communicate with Lua and Lua can communicate
with JavaScript. The same design choice that makes custom UIs possible is what makes XSS here
categorically worse than XSS in a web app.

## The bridge

The communication mechanism is worth understanding before the escalation. Two functions carry traffic
across the boundary:

- `SendNUIMessage` — Lua to JavaScript. Sends a JSON object into the browser, received by a
  `window.addEventListener('message', ...)` handler in JS.
- `RegisterNUICallback` — JavaScript to Lua. JS makes an HTTP POST to
  `https://${GetParentResourceName()}/callbackName`; the registered Lua handler receives the body.

Data flows in both directions. A payload that lands in the browser can use `RegisterNUICallback` to
send data back to Lua — and client-side Lua has access to game state, player data, and game
functions. The bridge is the mechanism. Everything below is what happens when untrusted input reaches
the DOM on the wrong side of it.

## The vulnerable pattern

The vulnerable pattern is one line:

```js
// nui/inventory.js
element.innerHTML = itemDescription
```

`itemDescription` arrived from the server via `SendNUIMessage`. The developer trusted it. That trust
is misplaced — the data ultimately originates from player input, a database that players write to,
or a server-side script that handles player-controlled strings.

The attacker sets their character name, their item name, or their support ticket body to a payload.
Something like an image tag with an error handler that loads and evaluates a remote script. The
payload is innocuous-looking. It sits in the database. It waits.

> **Note:** Specific payload syntax is intentionally omitted. This is a documented class of
> vulnerability — the goal is to make the attack surface legible, not to provide a tutorial.

## Step one: proof of concept on yourself

Before targeting anyone, the attacker confirms the surface. They set a player-controlled field to a
payload and then open the UI that renders it — their own inventory, their own player card. The
payload fires on their own screen. DOM mutates. Nothing illegal happened; it is their own client.
What they now know: the injection point exists, the browser evaluates it, the field is not sanitised.
This is reconnaissance. Low stakes, high signal.

## Step two: blind XSS against staff

Staff panels are NUI too. Player reports, ban requests, ticket queues, admin dashboards — all
rendered in a Chromium browser inside the game. If the attacker's payload is stored in something
that staff view, the payload fires in the *staff member's* client when they open the relevant panel.
The attacker may be offline. The attacker never sees it trigger. This is blind XSS: fire and forget.

The payload includes a beacon — a `fetch` call to an attacker-controlled endpoint that fires on
execution, passing along whatever is readable in the DOM at the time: staff member identifiers,
pending ban records, current player list, session tokens if a web panel is embedded. The attacker
gets an HTTP request. That request confirms execution and carries the exfiltrated data.

The staff member opened a ticket. Nothing looked wrong.

## Step three: stored XSS against all clients

Same mechanism, no longer limited to staff. The payload is stored in something every player
renders: item names, vehicle descriptions, gang tags, death notifications, chat messages. When any
client opens the affected UI, the payload executes in their browser. One stored injection, every
player who opens that menu, no further interaction required from the attacker.

The attacker went offline after submitting the payload. The payload is still executing on new
clients.

## Step four: game control

The JavaScript running in victim clients has access to `window.invokeNative`.[^6] This is a bridge
to C++ game functions — the same functions the game engine uses internally. From injected JavaScript
running in a victim's NUI: teleport the player, spawn or delete entities, trigger animations, call
commands that would normally require server-side authorisation. The attacker is not sending a
crafted server event anymore. They are calling game engine functions directly from inside the
victim's client, without touching the server at all.

The anticheat has no visibility into this. It is not a game modification. It is JavaScript executing
inside a browser that the game provides.

## Step five: machine control

`window.invokeNative` is not the ceiling.

The CEF instance running NUI is a browser. Browsers have APIs: clipboard read and write, microphone
access, camera access. In a standard browser these prompt for permission. Inside the game client,
the permission surface is different — prompts may not appear, or may appear in a context where the
player dismisses them without understanding what they are approving.

Beyond that: the CEF remote debug interface runs on `localhost:13172` while the game is open.[^7]
Any process on the same machine can attach to it and inject code into the running browser context,
or inspect and modify anything currently loaded. This is not an attacker capability — it is a
developer tool. But it is exposed by default, and it is accessible to anything running locally.

From a payload already executing in NUI: read local files via `fetch` against `file://` paths,
exfiltrate stored credentials, drop content to disk if the browser context permits it. The attacker
has moved from manipulating a game UI to running arbitrary code on the victim's operating system.

## The end state

One stored payload. Every client that rendered the affected UI executed arbitrary code on a real
machine. Those machines have filesystems, credentials, and network access. They are not sandboxed
by anything the game provides.

On the server side: if the payload reaches a rendering context that has server access — an admin
web panel, a database management UI, anything that renders stored player data in a browser sitting
on the server host — the escalation path continues to the server machine. RCE. Privilege escalation.
Lateral movement into whatever network the server is on.

This started with a developer using `innerHTML` instead of `textContent`.

## Fixing the NUI layer

**`textContent` over `innerHTML`** — if you are not rendering HTML, do not invoke the HTML parser.
One substitution eliminates this entire class of vulnerability for text content.

**DOMPurify if HTML is genuinely required** — not a regex. Tag-stripping with a regular expression
is bypassable; a proper sanitiser understands the DOM tree and removes dangerous constructs
without breaking legitimate markup.

**Content Security Policy** — add a CSP to NUI resource HTML files. Restrict inline script
execution and limit which origins `fetch` can reach. This does not prevent injection, but it
severs the fetch-eval chain that turns reflected input into remote code execution.

**Treat `RegisterNUICallback` data as hostile** — apply the same principle from Section 1. Data
arriving from the NUI layer is untrusted. Validate type, range, and plausibility in the Lua handler
before acting on it. The bridge runs in both directions; the input validation obligation runs in
both directions.

**Minimal bridge exposure** — only register the callbacks you need. Each registered callback is an
attack surface; an unnecessary one is an unnecessary risk.

---

# Section 3 — Supply Chain Risk from Community Scripts

- Most servers run unaudited third-party code from GitHub/forums/resellers
- What malicious scripts do: backdoors (hidden event handlers), data exfiltration via HTTP, delayed payloads
- Reseller risk: modified copies without visible history
- Mitigation: read server-side files before install, audit PerformHttpRequest calls, check for hardcoded key
  patterns, prefer auditable repos, minimal OS permissions for the server process

---

# Section 4 — The rest of the stack

If you have read this far, you are probably already reconsidering some decisions. Good. But
everything covered in sections 1 through 3 assumes the attacker is a player — someone who logged
in, connected to your server, and is operating within the FiveM client. That is the comfortable
threat model. The uncomfortable one is that your server is a machine on the internet, and FiveM
is one of several things running on it. In this section we briefly step outside the game layer and
look at what surrounds it.

## The server machine

[nmap scan, other services, open ports]

## Permissions and infrastructure

[roles, permissions, default passwords and unprotectedmaybe DBs]

## Bare Metal

[untrusted hosting platforms, physical attacks]

---

# Pre-Install Checklist

- [ ] Audit all `PerformHttpRequest` calls — destination and payload
- [ ] Check for hidden or catch-all `AddEventHandler` registrations
- [ ] Search for hardcoded keys, tokens, and base64-encoded strings
- [ ] Review NUI files for `innerHTML` with variable input
- [ ] Verify commit history and source integrity
- [ ] Confirm OS-level server permissions are minimal
- [ ] Run on a staging server for 24h before production

Each of these is covered in depth across the sections above.

**TL;DR:** read the files before you trust them with your players.

---

# For devs: Security as a Headspace (SaaH)

The fixes are not complex. Here is the original `bank:withdraw` handler from section 1 with the four principles
applied — the diff in code is small; the diff in exposure is everything.

```lua
-- server.lua
RegisterNetEvent('bank:withdraw')
AddEventHandler('bank:withdraw', function(amount)
    local src = source

    -- Type, sanity & context check
    if "number" == type(amount) and 0 < amount and true == isPlayerAtBank(src) then
      
      -- Authorization
      local balance = getPlayerBalance(src)
      if nil ~= balance and balance >= amount then
        
        -- Perform the action
        removeMoney(src, amount)
      end
    end

    return
end)
```

The same logic applies to `bank:transfer` — but now there are two amounts and two players to
validate. Both must be real, both must be in range, and the sender must actually have the funds.
Neither end of the transaction should be trusted.

```lua
-- server.lua
RegisterNetEvent('bank:transfer')
AddEventHandler('bank:transfer', function(target, amount)
    local src = source

    -- Type, sanity & target check
    if "number" == type(amount) and 0 < amount and true == DoesPlayerExist(target) and src ~= target then

      -- Authorization
      local balance = getPlayerBalance(src)
      if nil ~= balance and balance >= amount then

        -- Perform the action
        removeMoney(src, amount)
        addMoney(target, amount)
      end
    end

    return
end)
```

Notice that `usr1` is gone — the server already knows who the sender is via `source`. Letting
the client pass it as an argument is exactly the kind of thing that gets abused.

A few things worth naming explicitly in both snippets:

- **Default to negative.** The function does nothing unless every condition is met. No action, no
  side effect, no response — just a silent `return`. The burden of proof is on the request, not
  the rejection. That silent return is also the right place to raise a log flag: it is the default
  path, and it should never be hit in normal operation.[^4]

- **Yoda conditions.** Comparisons are written with the constant on the left: `"number" == type(amount)`
  rather than `type(amount) == "number"`. In Lua the difference is stylistic — it signals that the
  expected value is the reference point and the input is what gets tested against it.[^5]

- **Layered validation.** The checks are not a single gate — they are a sequence of independent
  filters, each answering a different question: *is this the right type? is the value in range? is
  the player in the right context? does the authorization hold?* A bypass of one does not collapse
  the rest, and any single failure sends the request straight to the bin.

---

# Closing

Low attacker bar, soft targets, simple fixes.

The threat model for a FiveM server is not exotic. There is no zero-day, no nation-state actor, no
sophisticated toolchain. The attacker is usually a bored teenager with a Lua console and a list of
event names pulled from your own client-side files — which they already have, because your client
runs on their machine. The entry point is the trust you extended without meaning to.

The reason most servers haven't been visibly compromised is not that they are secure — it is that
they were either lucky, or they were hit and never noticed. An economy manipulation that stays
within plausible bounds leaves no obvious trace. Logs that nobody reads might as well not exist.
Anticheats operate at the game engine layer: they catch aimbots and movement exploits, script
kiddie territory. They have no visibility into a crafted event payload crossing the network. A
server owner pointing at their anticheat as a security posture is protecting the wrong perimeter.

None of the mitigations in this post are novel. Server-side validation, minimal client scope,
input sanitisation, anomaly logging — these are fundamentals. They appear in every secure
development guide written in the last thirty years. The reason they are worth writing about in
the context of FiveM is that the culture around it has never framed the server as an attack surface.
Anticheat is discussed endlessly; the event handler that moves money is not.

Reframe: the gap between exposed and defensible is attention, not expertise. The fixes are a few
lines of Lua. Most servers aren’t hacked — they’re asked politely, and they comply.

There is one thing this post has not touched: consequences. Not in-game ones — real ones. Every server
collects data. IPs, identifiers, transaction records, chat logs. The moment a player connects,
you are a data controller. The moment real money changes hands, you are operating a financial
service. Most server owners have never thought about this. Most will keep not thinking about it
until they receive something that is not a cheat report.

In a future post, we will cover what a breach actually costs — legally, financially, and personally.
If this post reached someone running a server, send it to them. Better read a blog post than
receive a report from the IRS... or worse.

---

# Notes

[^1]: In networking and security, "*service*" is a broad term. FiveM scripts can reasonably be
    described as a service running inside a browser (Chromium/NUI), running on a network stack
    (FiveM), running on a game engine (RAGE).

[^2]: This can go further than it looks. A common pattern is routing stolen funds through a
    temporary account, then converting them to placeable in-game objects to break the audit trail.
    In some cases this technique has been used to frame other players — the logs showed them
    receiving large wire transfers, leading server staff to believe they were responsible.

[^3]: This also goes for performance. Offloading the client to the max usually helps with
    client-side FPS.

[^4]: Anomaly detection at the event level is underused in FiveM. A handler that rejects more than
    it accepts is a signal worth surfacing — especially on high-value events like transfers or
    inventory mutations.

[^5]: In languages where `=` is assignment and `==` is comparison — C, JavaScript, PHP — writing
    the constant on the left turns an accidental `=` into a compile-time or runtime error rather
    than a silent bug. The pattern originates there; in Lua it is purely a readability convention.

[^6]: `window.invokeNative` access has been partially restricted in newer CitizenFX builds. The
    restriction is not complete or consistent across resource contexts, and the underlying
    architecture — a JS-to-game-engine bridge — remains. Treat it as present until confirmed absent.

[^7]: The CEF remote debug port on `localhost:13172` is a developer tool, not a vulnerability in
    itself. It is exposed by default while the game runs and is accessible to any local process.
    On a shared host or a machine that has already been partially compromised, it becomes a
    reliable pivot point. See the Cfx.re community discussion on CEF debug tooling for context.
