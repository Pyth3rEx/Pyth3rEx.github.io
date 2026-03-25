---
layout: post
title: "The web inside FiveM: From browser to full remote control"
date: 2026-03-25
toc: true
series: "FiveM Security"
series_part: 2
tags: [
  fivem, fivem-security, gta-roleplay, cfx,
  lua, lua-security, server-events, event-validation,
  game-server-security, game-server-hardening,
  security-awareness, red-team, penetration-testing,
  input-validation, client-server, roleplay-server
]
---

A player typed something into a text field. Now an attacker is reading files on another player's computer.
Your server didn't get hacked. You were never the target. But you are the one who let it happen.

---

# Part 1 recap

Part 1 was about the server. An attacker connected, fired events the server wasn't expecting, and
walked away with whatever the scripts handed over. The attacker was still a player — present on the
server, operating within the network stack.

That stays true here. The attacker is still a connected player. What changes is the target.
In Part 1 the server was the victim. In this post, so are the other players.

FiveM ships a Chromium browser inside every game client. Developers use it to build custom UIs — inventory menus, HUD
overlays, admin panels. Those UIs render data. Some of that data was written by other players. If it
is rendered without sanitisation, it executes.

A payload stored in a player-controlled field — a name, an item description, a support ticket — sits
in the database and waits. Every client that opens the affected UI runs it. The attacker can be
offline. The payload keeps firing.

That is the first shift. The second is where it leads. The Chromium instance running NUI is not
isolated from the host machine. It has a designed bridge to the game engine, and through that bridge,
to game functions and eventually to the operating system. A payload that starts as an `innerHTML`
injection can end on the victim's filesystem — outside the game, outside the server, on a real
machine.

---

# The NUI / Web Layer

FiveM's NUI system is a Chromium browser running inside the game client. Developers build custom UIs
with HTML, CSS, and JavaScript — inventory menus, HUDs, admin panels, ticket queues — exactly the
same way you build a website. The stack is standard. The attack surface is standard. If you have
done web security before, you already know the attack. If you haven't, a quick look at any bug
bounty leaderboard will show you how common this class of vulnerability is and how little it takes
to exploit it. The question is what the context makes possible.

# Web security in a game is worse

In a normal browser, XSS[^1] is bounded. The sandbox limits system access. Same-origin policy restricts
what an injected JavaScript can reach. Exfiltrating a session cookie is the ceiling for most web XSS, and you'll rarely if ever end up
with a fully compromised system from a web-vectored attack alone[^2].

NUI does not have that ceiling. The Chromium instance runs inside a process that has direct, designed
access to the game engine. There is no boundary between the web layer and the game layer — that
boundary was intentionally removed so that JavaScript can communicate with Lua and Lua can communicate
with JavaScript. The same design choice that makes custom UIs possible is what makes XSS here
categorically worse than XSS in a web app.

# The bridge

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

> **Note:** Also notice the similarity with the vulnerabilities mentioned in Part 1? They also apply here. If you missed it, read about it [here](/blog/2026/03/24/fivem-server-events/).

# Case study

## Step 1: noticing

We join a new server — it's got open police slots, great. Playing around we notice evidence bags:
placeable items like bullet casings that accept metadata comments, letting detectives add context
to evidence later in an investigation. Let's dig.

## Step 2: digging

The script is paid — no public source, documentation behind a paywall. A bit of OSINT surfaces an
outdated leak: obfuscated code and a three-year-old user guide. The UI has changed and the feature
list is half of what the script offers today, but that doesn't matter. Core functions are rarely
rewritten from scratch. There's a good chance the internals are similar, if not identical.

Digging through the docs, we find an example structure for item declarations using `filled_evidence_bag`.
Let's check if that item exists on the server.

Back in FiveM we manipulate our inventory requests to request the `itemthatdoesnotexist` item.

```bash
SYSTEM: Item does not exist...
```

Alright, let's try `filled_evidence_bag`:

```bash
SYSTEM: User inventory already defined in database
```

Jackpot. The item exists in the resource files. All we need now is an item that accepts metadata.

## Step 3: Proof of Concept (PoC)

All items have a metadata attribute — it's just unused unless a script needs it. That means we can
assign metadata to the welcome guide handed out on character creation.

```html
<script>
    alert('Vulnerable')
</script>
```

Setting this as the item's metadata lets us test locally — no other player is affected. On inventory
open, a `Vulnerable` popup appears in the UI layer. The service is vulnerable.

### Blind XSS

The inventory is not the only injection point. Admin reports are NUI too — player reports, ban
requests, ticket queues. A payload stored in a report body won't visibly render as a script; the
staff member opens what looks like a normal ticket. The payload fires in their client, under their
permissions. They never see it execute. This is blind XSS: the attacker fires and goes offline.
The payload does the rest.

## Step 4: Persist via Stored XSS

Several vectors are already in reach — one is already in place in our testing: the item's metadata.
What if I log in from a second machine, drop the infected welcome guide on the ground, and pick it
up with another character?

`Vulnerable` popup on the receiving screen. The payload persists with object state. Going back to
the evidence bag: if we were to create an infected bag and store it in the police station, we could
specifically target police players. Or we could go wide — hiding the payload in the chat bar, item
names, vehicle descriptions, gang tags. Possibilities are endless. One stored injection, every
player who opens the affected UI, no further interaction required.

## Step 5: Weaponize

Now that we know we can hit anyone, anywhere, it's time to decide what to hit them with. The
simplest starting point is DOM manipulation — rewriting what the victim sees inside their own UI.

```js
// html/app.js
var descriptionEl = document.querySelector('[data-component="evidence-description"]');
if (descriptionEl) {
  descriptionEl.innerText = SPOOFED_DESCRIPTION;
}

fetch(CALLBACK_ENDPOINT, {
  method: 'POST',
  body: JSON.stringify({
    action: 'transferEvidence',
    target: ATTACKER_INVENTORY,
    item: EVIDENCE_BAG_ID
  })
});
```

> **Note:** Specific payload syntax is intentionally omitted. This is a documented class of
> vulnerability — the goal is to make the attack surface legible, not to provide a tutorial.

The first part rewrites the evidence description in the victim's UI — they see whatever we want
them to see. The second fires a `POST` to the inventory callback, requesting a transfer of the
item to our inventory. The victim opened their evidence bag. We took what was inside.

## Step 6: Elevate

Now that we have visibility into what players see, we can think about elevating — using our foothold
to perform more destructive actions. Our payload has full DOM interactivity. If it's sophisticated
enough it can scan, detect, and pivot autonomously. Let's see what's in the DOM.

```html
<div class="notif-label">
  <div class="notif-title">Payment Received</div>
  <div class="notif-subtitle">Unemployment check - $15</div>
</div>
```

Convenient: the moment I ran my recon payload was the same instant I received my 15-minute
in-game paycheck. That notification was loaded in my DOM[^3]. Oddly curious.

After digging into how FiveM handles NUI, the picture becomes clear. FiveM isolates resources in
separate iframes — they shouldn't be able to see each other's DOM. But many servers run a
centralised notification or display system: a single third-party script that routes all UI
elements through one stack for a consistent look. When that's in place, all resources share the
same DOM, and any callback registered there is reachable from our payload.

Scanning the DOM for registered callbacks, one stands out:

```lua
-- server.lua
RegisterNUICallback('UIsystem:generalCallbacks', function(data, cb)
  -- routes callback to the originating resource by name
end)
```

A generic pass-through — routes any callback to its originating resource without validation. That
is a wide pivot surface. Every resource on the server with a registered callback is now reachable
from our injection point.

The opening we are looking for is `window.invokeNative`[^4], which exposes game engine functions
directly to JavaScript running in NUI.

From injected JavaScript running in a victim's NUI: teleport the player, spawn or delete entities,
trigger animations, call commands that would normally require server-side authorisation. The attacker
is not sending a crafted server event anymore. They are calling game engine functions directly from
inside the victim's client, without touching the server at all.

The anticheat has no visibility into this. It is not a game modification. It is JavaScript executing
inside a browser that the game provides.

## Step 7: Exfiltrate

> **Note:** This section is deliberately vague and leans toward speculation rather than demonstration,
> for obvious reasons. Keep an open mind.

`window.invokeNative` is not the ceiling.

The CEF instance running NUI is a browser. Browsers have APIs: clipboard read and write, microphone
access, camera access. In a standard browser these prompt for permission. Inside the game client,
the permission surface is different — prompts may not appear, or may appear in a context where the
player dismisses them without understanding what they are approving.

Beyond that: the CEF remote debug interface runs on `localhost:13172` while the game is open.[^5]
Any process on the same machine can attach to it and inject code into the running browser context,
or inspect and modify anything currently loaded. This is not an attacker capability — it is a
developer tool. But it is exposed by default, and accessible to anything running locally.

> **Note:** The activation and blocking of debug services on FiveM is not well documented. Most will
> argue that if you don't enable the tools, they aren't enabled — but some claim it is possible to
> force or bypass their activation. The documentation is thin; the threat model shouldn't assume the
> default is safe.

With a payload executing in the NUI context and a foothold on the debug interface, the attacker can
operate at OS level — and they no longer need to be connected to the server. Reading local files via
`fetch` against `file://` paths, exfiltrating stored credentials, or dropping content to disk are
all within reach. The attacker has moved from manipulating a game UI to running arbitrary code on
the victim's operating system.

---

# The end state

A detective opened an evidence bag.

The metadata field rendered without sanitisation. Our payload executed in their NUI context. It
rewrote the bag's description — they saw whatever we wanted them to see. It fired a callback and
transferred the bag to our inventory. It scanned the DOM, found the centralised notification system,
and mapped every registered callback on the server. It called `window.invokeNative` — directly,
without touching the server — and issued game engine commands under their identity. Then it reached
the debug interface and read files off their machine.

They were just doing their job. Opening evidence, like every shift.

The payload had been sitting in that bag for days. We were offline. It fires on every detective who
opens it. The server saw none of this — no unusual events, no suspicious connections, nothing to
flag. The only trace is a text field in a database, waiting for the next person to open the right
menu.

This started with a developer using `innerHTML` instead of `textContent`.

# Fixing the NUI layer

The same three principles from Part 1 apply here. The bridge runs in both directions; the
obligation runs in both directions.

**The render side.**

The JavaScript that displays player-controlled data is the first gate. By default, it does nothing
unless the data passes. `textContent` is the default — it does not invoke the HTML parser, so
injected markup is inert. If HTML rendering is genuinely required, DOMPurify runs first. No
exceptions for "trusted" sources: if the data touched the database and a player wrote it, it is
untrusted.

```js
// html/app.js
function renderDescription(data) {
  var descEl = document.querySelector('[data-component="evidence-description"]');
  if (null !== descEl) {
  
    // Type check
    if ('string' === typeof data.description) {
    
      // Render — textContent, never innerHTML
      descEl.textContent = data.description;
    }
  }
  
  return;
}
```

Default to negative. The function does nothing unless the element exists and the data is a string.
No render, no side effect.

**The callback side.**

Data arriving from the NUI layer is untrusted. A payload executing in the browser can call any
registered callback with any body it constructs. The Lua handler is the second gate — same layered
pattern as Part 1.

```lua
-- client.lua
RegisterNUICallback('inventory:transferEvidence', function(data, cb)

    -- Type check
    if "string" == type(data.itemId) and "number" == type(data.target) then
    
        -- Sanity check
        if 64 > #data.itemId and 1 <= data.target then
        
            -- Context check
            if true == isValidItem(data.itemId) and true == DoesEntityExist(data.target) then
            
                -- Perform the action
                TriggerServerEvent('inventory:transferEvidence', data.itemId, data.target)
                cb({ success = true })
                return
            end
        end
    end

    cb({ success = false })
    return
end)
```

Default to negative. Silent `cb({ success = false })` and `return` on any failed check. The action
— a server event — only fires when every layer passes.

Three things worth naming explicitly:

- **Default to negative.** Both sides of the bridge do nothing unless all conditions pass. No
  render, no callback, no server event. Silent return.

- **Layered validation.** Not a single guard — a sequence: type, sanity, context, then action.
  Each layer is independent. A failure at any point drops the request.

- **Minimal surface.** Only register the callbacks you need. The generic pass-through from Step 6
  — routing any callback to any resource without validation — is the opposite of this. Each
  registered callback is a decision; treat it like one.

A Content Security Policy on NUI HTML files adds a fourth layer: restrict `script-src` to your
own bundle and block inline execution. It does not prevent injection, but it severs the eval chain.
A payload that cannot execute inline and cannot reach an external endpoint is significantly less
useful, even if it lands.

---

# Closing

Part 1 was one attacker, one server, one payload at a time. This is worse.

A single stored injection fires on every player who opens the affected UI — indefinitely, without
the attacker being present, without the server seeing anything unusual. The surface is not just
the server anymore. It is every client, every machine, every set of credentials sitting in a
browser profile on the same computer running the game.

Most servers won't notice. The tell is not an alert or a spike — it is a detective who lost their
evidence bag and assumed it was a script bug. It is a staff member whose admin panel behaved
strangely for a moment. It is a player who saw a notification they didn't expect. Or it's nothing
at all. None of those get filed as security incidents. They get filed as bugs, or they don't get
filed at all.

The attacker doesn't need to be skilled. They need to find one field that renders without
sanitisation and one developer who reached for `innerHTML` because it was easier. That field
exists on most servers. That developer made that choice on most resources. The gap between exposed
and defensible is `textContent`, a type check on a callback handler, and the decision to treat
the NUI layer as what it is: a browser running untrusted input.

Two posts in, we have covered the server and the clients. There is a third layer we haven't
touched — the database. The same input that executes in a browser can execute in a query. Part 3
is about what happens when untrusted data reaches SQL.

If this reached someone running a server, send it to them. Their players' machines are not part
of the game — until they are.

---

# Notes

[^1]: Cross-Site Scripting. An attacker injects a script into a page viewed by another user. The
    browser executes it as if it were part of the page.

[^2]: A decade or two ago, browsers were a genuine vector for full system compromise. Systems were
    less hardened, browser sandboxes were weaker, and exploitation toolkits made it routine. Modern
    browsers have closed most of those paths — which is exactly what makes NUI's exposure notable:
    it reopens them by design.

[^3]: FiveM isolates resources in separate iframes — theoretically preventing cross-resource
    communication. In this example the resources share the same NUI via a centralised display
    script. Worth noting: even without a shared DOM, that doesn't prevent a payload from calling
    another resource's registered callbacks directly.

[^4]: `window.invokeNative` is a CEF-exposed function specific to the FiveM client. It is
    undocumented officially but widely reverse-engineered by the community. Its availability and
    scope may vary across client versions.

[^5]: The CEF remote debugging port (`13172` by default) is a Chromium DevTools Protocol endpoint.
    Any application on localhost can attach to it while the game is running. It is a standard
    developer tool, not a vulnerability — but its exposure is worth understanding in a threat model.
