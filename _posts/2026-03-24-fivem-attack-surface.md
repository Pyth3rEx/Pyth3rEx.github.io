---
layout: post
title: "FiveM Is a Real Attack Surface"
date: 2026-03-24
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

Now let's put on our hacker hoodies and think red: what happens if we call the event directly, bypassing the UI entirely?

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

### Client files should contain the bare minimum:

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

> **Note:** With the growth of AI and the rise of consumer-level big data systems, it'd be very interesting to see what can be done with the mass treatment of logs across servers: training AI models to scan logs for anomalies the same way it's done in tax offices to hunt money laundering.

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
# Pre-Install Checklist

A short checklist (7 items) covering HTTP calls, event handlers, NUI innerHTML, hardcoded keys, commit history,
source integrity, and staging test.

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
---
# Notes

[^1]: In networking and security, "*service*" is a broad term. FiveM scripts can reasonably be described as a service running inside a browser (Chromium/NUI), running on a network stack (FiveM), running on a game engine (RAGE).

[^2]: This can go further than it looks. A common pattern is routing stolen funds through a temporary account, then converting them to placeable in-game objects to break the audit trail. In some cases this technique has been used to frame other players — the logs showed them receiving large wire transfers, leading server staff to believe they were responsible.

[^3]: This also goes for performance. Offloading the client to the max usually helps with client-side FPS.

[^4]: Anomaly detection at the event level is underused in FiveM. A handler that rejects more than it accepts is a signal worth surfacing — especially on high-value events like transfers or inventory mutations.

[^5]: In languages where `=` is assignment and `==` is comparison — C, JavaScript, PHP — writing the constant on the left turns an accidental `=` into a compile-time or runtime error rather than a silent bug. The pattern originates there; in Lua it is purely a readability convention.