---
layout: post
title: "Your Server Events Are a Security Hole"
date: 2026-03-24
toc: true
series: "FiveM Security"
series_part: 1
tags: [
  fivem, fivem-security, gta-roleplay, cfx,
  lua, lua-security, server-events, event-validation,
  game-server-security, game-server-hardening,
  security-awareness, red-team, penetration-testing,
  input-validation, client-server, roleplay-server
]
---

The attacker is already on your server. They connected like any other player. Your anticheat
cleared them. Now they're reading your client files — which they have a copy of, because that's
how FiveM works — mapping the event names your server listens for, noting which ones take
arguments. They're not looking for a zero-day. They're looking for a handler that forgot to
validate its input.

Most servers have several.

---

# The attack surface

FiveM scripts split across two layers: *server-side* and *client-side*. Client code runs on the
player's machine. The player owns that machine. They can read every file in your resource, modify
any function, call anything they want.

What is less often considered is what that implies for the server. The two layers communicate
through events — the client fires a named event, the server handles it. The problem is that
**any connected client can fire any registered server event, by name, with any arguments they
choose**. The server has no way to distinguish a call from your UI from a call typed into a
console. It only sees an event and its payload.

# Case study

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
marketplace. The server receives `amount` from the client and acts on it. The caller's identity
(`src`) is resolved server-side, so that part is fine. What isn't fine is the assumption that
`amount` can be trusted. In a legitimate flow the client wraps the call in checks:

- Is the user at a bank?
- Does the user have enough funds?
- Is the amount within a sensible range?

None of those checks exist on the server. They live on the client, where the attacker already has
full control.

> **Note:** The examples below are intentionally vague. The goal is not a hacking tutorial — these
> are well-known techniques in the offensive world, but the focus here is awareness, not execution.

Calling `bank:withdraw(100)` outside the normal UI flow goes through without issue. Clean log
entry, money received, no flags raised — from the middle of the Sandy Shores desert. The
service[^1] is vulnerable. So we keep looking.

```lua
-- server.lua
RegisterNetEvent('bank:transfer')
AddEventHandler('bank:transfer', function(usr1, usr2, amount)
    removeMoney(usr1, amount)
    addMoney(usr2, amount)
end)
```

Jackpot. `bank:transfer`, a few lines below, has the same problem — and this time the attacker
controls both ends. Run it in a loop across all online players and the money flows to a single
account. Every log entry looks like a legitimate transfer. Only a manual audit would catch it,
and only if the attacker stayed within plausible bounds[^2].

Server events **can be called from anywhere, by anyone, with any arguments**. What that means
in practice:

- Your logs are clean
- Your paid anticheat didn't trigger
- Your staff has no idea

This is full compromise. In a red team engagement this is a failed audit.

# Remediation

👏 DON'T 👏 TRUST 👏 THE 👏 USER 👏

## Scope your client code

Client code handles the client: UI, visual effects, local state. Moving money, writing to a
database, spawning a vehicle server-side — that belongs in server code. If your client is doing
more than presenting state and sending requests, something is wrong.[^3]

## Treat every request as hostile

The client sends a request. The server validates it, decides, and either acts or rejects. That
order is non-negotiable. The client cannot be trusted to have already checked — it doesn't matter
whether the client *would* check in the normal flow. Assume every incoming event is adversarial.

## Validate arguments

Check type, range, and plausibility on the server before touching anything. Negative withdrawal
amount? String where a number is expected? Reject immediately, no side effects.

## Log smart

Logging every transaction and reviewing it after the fact is not security — it is archaeology.
Flag anomalies in real time. A player firing more than five transactions per minute? Flag it. An
account receiving transfers from twenty different players in thirty seconds? Flag it.

> **Note:** With the growth of AI and consumer-level data infrastructure, there's an interesting
> open question here: training models on cross-server log data to surface anomalies the way tax
> authorities hunt money laundering patterns.

---

# Security as a headspace

The fixes are not complex. Here is the original `bank:withdraw` handler with the four principles
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

The same logic on `bank:transfer` — two players, two ends of the transaction, both need
validating. Neither can be trusted.

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

Notice `usr1` is gone — the server already knows the sender via `source`. Accepting it as a
client argument is exactly the kind of thing that gets abused.

Three things worth naming explicitly:

- **Default to negative.** The function does nothing unless every condition passes. No action, no
  side effect, silent `return`. That default path is also the right place to emit a log flag — it
  should never fire in normal operation.[^4]

- **Yoda conditions.** Constant on the left: `"number" == type(amount)`. In Lua this is purely
  stylistic — the constant is the reference point, the input is what gets tested against it.[^5]

- **Layered validation.** Not a single gate — a sequence of independent filters: type, range,
  context, authorization. A bypass of one doesn't collapse the rest.

---

# Closing

Low attacker bar, soft targets, simple fixes.

The threat model is not exotic. No zero-day, no sophisticated toolchain. The attacker is usually
someone with a Lua console and a list of event names copied from your client files — files they
have because your client runs on their machine. The entry point is the trust you handed out
without meaning to.

Most servers haven't been visibly hit not because they're secure but because they were either
lucky, hit quietly, or hit and never noticed. An economy drain that stays within plausible daily
variance leaves no obvious trace. Logs nobody reads might as well not exist. Your anticheat
catches aimbots and movement cheats. It has no visibility into a crafted event payload.

The gap between exposed and defensible is a few lines of Lua and the decision to treat the server
as what it is: a networked application that accepts untrusted input.

Server events are the most direct entry point — one handler, one attacker, one payload at a time.
Part 2 is a different shape of problem. FiveM embeds a full Chromium browser inside the game
client — custom UIs, inventory menus, admin panels, all built in HTML and JavaScript. That browser
has a message bridge directly into Lua, and the game gave it access to native engine functions.
A developer who renders a player-controlled string with `innerHTML` instead of `textContent`
doesn't expose one handler. They expose every client that opens that menu, simultaneously, to
code execution — and the escalation path from there goes places that have nothing to do with
in-game economy.

---

# Notes

[^1]: In networking and security, "*service*" is a broad term. FiveM scripts can reasonably be
    described as a service running inside a browser (Chromium/NUI), running on a network stack
    (FiveM), running on a game engine (RAGE).

[^2]: A common pattern is routing stolen funds through a temporary account then converting them
    to in-game objects to break the audit trail. In some cases this has been used to frame other
    players — the logs showed them receiving large transfers, leading staff to believe they were
    responsible.

[^3]: This also applies to performance. Offloading work from the client reduces client-side
    overhead and is the correct architectural pattern regardless of security posture.

[^4]: Anomaly detection at the event level is underused in FiveM. A handler that rejects more
    than it accepts is a signal worth surfacing — especially on high-value events like transfers
    or inventory mutations.

[^5]: In languages where `=` is assignment and `==` is comparison — C, JavaScript, PHP — writing
    the constant on the left turns an accidental `=` into a compile-time or runtime error rather
    than a silent bug. The pattern originates there; in Lua it is purely a readability convention.
