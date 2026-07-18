# LoginGuard — password-protected usernames for neoLegacy (FourKit)

Adds AuthMe-style login/registration to the neoLegacy FourKit dedicated
server. Any player joining under a username that's already registered must
type `/login <password>` to prove ownership; new usernames register
themselves the first time with `/register <password> <password>`. Until a
player authenticates they're frozen — no movement, chat, block interaction,
item drops, or commands other than `/login`/`/register`.

## How this was built

This was vibe-coded with claude and me viewing the code, This was more of a beginner project were I wanted it to "just work" so please dont expect the code to be very pretty.

## Installing

1. Drop `LoginGuard.dll` into the server's `plugins/` folder (the same
   folder that ships empty in the FourKit zip, next to `Minecraft.Server.exe`).
2. Restart the server. You should see in the console:
   ```
   Loaded plugin: LoginGuard v1.0.0 by Claude for Anthropic
   Enabled: LoginGuard
   [LoginGuard] enabled - 0 account(s) loaded.
   ```
3. That's it — no config file needed for a first run. Player data is stored
   under this plugin's data directory (whatever the host assigns via
   `dataDirectory`, typically something like `plugins/LoginGuard/accounts.json`).

## Player-facing commands

| Command | Who | What it does |
|---|---|---|
| `/register <password> <password>` | New username | Claims the username and logs you in |
| `/login <password>` | Registered username | Logs you in for this session |

- Passwords must be at least 4 characters.
- Sessions aren't remembered across reconnects — you log in again each time
  you join, same as classic AuthMe.
- If nobody logs in within 60 seconds of joining, they're kicked
  automatically (best-effort, see caveat below).

## Security notes

- Passwords are hashed with PBKDF2-SHA256 (100,000 iterations, random 16-byte
  salt per account) and compared in constant time. Nothing is ever stored or
  logged in plain text.
- This only protects the *username* — it doesn't replace the server's
  existing built-in token-based authentication described in the neoLegacy
  project's own docs. Think of it as an extra "claim your name" layer on top,
  similar to what AuthMe does for offline-mode Java servers.

## Known limitations / things to be aware of

- **No custom kick messages.** The host's `PlayerLoginEvent`/
  `PlayerPreLoginEvent` only expose `isCancelled()`/`setCancelled()` — there's
  no API to set a custom disconnect reason on those events, and
  `Player.kickPlayer()` takes no message argument either. So the plugin
  freezes+prompts the player instead of hard-cancelling login, and just sends
  a chat message before kicking on timeout.
- **The 60-second auto-kick runs on a background timer thread**, not
  whatever thread the server normally drives gameplay logic from. I wrapped
  every call in try/catch so a problem there can't crash the server, but if
  you notice anything odd (e.g. errors mentioning cross-thread access) after
  enabling this, the simplest fix is to delete the `_timeoutTimer` block in
  `onEnable()`/`onDisable()` — everyone will still be frozen out until they
  log in, they just won't be auto-kicked for going AFK before doing so.
  
## Rebuilding from source

```
dotnet build -c Release
```

`LoginGuard.csproj` references `lib/Minecraft.Server.FourKit.dll` — copy that
DLL out of your server's `runtime/` folder into a `lib/` folder next to the
`.csproj` before building (not included here to keep this small)
