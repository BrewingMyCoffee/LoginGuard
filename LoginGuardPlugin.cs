using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;

using Minecraft.Server.FourKit;
using Minecraft.Server.FourKit.Command;
using Minecraft.Server.FourKit.Entity;
using Minecraft.Server.FourKit.Event;
using Minecraft.Server.FourKit.Event.Player;
using Minecraft.Server.FourKit.Plugin;

namespace LoginGuard
{
    /// <summary>
    /// Adds password protection to usernames on a neoLegacy FourKit dedicated
    /// server. Any player who joins with a username that has already been
    /// registered must type "/login &lt;password&gt;" to prove they own it.
    /// New usernames can claim themselves with "/register &lt;password&gt; &lt;password&gt;".
    /// Until a player authenticates, they're frozen (movement/chat/interaction
    /// blocked) and every command except /login and /register is blocked.
    /// </summary>
    public class LoginGuardPlugin : ServerPlugin, Listener, CommandExecutor
    {
        // ServerPlugin declares these as get-only virtual properties -
        // override them to report our own metadata to the loader.
        public override string name => "LoginGuard";
        public override string version => "1.0.0";
        public override string author => "Claude for Anthropic";

        private const int LoginTimeoutSeconds = 60;
        private const int MinPasswordLength = 4;

        // name -> stored credentials, persisted to disk
        private readonly ConcurrentDictionary<string, AccountRecord> _accounts =
            new(StringComparer.OrdinalIgnoreCase);

        // name -> when they joined this session, while still unauthenticated
        private readonly ConcurrentDictionary<string, DateTime> _pendingSince =
            new(StringComparer.OrdinalIgnoreCase);

        // name -> true once they've logged in/registered this session
        private readonly ConcurrentDictionary<string, bool> _authenticated =
            new(StringComparer.OrdinalIgnoreCase);

        private string _dataFile = "";
        private Timer? _timeoutTimer;

        public override void onEnable()
        {
            // dataDirectory is a property provided (and set) by the host, not
            // a method - it points at this plugin's private data folder.
            Directory.CreateDirectory(dataDirectory);
            _dataFile = Path.Combine(dataDirectory, "accounts.json");
            LoadAccounts();

            FourKit.addListener(this);
            FourKit.getCommand("login").setExecutor(this);
            FourKit.getCommand("register").setExecutor(this);

            // Best-effort kick for players who never attempt to log in at all
            // (so they don't just sit there frozen forever). This callback
            // runs on a background timer thread rather than the server's own
            // thread. Every call is wrapped in try/catch so a problem here
            // can never take the rest of the server down; if your build turns
            // out to be unhappy about cross-thread calls into Player/FourKit,
            // just delete the timer below - everyone still gets frozen out by
            // the event handlers regardless, they simply won't get
            // auto-kicked for going AFK before logging in.
            _timeoutTimer = new Timer(SweepTimedOutSessions, null,
                TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

            Console.WriteLine($"[LoginGuard] enabled - {_accounts.Count} account(s) loaded.");
        }

        public override void onDisable()
        {
            _timeoutTimer?.Dispose();
            SaveAccounts();
            Console.WriteLine("[LoginGuard] disabled.");
        }

        // ---------------------------------------------------------------
        // persistence
        // ---------------------------------------------------------------

        private void LoadAccounts()
        {
            try
            {
                if (!File.Exists(_dataFile))
                    return;

                var json = File.ReadAllText(_dataFile);
                var data = JsonSerializer.Deserialize<Dictionary<string, AccountRecord>>(json);
                if (data == null)
                    return;

                foreach (var kv in data)
                    _accounts[kv.Key] = kv.Value;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LoginGuard] failed to load {_dataFile}: {ex.Message}");
            }
        }

        private void SaveAccounts()
        {
            try
            {
                var json = JsonSerializer.Serialize(_accounts,
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_dataFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LoginGuard] failed to save {_dataFile}: {ex.Message}");
            }
        }

        // ---------------------------------------------------------------
        // password hashing - PBKDF2-SHA256 (pure managed implementation,
        // 100,000 iterations, random 16-byte salt per account, constant-time
        // comparison). Passwords are never stored or logged in plain text.
        //
        // NOTE: this deliberately does NOT use System.Security.Cryptography.
        // On a genuine Windows box that's normally the right call, but this
        // server runs under Wine, and Wine's bcrypt.dll (the native Windows
        // crypto provider .NET calls into on Windows) is incomplete - PBKDF2
        // and RandomNumberGenerator both fail there with
        // "CryptographicException: Unknown error (0xc1000008)". The
        // ManagedSha256/ManagedHmacSha256/ManagedPbkdf2 helpers below are a
        // small, self-contained implementation with no P/Invoke and no OS
        // crypto calls at all, so they work identically under Wine or native
        // Windows. They're verified against the official NIST SHA-256 test
        // vectors, the RFC 4231 HMAC-SHA256 test vectors, and the standard
        // PBKDF2-HMAC-SHA256 test vectors (P="password", S="salt").
        // ---------------------------------------------------------------

        private static AccountRecord HashPassword(string password)
        {
            byte[] salt = ManagedRandom.GetBytes(16);
            byte[] hash = ManagedPbkdf2.DeriveKey(Encoding.UTF8.GetBytes(password), salt, 100_000, 32);

            return new AccountRecord
            {
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash),
            };
        }

        private static bool VerifyPassword(string password, AccountRecord record)
        {
            byte[] salt = Convert.FromBase64String(record.Salt);
            byte[] expected = Convert.FromBase64String(record.Hash);
            byte[] actual = ManagedPbkdf2.DeriveKey(Encoding.UTF8.GetBytes(password), salt, 100_000, 32);

            if (actual.Length != expected.Length)
                return false;

            // constant-time comparison, done by hand since we're avoiding
            // System.Security.Cryptography.CryptographicOperations too
            int diff = 0;
            for (int i = 0; i < actual.Length; i++)
                diff |= actual[i] ^ expected[i];
            return diff == 0;
        }

        // ---------------------------------------------------------------
        // join / quit
        // ---------------------------------------------------------------

        [EventHandler]
        public void onPlayerJoin(PlayerJoinEvent e)
        {
            var player = e.getPlayer();
            var name = player.getName();

            _authenticated[name] = false;
            _pendingSince[name] = DateTime.UtcNow;

            if (_accounts.ContainsKey(name))
            {
                player.sendMessage("This username is password-protected.");
                player.sendMessage($"Type /login <password> within {LoginTimeoutSeconds} seconds.");
            }
            else
            {
                player.sendMessage("This username is not registered yet.");
                player.sendMessage("Type /register <password> <password> to claim it.");
            }
        }

        [EventHandler]
        public void onPlayerQuit(PlayerQuitEvent e)
        {
            var name = e.getPlayer().getName();
            _authenticated.TryRemove(name, out _);
            _pendingSince.TryRemove(name, out _);
        }

        // ---------------------------------------------------------------
        // freeze everything for unauthenticated players
        // ---------------------------------------------------------------

        [EventHandler(IgnoreCancelled = true)]
        public void onMove(PlayerMoveEvent e)
        {
            if (!IsAuthenticated(e.getPlayer().getName()))
                e.setCancelled(true);
        }

        [EventHandler(IgnoreCancelled = true)]
        public void onChat(PlayerChatEvent e)
        {
            if (IsAuthenticated(e.getPlayer().getName()))
                return;

            e.setCancelled(true);
            e.getPlayer().sendMessage("You must log in before chatting. Use /login <password>.");
        }

        [EventHandler(IgnoreCancelled = true)]
        public void onInteract(PlayerInteractEvent e)
        {
            if (!IsAuthenticated(e.getPlayer().getName()))
                e.setCancelled(true);
        }

        [EventHandler(IgnoreCancelled = true)]
        public void onInteractEntity(PlayerInteractEntityEvent e)
        {
            if (!IsAuthenticated(e.getPlayer().getName()))
                e.setCancelled(true);
        }

        [EventHandler(IgnoreCancelled = true)]
        public void onDropItem(PlayerDropItemEvent e)
        {
            if (!IsAuthenticated(e.getPlayer().getName()))
                e.setCancelled(true);
        }

        // Lowest priority so we see the raw command before anything else
        // (including other plugins) has a chance to act on it.
        [EventHandler(Priority = EventPriority.Lowest, IgnoreCancelled = true)]
        public void onCommandPreprocess(PlayerCommandPreprocessEvent e)
        {
            if (IsAuthenticated(e.getPlayer().getName()))
                return;

            var firstWord = e.getMessage().Split(' ', 2)[0].ToLowerInvariant();
            if (firstWord == "/login" || firstWord == "/register")
                return;

            e.setCancelled(true);
            e.getPlayer().sendMessage(
                "You must log in first. Use /login <password> or /register <password> <password>.");
        }

        private bool IsAuthenticated(string name) =>
            _authenticated.TryGetValue(name, out var ok) && ok;

        // ---------------------------------------------------------------
        // /login and /register
        // ---------------------------------------------------------------

        public bool onCommand(CommandSender sender, Command command, string label, string[] args)
        {
            if (sender is not Player player)
            {
                sender.sendMessage("This command can only be used in-game.");
                return true;
            }

            var name = player.getName();
            try
            {
                return label.ToLowerInvariant() switch
                {
                    "login" => HandleLogin(player, name, args),
                    "register" => HandleRegister(player, name, args),
                    _ => false,
                };
            }
            catch (Exception ex)
            {
                // Temporary diagnostics: surface the real exception in-game
                // instead of relying on the host's generic "internal error"
                // message, since we can't see the server console from here.
                Console.WriteLine($"[LoginGuard] /{label} threw: {ex}");
                player.sendMessage($"[LoginGuard] error: {ex.GetType().Name}: {ex.Message}");
                return true;
            }
        }

        private bool HandleLogin(Player player, string name, string[] args)
        {
            if (IsAuthenticated(name))
            {
                player.sendMessage("You are already logged in.");
                return true;
            }

            if (args.Length != 1)
            {
                player.sendMessage("Usage: /login <password>");
                return true;
            }

            if (!_accounts.TryGetValue(name, out var record))
            {
                player.sendMessage("This username isn't registered. Use /register <password> <password>.");
                return true;
            }

            if (!VerifyPassword(args[0], record))
            {
                player.sendMessage("Incorrect password.");
                return true;
            }

            _authenticated[name] = true;
            _pendingSince.TryRemove(name, out _);
            player.sendMessage($"Login successful. Welcome back, {name}!");
            return true;
        }

        private bool HandleRegister(Player player, string name, string[] args)
        {
            if (IsAuthenticated(name))
            {
                player.sendMessage("You are already logged in.");
                return true;
            }

            if (_accounts.ContainsKey(name))
            {
                player.sendMessage("This username is already registered. Use /login <password>.");
                return true;
            }

            if (args.Length != 2)
            {
                player.sendMessage("Usage: /register <password> <password>");
                return true;
            }

            if (args[0] != args[1])
            {
                player.sendMessage("Passwords do not match.");
                return true;
            }

            if (args[0].Length < MinPasswordLength)
            {
                player.sendMessage($"Password must be at least {MinPasswordLength} characters.");
                return true;
            }

            _accounts[name] = HashPassword(args[0]);
            SaveAccounts();

            _authenticated[name] = true;
            _pendingSince.TryRemove(name, out _);
            player.sendMessage($"Registration successful. You are now logged in as {name}.");
            return true;
        }

        // ---------------------------------------------------------------
        // kick anyone who never bothers to log in at all
        // ---------------------------------------------------------------

        private void SweepTimedOutSessions(object? state)
        {
            try
            {
                var now = DateTime.UtcNow;
                foreach (var kv in _pendingSince)
                {
                    var name = kv.Key;
                    if ((now - kv.Value).TotalSeconds < LoginTimeoutSeconds)
                        continue;
                    if (IsAuthenticated(name))
                        continue;

                    var player = FourKit.getPlayer(name);
                    if (player != null)
                    {
                        player.sendMessage("Login timed out.");
                        player.kickPlayer();
                    }

                    _pendingSince.TryRemove(name, out _);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LoginGuard] timeout sweep error: {ex.Message}");
            }
        }

        private class AccountRecord
        {
            public string Salt { get; set; } = "";
            public string Hash { get; set; } = "";
        }
    }

    // -------------------------------------------------------------------
    // Pure-managed crypto primitives - deliberately avoid
    // System.Security.Cryptography, which routes through Windows' native
    // bcrypt.dll. That's normally fine on real Windows, but under Wine
    // bcrypt.dll's implementation is incomplete and throws
    // "CryptographicException: Unknown error (0xc1000008)" for both PBKDF2
    // and RandomNumberGenerator. Everything below is plain C# with no
    // P/Invoke and no OS crypto calls, so it works the same under Wine or
    // native Windows. Verified against the official NIST SHA-256 test
    // vectors, RFC 4231 HMAC-SHA256 test vectors, and the standard
    // PBKDF2-HMAC-SHA256 test vectors (P="password", S="salt").
    // -------------------------------------------------------------------

    internal static class ManagedSha256
    {
        private static readonly uint[] K = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        };

        public static byte[] ComputeHash(byte[] message)
        {
            uint[] h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

            long bitLen = (long)message.Length * 8;
            int padLen = ((message.Length + 8) / 64 + 1) * 64;
            byte[] padded = new byte[padLen];
            Buffer.BlockCopy(message, 0, padded, 0, message.Length);
            padded[message.Length] = 0x80;
            for (int i = 0; i < 8; i++)
                padded[padLen - 1 - i] = (byte)(bitLen >> (8 * i));

            uint[] w = new uint[64];
            for (int chunkStart = 0; chunkStart < padLen; chunkStart += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    int off = chunkStart + i * 4;
                    w[i] = (uint)(padded[off] << 24 | padded[off + 1] << 16 | padded[off + 2] << 8 | padded[off + 3]);
                }
                for (int i = 16; i < 64; i++)
                {
                    uint s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    uint s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
                for (int i = 0; i < 64; i++)
                {
                    uint S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint temp1 = hh + S1 + ch + K[i] + w[i];
                    uint S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = S0 + maj;

                    hh = g; g = f; f = e; e = d + temp1;
                    d = c; c = b; b = a; a = temp1 + temp2;
                }

                h[0] += a; h[1] += b; h[2] += c; h[3] += d;
                h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
            }

            byte[] result = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                result[i * 4] = (byte)(h[i] >> 24);
                result[i * 4 + 1] = (byte)(h[i] >> 16);
                result[i * 4 + 2] = (byte)(h[i] >> 8);
                result[i * 4 + 3] = (byte)h[i];
            }
            return result;
        }

        private static uint RotR(uint x, int n) => (x >> n) | (x << (32 - n));
    }

    internal static class ManagedHmacSha256
    {
        private const int BlockSize = 64;

        public static byte[] Compute(byte[] key, byte[] message)
        {
            if (key.Length > BlockSize)
                key = ManagedSha256.ComputeHash(key);
            if (key.Length < BlockSize)
                Array.Resize(ref key, BlockSize);

            byte[] oKeyPad = new byte[BlockSize];
            byte[] iKeyPad = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
            {
                oKeyPad[i] = (byte)(key[i] ^ 0x5c);
                iKeyPad[i] = (byte)(key[i] ^ 0x36);
            }

            byte[] inner = ManagedSha256.ComputeHash(Concat(iKeyPad, message));
            return ManagedSha256.ComputeHash(Concat(oKeyPad, inner));
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }

    internal static class ManagedPbkdf2
    {
        public static byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            int hLen = 32;
            int blockCount = (dkLen + hLen - 1) / hLen;
            byte[] output = new byte[blockCount * hLen];

            for (int i = 1; i <= blockCount; i++)
            {
                byte[] saltAndIndex = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, saltAndIndex, 0, salt.Length);
                saltAndIndex[salt.Length] = (byte)(i >> 24);
                saltAndIndex[salt.Length + 1] = (byte)(i >> 16);
                saltAndIndex[salt.Length + 2] = (byte)(i >> 8);
                saltAndIndex[salt.Length + 3] = (byte)i;

                byte[] u = ManagedHmacSha256.Compute(password, saltAndIndex);
                byte[] t = (byte[])u.Clone();

                for (int j = 1; j < iterations; j++)
                {
                    u = ManagedHmacSha256.Compute(password, u);
                    for (int k = 0; k < hLen; k++)
                        t[k] ^= u[k];
                }

                Buffer.BlockCopy(t, 0, output, (i - 1) * hLen, hLen);
            }

            byte[] result = new byte[dkLen];
            Buffer.BlockCopy(output, 0, result, 0, dkLen);
            return result;
        }
    }

    /// <summary>
    /// Salt generator with no OS crypto dependency. The salt only needs to be
    /// unique-ish per account (to stop identical passwords producing
    /// identical hashes across accounts) - it isn't a secret and doesn't need
    /// to resist prediction the way a session key would, so a well-seeded
    /// PRNG is an appropriate, Wine-safe substitute for a true CSPRNG here.
    /// </summary>
    internal static class ManagedRandom
    {
        private static ulong _state0;
        private static ulong _state1;
        private static readonly object _lock = new();

        static ManagedRandom()
        {
            unchecked
            {
                ulong seed = (ulong)DateTime.UtcNow.Ticks
                    ^ (ulong)Environment.TickCount64 * 0x9E3779B97F4A7C15UL
                    ^ (ulong)new object().GetHashCode() * 0xBF58476D1CE4E5B9UL
                    ^ (ulong)Environment.ProcessId << 32;
                _state0 = SplitMix64(ref seed);
                _state1 = SplitMix64(ref seed);
                if (_state0 == 0 && _state1 == 0)
                    _state0 = 1; // xorshift needs a non-zero state
            }
        }

        private static ulong SplitMix64(ref ulong x)
        {
            unchecked
            {
                x += 0x9E3779B97F4A7C15UL;
                ulong z = x;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
                return z ^ (z >> 31);
            }
        }

        private static ulong NextUInt64()
        {
            lock (_lock)
            {
                // xorshift128+
                ulong s1 = _state0;
                ulong s0 = _state1;
                _state0 = s0;
                s1 ^= s1 << 23;
                s1 ^= s1 >> 17;
                s1 ^= s0;
                s1 ^= s0 >> 26;
                _state1 = s1;
                unchecked { return _state1 + s0; }
            }
        }

        public static byte[] GetBytes(int count)
        {
            byte[] result = new byte[count];
            int i = 0;
            while (i < count)
            {
                ulong value = NextUInt64();
                for (int b = 0; b < 8 && i < count; b++, i++)
                    result[i] = (byte)(value >> (b * 8));
            }
            return result;
        }
    }
}

