using BannerlordFirewall.MissionBehaviors;
using BannerlordFirewall.PatchedCode;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using TaleWorlds.Library;
using TaleWorlds.ModuleManager;
using TaleWorlds.MountAndBlade;
using TaleWorlds.MountAndBlade.Diamond;
using TaleWorlds.PlayerServices;

namespace BannerlordFirewall
{
    public class BannerlordFirewall : MBSubModuleBase
    {
        private const int MaxWhitelistedPlayers = 512;
        public const int MaxPlayersPerJoinMessage = 128;
        private const int MaxWhitelistedIpsPerSubnet24 = 16;
        private const int PendingWhitelistSeconds = 20;
        private const int TemporaryBlockMinutes = 60;
        private const int MaxPendingTimeoutsBeforeBlock = 1;
        private const int MaxFastDisconnectsBeforeBlock = 3;
        private const int MaxIpChangesBeforeBlock = 4;
        private const int FastDisconnectSeconds = 45;
        private const string HarmonyId = "mentalrob.bannerlordfirewall.bannerlord";
        private const string NativeFilterDllName = "windivert_game_filter.dll";
        private const string DdosWebhookUrl = "WEB_HOOK_GIR";
        private const int DdosLogIntervalSeconds = 10;
        private const int MaxDdosIpsInLiveLog = 40;
        private const int MaxDdosIpsInDiscordLog = 90;

        public static BannerlordFirewall Instance;
        private static readonly BlockedIPLogCallback NativeBlockedIPLogCallback = OnNativeBlockedIPLog;
        private static readonly object DdosLogLock = new object();
        private static readonly ConcurrentDictionary<string, uint> DdosBlockedIpPacketCounts = new ConcurrentDictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        private static readonly HttpClient DdosWebhookHttpClient = new HttpClient();
        private static DateTime _nextDdosLogAtUtc = DateTime.MinValue;
        private static uint _ddosBlockedPacketCount;
        private static ushort _lastDdosPort;
        private static int _ddosLogSequence;
        private static int _ddosShutdownHandlersRegistered;
        private static int _ddosShutdownFlushStarted;

        public static readonly object FirewallLock = new object();

        public ConcurrentDictionary<PlayerId, IPAddress> WhitelistedIps;
        public ConcurrentDictionary<PlayerId, DateTime> WhitelistedIpLastSeen;
        public ConcurrentDictionary<PlayerId, bool> ActivePlayers;
        public ConcurrentDictionary<PlayerId, DateTime> ActivePlayerSince;
        public ConcurrentDictionary<string, DateTime> BlockedPlayers;
        public ConcurrentDictionary<string, DateTime> BlockedIpAddresses;
        public ConcurrentDictionary<string, int> PendingTimeoutCounts;
        public ConcurrentDictionary<string, int> FastDisconnectCounts;
        public ConcurrentDictionary<string, int> IpChangeCounts;
        public ConcurrentDictionary<string, string> LastPlayerIpAddress;

        public HarmonyLib.Harmony HarmonyHandle;

        private readonly ConcurrentDictionary<string, bool> _nativeAllowedIpAddresses = new ConcurrentDictionary<string, bool>();
        private bool _nativeFilterAvailable;

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void AddAllowedIP(uint ip);

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void RemoveAllowedIP(uint ip);

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void SetProtectedUdpPort(ushort port);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void BlockedIPLogCallback(uint ip, ushort port, uint blockedPacketCount);

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void SetBlockedIPLogCallback(BlockedIPLogCallback callback);

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I4)]
        private static extern int StartFilter();

        [DllImport(NativeFilterDllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void StopFilter();

        public bool IsNativeFilterAvailable()
        {
            return this._nativeFilterAvailable;
        }

        public bool EnsureFirewallRule()
        {
            return this.EnsureNativeFilter();
        }

        public bool EnsureNativeFilter()
        {
            try
            {
                lock (FirewallLock)
                {
                    int port = Module.CurrentModule.StartupInfo.ServerPort;
                    if (port < 1 || port > 65535)
                    {
                        throw new InvalidOperationException("[BannerlordFirewall] Invalid server port: " + port.ToString());
                    }

                    SetProtectedUdpPort(Convert.ToUInt16(port));
                    SetBlockedIPLogCallback(NativeBlockedIPLogCallback);
                    if (StartFilter() == 0)
                    {
                        throw new InvalidOperationException("StartFilter returned failure");
                    }

                    this.RefreshFirewallWhitelistLocked();
                    this._nativeFilterAvailable = true;
                    return true;
                }
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] Native WinDivert filter could not be initialized: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                this._nativeFilterAvailable = false;
                return false;
            }
        }

        public bool TryWhitelistPlayerIp(PlayerId playerId, string rawIpAddress, bool refreshFirewall)
        {
            if (playerId == null)
            {
                Debug.Print("[BannerlordFirewall] Rejected join data with empty player id.", 0, Debug.DebugColor.DarkYellow);
                return false;
            }

            IPAddress firewallAddress;
            string rejectReason;
            if (!TryCreateFirewallAddress(rawIpAddress, out firewallAddress, out rejectReason))
            {
                Debug.Print("[BannerlordFirewall] Rejected suspicious IP '" + SafeLogValue(rawIpAddress) + "': " + rejectReason, 0, Debug.DebugColor.DarkYellow);
                return false;
            }

            lock (FirewallLock)
            {
                this.RemoveExpiredBlocksLocked();

                string playerKey = GetPlayerKey(playerId);
                string ipAddressText = firewallAddress.ToString();
                if (this.IsPlayerOrIpBlockedLocked(playerKey, ipAddressText))
                {
                    Debug.Print("[BannerlordFirewall] Blocked player/IP tried to join again: " + SafeLogValue(playerKey) + " / " + ipAddressText, 0, Debug.DebugColor.Red);
                    return false;
                }

                string lastIpAddress;
                if (this.LastPlayerIpAddress.TryGetValue(playerKey, out lastIpAddress) && !string.Equals(lastIpAddress, ipAddressText, StringComparison.Ordinal))
                {
                    int ipChangeCount = this.IpChangeCounts.AddOrUpdate(playerKey, 1, (key, value) => value + 1);
                    if (ipChangeCount >= MaxIpChangesBeforeBlock)
                    {
                        this.BlockPlayerAndIpLocked(playerKey, ipAddressText, "too many IP/VPN changes");
                        return false;
                    }
                }

                this.LastPlayerIpAddress[playerKey] = ipAddressText;

                if (!this.WhitelistedIps.ContainsKey(playerId) && this.WhitelistedIps.Count >= MaxWhitelistedPlayers)
                {
                    Debug.Print("[BannerlordFirewall] Whitelist is full; rejected " + firewallAddress.ToString(), 0, Debug.DebugColor.Red);
                    return false;
                }

                if (!this.WhitelistedIps.ContainsKey(playerId) && this.GetWhitelistedCountInSameSubnet24(firewallAddress) >= MaxWhitelistedIpsPerSubnet24)
                {
                    Debug.Print("[BannerlordFirewall] Too many whitelisted IPs from same /24 subnet; rejected " + firewallAddress.ToString(), 0, Debug.DebugColor.Red);
                    return false;
                }

                bool isAlreadyActive;
                this.ActivePlayers.TryGetValue(playerId, out isAlreadyActive);

                this.WhitelistedIps[playerId] = firewallAddress;
                this.WhitelistedIpLastSeen[playerId] = DateTime.UtcNow;
                this.ActivePlayers[playerId] = isAlreadyActive;
                Debug.Print("[BannerlordFirewall] " + firewallAddress.ToString() + " added to pending native whitelist", 0, Debug.DebugColor.Green);

                if (refreshFirewall)
                {
                    this.RefreshFirewallWhitelistLocked();
                }
            }

            return true;
        }

        public bool MarkPlayerInGame(PlayerId playerId, string playerName)
        {
            if (playerId == null)
            {
                return false;
            }

            lock (FirewallLock)
            {
                if (!this.WhitelistedIps.ContainsKey(playerId))
                {
                    Debug.Print("[BannerlordFirewall] " + SafeLogValue(playerName) + " is in game but has no whitelisted IP yet.", 0, Debug.DebugColor.DarkYellow);
                    return false;
                }

                this.ActivePlayers[playerId] = true;
                this.ActivePlayerSince[playerId] = DateTime.UtcNow;
                this.WhitelistedIpLastSeen[playerId] = DateTime.UtcNow;
                this.RefreshFirewallWhitelistLocked();
                Debug.Print("[BannerlordFirewall] " + SafeLogValue(playerName) + " confirmed in game; native filter IP is now active.", 0, Debug.DebugColor.Green);
                return true;
            }
        }

        public bool RemoveWhitelistedPlayer(PlayerId playerId, string playerName)
        {
            if (playerId == null)
            {
                return false;
            }

            lock (FirewallLock)
            {
                IPAddress removedAddress;
                if (!this.WhitelistedIps.TryRemove(playerId, out removedAddress))
                {
                    return false;
                }

                DateTime removedLastSeen;
                this.WhitelistedIpLastSeen.TryRemove(playerId, out removedLastSeen);
                bool removedActiveState;
                this.ActivePlayers.TryRemove(playerId, out removedActiveState);
                DateTime activeSince;
                this.ActivePlayerSince.TryRemove(playerId, out activeSince);

                if (removedActiveState && activeSince != default(DateTime) && DateTime.UtcNow.Subtract(activeSince).TotalSeconds <= FastDisconnectSeconds)
                {
                    string playerKey = GetPlayerKey(playerId);
                    string ipAddressText = removedAddress == null ? null : removedAddress.ToString();
                    int fastDisconnectCount = this.FastDisconnectCounts.AddOrUpdate(playerKey, 1, (key, value) => value + 1);
                    if (fastDisconnectCount >= MaxFastDisconnectsBeforeBlock)
                    {
                        this.BlockPlayerAndIpLocked(playerKey, ipAddressText, "too many fast disconnects after joining");
                    }
                }

                this.RefreshFirewallWhitelistLocked();
                Debug.Print("[BannerlordFirewall] " + SafeLogValue(playerName) + " was removed from the native whitelist, whitelisted ip count: " + this.WhitelistedIps.Count.ToString(), 0, Debug.DebugColor.Red);
                return true;
            }
        }

        private int GetWhitelistedCountInSameSubnet24(IPAddress newAddress)
        {
            string newSubnet;
            if (!TryGetSubnet24(newAddress, out newSubnet))
            {
                return 0;
            }

            int count = 0;
            foreach (IPAddress address in this.WhitelistedIps.Values)
            {
                string subnet;
                if (TryGetSubnet24(address, out subnet) && string.Equals(subnet, newSubnet, StringComparison.Ordinal))
                {
                    count++;
                }
            }

            return count;
        }

        private static bool TryGetSubnet24(IPAddress address, out string subnet)
        {
            subnet = null;
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            subnet = bytes[0].ToString() + "." + bytes[1].ToString() + "." + bytes[2].ToString();
            return true;
        }

        public void RefreshFirewallWhitelist()
        {
            lock (FirewallLock)
            {
                this.RefreshFirewallWhitelistLocked();
            }
        }

        private void RefreshFirewallWhitelistLocked()
        {
            try
            {
                this.RemoveExpiredBlocksLocked();
                this.RemoveExpiredWhitelistEntriesLocked();
                this.SyncNativeWhitelistLocked();
                this._nativeFilterAvailable = true;
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] Native whitelist update failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                this._nativeFilterAvailable = false;
            }
        }

        private void RemoveExpiredWhitelistEntriesLocked()
        {
            DateTime expireBefore = DateTime.UtcNow.AddSeconds(-PendingWhitelistSeconds);
            foreach (var lastSeen in this.WhitelistedIpLastSeen.ToArray())
            {
                bool isActive;
                if (this.ActivePlayers.TryGetValue(lastSeen.Key, out isActive) && isActive)
                {
                    continue;
                }

                if (lastSeen.Value >= expireBefore)
                {
                    continue;
                }

                IPAddress removedAddress;
                DateTime removedLastSeen;
                bool removedActiveState;
                DateTime removedActiveSince;
                this.WhitelistedIps.TryRemove(lastSeen.Key, out removedAddress);
                this.WhitelistedIpLastSeen.TryRemove(lastSeen.Key, out removedLastSeen);
                this.ActivePlayers.TryRemove(lastSeen.Key, out removedActiveState);
                this.ActivePlayerSince.TryRemove(lastSeen.Key, out removedActiveSince);

                string playerKey = GetPlayerKey(lastSeen.Key);
                int pendingTimeoutCount = this.PendingTimeoutCounts.AddOrUpdate(playerKey, 1, (key, value) => value + 1);
                if (pendingTimeoutCount >= MaxPendingTimeoutsBeforeBlock)
                {
                    this.BlockPlayerAndIpLocked(playerKey, removedAddress == null ? null : removedAddress.ToString(), "too many pending joins without entering the game");
                }

                Debug.Print("[BannerlordFirewall] Removed expired pending whitelist IP.", 0, Debug.DebugColor.DarkYellow);
            }
        }

        private bool IsPlayerOrIpBlockedLocked(string playerKey, string ipAddressText)
        {
            DateTime blockedUntil;
            if (!string.IsNullOrEmpty(playerKey) && this.BlockedPlayers.TryGetValue(playerKey, out blockedUntil) && blockedUntil > DateTime.UtcNow)
            {
                return true;
            }

            if (!string.IsNullOrEmpty(ipAddressText) && this.BlockedIpAddresses.TryGetValue(ipAddressText, out blockedUntil) && blockedUntil > DateTime.UtcNow)
            {
                return true;
            }

            return false;
        }

        private void BlockPlayerAndIpLocked(string playerKey, string ipAddressText, string reason)
        {
            DateTime blockedUntil = DateTime.UtcNow.AddMinutes(TemporaryBlockMinutes);

            if (!string.IsNullOrEmpty(playerKey))
            {
                this.BlockedPlayers[playerKey] = blockedUntil;
            }

            if (!string.IsNullOrEmpty(ipAddressText))
            {
                this.BlockedIpAddresses[ipAddressText] = blockedUntil;
            }

            foreach (var pair in this.WhitelistedIps.ToArray())
            {
                if (string.Equals(GetPlayerKey(pair.Key), playerKey, StringComparison.Ordinal) ||
                    (!string.IsNullOrEmpty(ipAddressText) && pair.Value != null && string.Equals(pair.Value.ToString(), ipAddressText, StringComparison.Ordinal)))
                {
                    IPAddress removedAddress;
                    DateTime removedLastSeen;
                    bool removedActiveState;
                    DateTime removedActiveSince;
                    this.WhitelistedIps.TryRemove(pair.Key, out removedAddress);
                    this.WhitelistedIpLastSeen.TryRemove(pair.Key, out removedLastSeen);
                    this.ActivePlayers.TryRemove(pair.Key, out removedActiveState);
                    this.ActivePlayerSince.TryRemove(pair.Key, out removedActiveSince);
                }
            }

            this.SyncNativeWhitelistLocked();
            Debug.Print("[BannerlordFirewall] TEMP BLOCK for " + TemporaryBlockMinutes.ToString() + " minutes (" + SafeLogValue(reason) + "): " + SafeLogValue(playerKey) + " / " + SafeLogValue(ipAddressText), 0, Debug.DebugColor.Red);
        }

        private void RemoveExpiredBlocksLocked()
        {
            DateTime now = DateTime.UtcNow;

            foreach (var block in this.BlockedPlayers.ToArray())
            {
                if (block.Value <= now)
                {
                    DateTime removedUntil;
                    this.BlockedPlayers.TryRemove(block.Key, out removedUntil);
                }
            }

            foreach (var block in this.BlockedIpAddresses.ToArray())
            {
                if (block.Value <= now)
                {
                    DateTime removedUntil;
                    this.BlockedIpAddresses.TryRemove(block.Key, out removedUntil);
                }
            }
        }

        private void SyncNativeWhitelistLocked()
        {
            string[] desiredAddresses = this.WhitelistedIps.Values
                .Where(address => address != null && address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.ToString())
                .Where(address => !this.BlockedIpAddresses.ContainsKey(address))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxWhitelistedPlayers)
                .ToArray();

            foreach (string desiredAddress in desiredAddresses)
            {
                if (this._nativeAllowedIpAddresses.ContainsKey(desiredAddress))
                {
                    continue;
                }

                AddAllowedIP(ToNativeUInt32(desiredAddress));
                this._nativeAllowedIpAddresses[desiredAddress] = true;
            }

            foreach (string existingAddress in this._nativeAllowedIpAddresses.Keys.ToArray())
            {
                if (desiredAddresses.Contains(existingAddress, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                RemoveAllowedIP(ToNativeUInt32(existingAddress));
                bool removed;
                this._nativeAllowedIpAddresses.TryRemove(existingAddress, out removed);
            }
        }

        private static bool TryCreateFirewallAddress(string rawIpAddress, out IPAddress firewallAddress, out string rejectReason)
        {
            firewallAddress = null;
            rejectReason = null;

            if (string.IsNullOrWhiteSpace(rawIpAddress))
            {
                rejectReason = "empty address";
                return false;
            }

            IPAddress ipAddress;
            if (!IPAddress.TryParse(rawIpAddress.Trim(), out ipAddress))
            {
                rejectReason = "invalid IP format";
                return false;
            }

            if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                rejectReason = "only IPv4 addresses are accepted";
                return false;
            }

            if (!IsPublicUnicastIpv4(ipAddress, out rejectReason))
            {
                return false;
            }

            firewallAddress = ipAddress;
            return true;
        }

        private static uint ToNativeUInt32(string ipAddressText)
        {
            return BitConverter.ToUInt32(IPAddress.Parse(ipAddressText).GetAddressBytes(), 0);
        }

        private static void OnNativeBlockedIPLog(uint ip, ushort port, uint blockedPacketCount)
        {
            try
            {
                string ipAddressText = new IPAddress(BitConverter.GetBytes(ip)).ToString();
                RegisterDdosBlockedPacket(ipAddressText, port, blockedPacketCount);
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] WinDivert blocked packet log failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
            }
        }

        private static void RegisterDdosBlockedPacket(string ipAddressText, ushort port, uint blockedPacketCount)
        {
            DateTime now = DateTime.UtcNow;

            lock (DdosLogLock)
            {
                if (_nextDdosLogAtUtc == DateTime.MinValue)
                {
                    _nextDdosLogAtUtc = now.AddSeconds(DdosLogIntervalSeconds);
                }

                _lastDdosPort = port;
                _ddosBlockedPacketCount = AddUInt32Clamped(_ddosBlockedPacketCount, blockedPacketCount);
                DdosBlockedIpPacketCounts.AddOrUpdate(ipAddressText, blockedPacketCount, (key, value) => AddUInt32Clamped(value, blockedPacketCount));

                if (now >= _nextDdosLogAtUtc)
                {
                    FlushDdosLogLocked(false);
                    _nextDdosLogAtUtc = now.AddSeconds(DdosLogIntervalSeconds);
                }
            }
        }

        private static void FlushDdosLogLocked(bool serverStopping)
        {
            if (_ddosBlockedPacketCount == 0 || DdosBlockedIpPacketCounts.Count == 0)
            {
                return;
            }

            int logNumber = ++_ddosLogSequence;
            string modulePath = GetBannerlordFirewallModulePath();
            string consoleMessage = BuildDdosConsoleLogMessage(modulePath, serverStopping, logNumber);
            string discordMessage = BuildDdosDiscordLogMessage(modulePath, serverStopping, logNumber);
            Debug.Print(consoleMessage, 0, Debug.DebugColor.Red);
            SendDiscordWebhook(discordMessage);
            WriteDdosFileLog(modulePath, logNumber, serverStopping, consoleMessage + Environment.NewLine + discordMessage);

            uint ignored;
            foreach (string key in DdosBlockedIpPacketCounts.Keys.ToArray())
            {
                DdosBlockedIpPacketCounts.TryRemove(key, out ignored);
            }

            _ddosBlockedPacketCount = 0;
        }

        private static string BuildDdosConsoleLogMessage(string modulePath, bool serverStopping, int logNumber)
        {
            var topIps = DdosBlockedIpPacketCounts
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Take(MaxDdosIpsInLiveLog)
                .ToArray();

            StringBuilder builder = new StringBuilder();
            builder.Append(serverStopping ? "[BannerlordFirewall] SERVER STOP DDoS summary" : "[BannerlordFirewall] DDoS summary");
            builder.Append(" #");
            builder.Append(logNumber.ToString("D6"));
            builder.Append(" | UDP ");
            builder.Append(_lastDdosPort.ToString());
            builder.Append(" | packets: ");
            builder.Append(_ddosBlockedPacketCount.ToString());
            builder.Append(" | unique IPs: ");
            builder.Append(DdosBlockedIpPacketCounts.Count.ToString());
            builder.Append(" | modulePath: ");
            builder.Append(modulePath);

            builder.AppendLine();
            builder.Append("Top IPs: ");
            for (int i = 0; i < topIps.Length; i++)
            {
                if (i > 0)
                {
                    builder.Append(", ");
                }

                builder.Append(topIps[i].Key);
                builder.Append("=");
                builder.Append(topIps[i].Value.ToString());
            }

            if (DdosBlockedIpPacketCounts.Count > topIps.Length)
            {
                builder.Append(", ... +");
                builder.Append((DdosBlockedIpPacketCounts.Count - topIps.Length).ToString());
                builder.Append(" more");
            }

            return TruncateForDiscord(builder.ToString());
        }

        private static string BuildDdosDiscordLogMessage(string modulePath, bool serverStopping, int logNumber)
        {
            var liveIps = DdosBlockedIpPacketCounts
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Take(MaxDdosIpsInDiscordLog)
                .ToArray();

            StringBuilder builder = new StringBuilder();
            builder.Append(serverStopping ? "**BannerlordFirewall DDoS Final Raporu**" : "**BannerlordFirewall Canli DDoS Raporu**");
            builder.Append(" `#");
            builder.Append(logNumber.ToString("D6"));
            builder.Append("`");
            builder.AppendLine();
            builder.Append("Port: UDP ");
            builder.Append(_lastDdosPort.ToString());
            builder.Append(" | Paket: ");
            builder.Append(_ddosBlockedPacketCount.ToString());
            builder.Append(" | IP cesidi: ");
            builder.Append(DdosBlockedIpPacketCounts.Count.ToString());
            builder.Append(" | Pencere: ");
            builder.Append(DdosLogIntervalSeconds.ToString());
            builder.Append(" sn");
            builder.AppendLine();
            builder.Append("ModulePath: ");
            builder.Append(modulePath);
            builder.AppendLine();
            builder.AppendLine();
            builder.AppendLine("Canli IP listesi:");

            for (int i = 0; i < liveIps.Length; i++)
            {
                builder.Append("- ");
                builder.Append(liveIps[i].Key);
                builder.Append(" = ");
                builder.Append(liveIps[i].Value.ToString());
                builder.AppendLine(" paket");
            }

            if (DdosBlockedIpPacketCounts.Count > liveIps.Length)
            {
                builder.Append("... +");
                builder.Append((DdosBlockedIpPacketCounts.Count - liveIps.Length).ToString());
                builder.AppendLine(" IP daha");
            }

            return TruncateForDiscord(builder.ToString());
        }

        private static void SendDiscordWebhook(string message)
        {
            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    string payload = "{\"content\":\"" + JsonEscape((string)state) + "\"}";
                    using (StringContent content = new StringContent(payload, Encoding.UTF8, "application/json"))
                    {
                        DdosWebhookHttpClient.PostAsync(DdosWebhookUrl, content).Wait(5000);
                    }
                }
                catch (Exception exception)
                {
                    Debug.Print("[BannerlordFirewall] Discord DDoS webhook failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                }
            }, message);
        }

        private static void WriteDdosFileLog(string modulePath, int logNumber, bool serverStopping, string message)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(modulePath))
                {
                    return;
                }

                Directory.CreateDirectory(modulePath);
                string logLine = "================ DDoS LOG #" + logNumber.ToString("D6") + " " + DateTime.UtcNow.ToString("o") + (serverStopping ? " SERVER_STOP" : " LIVE") + " ================" + Environment.NewLine + message + Environment.NewLine;
                File.AppendAllText(Path.Combine(modulePath, "ddos_live_ips.log"), logLine);
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] DDoS file log failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
            }
        }

        private static void RegisterDdosShutdownHandlers()
        {
            if (Interlocked.Exchange(ref _ddosShutdownHandlersRegistered, 1) == 1)
            {
                return;
            }

            AppDomain.CurrentDomain.ProcessExit += OnDdosProcessExit;
            AppDomain.CurrentDomain.DomainUnload += OnDdosProcessExit;
        }

        private static void OnDdosProcessExit(object sender, EventArgs eventArgs)
        {
            if (Interlocked.Exchange(ref _ddosShutdownFlushStarted, 1) == 1)
            {
                return;
            }

            try
            {
                lock (DdosLogLock)
                {
                    FlushDdosLogLocked(true);
                }
            }
            catch
            {
            }
        }

        private static string GetBannerlordFirewallModulePath()
        {
            try
            {
                return ModuleHelper.GetModuleFullPath("BannerlordFirewall");
            }
            catch (Exception exception)
            {
                return "ModuleHelper.GetModuleFullPath failed: " + SafeLogValue(exception.Message);
            }
        }

        private static uint AddUInt32Clamped(uint left, uint right)
        {
            return uint.MaxValue - left < right ? uint.MaxValue : left + right;
        }

        private static string TruncateForDiscord(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= 1900)
            {
                return value;
            }

            return value.Substring(0, 1900) + "...";
        }

        private static string JsonEscape(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }

        private static bool IsPublicUnicastIpv4(IPAddress ipAddress, out string rejectReason)
        {
            rejectReason = null;
            byte[] bytes = ipAddress.GetAddressBytes();

            if (bytes[0] == 0)
            {
                rejectReason = "0.0.0.0/8 is not routable";
                return false;
            }

            if (bytes[0] == 10 || bytes[0] == 127)
            {
                rejectReason = "private or loopback address";
                return false;
            }

            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            {
                rejectReason = "carrier-grade NAT address";
                return false;
            }

            if (bytes[0] == 169 && bytes[1] == 254)
            {
                rejectReason = "link-local address";
                return false;
            }

            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                rejectReason = "private address";
                return false;
            }

            if (bytes[0] == 192 && bytes[1] == 168)
            {
                rejectReason = "private address";
                return false;
            }

            if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
            {
                rejectReason = "documentation address";
                return false;
            }

            if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))
            {
                rejectReason = "benchmark address";
                return false;
            }

            if (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
            {
                rejectReason = "documentation address";
                return false;
            }

            if (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
            {
                rejectReason = "documentation address";
                return false;
            }

            if (bytes[0] >= 224)
            {
                rejectReason = "multicast or reserved address";
                return false;
            }

            return true;
        }

        private static string SafeLogValue(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value.Replace("\r", string.Empty).Replace("\n", string.Empty);
        }

        private static string GetPlayerKey(PlayerId playerId)
        {
            return playerId == null ? string.Empty : playerId.ToString();
        }

        protected override void OnSubModuleLoad()
        {
            base.OnSubModuleLoad();
            Instance = this;

            this.WhitelistedIps = new ConcurrentDictionary<PlayerId, IPAddress>();
            this.WhitelistedIpLastSeen = new ConcurrentDictionary<PlayerId, DateTime>();
            this.ActivePlayers = new ConcurrentDictionary<PlayerId, bool>();
            this.ActivePlayerSince = new ConcurrentDictionary<PlayerId, DateTime>();
            this.BlockedPlayers = new ConcurrentDictionary<string, DateTime>();
            this.BlockedIpAddresses = new ConcurrentDictionary<string, DateTime>();
            this.PendingTimeoutCounts = new ConcurrentDictionary<string, int>();
            this.FastDisconnectCounts = new ConcurrentDictionary<string, int>();
            this.IpChangeCounts = new ConcurrentDictionary<string, int>();
            this.LastPlayerIpAddress = new ConcurrentDictionary<string, string>();
            RegisterDdosShutdownHandlers();

            this.HarmonyHandle = new HarmonyLib.Harmony(HarmonyId);
            var original = typeof(CustomBattleServer).GetMethod("OnClientWantsToConnectCustomGameMessage", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var prefix = typeof(PatchCustomBattleServer).GetMethod("PrefixOnClientWantsToConnectCustomGameMessage", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            if (original == null || prefix == null)
            {
                Debug.Print("[BannerlordFirewall] Harmony patch target was not found; whitelist cannot be updated from join messages.", 0, Debug.DebugColor.Red);
            }
            else
            {
                try
                {
                    this.HarmonyHandle.Patch(original, prefix: new HarmonyLib.HarmonyMethod(prefix));
                    Debug.Print("[BannerlordFirewall] Harmony patch installed.", 0, Debug.DebugColor.Green);
                }
                catch (Exception exception)
                {
                    Debug.Print("[BannerlordFirewall] Harmony patch failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                }
            }

            this.EnsureNativeFilter();
        }

        public override void OnBeforeMissionBehaviorInitialize(Mission mission)
        {
            if (mission == null)
            {
                return;
            }

            Debug.Print("[BannerlordFirewall] Trying to add RemoveIpBehavior...", 0, Debug.DebugColor.DarkYellow);
            mission.AddMissionBehavior(new RemoveIpBehavior());
        }

        protected override void OnSubModuleUnloaded()
        {
            try
            {
                OnDdosProcessExit(null, EventArgs.Empty);

                SetBlockedIPLogCallback(null);
                StopFilter();
            }
            catch
            {
            }

            base.OnSubModuleUnloaded();
        }
    }
}
