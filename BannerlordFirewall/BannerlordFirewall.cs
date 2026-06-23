using BannerlordFirewall.MissionBehaviors;
using BannerlordFirewall.PatchedCode;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using TaleWorlds.Library;
using TaleWorlds.MountAndBlade;
using TaleWorlds.MountAndBlade.Diamond;
using TaleWorlds.PlayerServices;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;

namespace BannerlordFirewall
{
    public class BannerlordFirewall : MBSubModuleBase
    {
        private const int MaxWhitelistedPlayers = 512;
        public const int MaxPlayersPerJoinMessage = 128;
        private const int MaxWhitelistedIpsPerSubnet24 = 16;
        private const int PendingWhitelistSeconds = 90;
        private const int TemporaryBlockMinutes = 60;
        private const int MaxPendingTimeoutsBeforeBlock = 3;
        private const int MaxFastDisconnectsBeforeBlock = 3;
        private const int MaxIpChangesBeforeBlock = 4;
        private const int FastDisconnectSeconds = 45;
        private static readonly bool DisableConflictingAllowRules = true;
        private const string HarmonyId = "mentalrob.bannerlordfirewall.bannerlord";
        private const string LocalOnlyFallbackAddress = "127.255.255.254";

        public static BannerlordFirewall Instance;

        public static readonly object FirewallLock = new object();

        public ConcurrentDictionary<PlayerId, IAddress> WhitelistedIps;
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

        private IFirewallRule _cachedFirewallRule;
        private IFirewallRule _cachedBlacklistFirewallRule;

        public string GetFirewallRuleName()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            return "Bannerlord Firewall " + port.ToString();
        }

        public string GetBlacklistFirewallRuleName()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            return "Bannerlord Firewall Blacklist " + port.ToString();
        }

        public IFirewallRule GetFirewallRule()
        {
            if (this._cachedFirewallRule == null)
            {
                string ruleName = this.GetFirewallRuleName();
                this._cachedFirewallRule = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == ruleName);
            }

            return this._cachedFirewallRule;
        }

        public IFirewallRule GetBlacklistFirewallRule()
        {
            if (this._cachedBlacklistFirewallRule == null)
            {
                string ruleName = this.GetBlacklistFirewallRuleName();
                this._cachedBlacklistFirewallRule = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == ruleName);
            }

            return this._cachedBlacklistFirewallRule;
        }

        public void CreateFirewallRule()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            if (port < 1 || port > 65535)
            {
                throw new InvalidOperationException("[BannerlordFirewall] Invalid server port: " + port.ToString());
            }

            this._cachedFirewallRule = FirewallManager.Instance.CreatePortRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                this.GetFirewallRuleName(),
                FirewallAction.Allow,
                Convert.ToUInt16(port),
                FirewallProtocol.UDP
            );
            this._cachedFirewallRule.RemoteAddresses = BuildRemoteAddressList(this.WhitelistedIps.Values.ToArray());
            FirewallManager.Instance.Rules.Add(this._cachedFirewallRule);
        }

        public void CreateBlacklistFirewallRule()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            if (port < 1 || port > 65535)
            {
                throw new InvalidOperationException("[BannerlordFirewall] Invalid server port: " + port.ToString());
            }

            this._cachedBlacklistFirewallRule = FirewallManager.Instance.CreatePortRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                this.GetBlacklistFirewallRuleName(),
                FirewallAction.Block,
                Convert.ToUInt16(port),
                FirewallProtocol.UDP
            );
            this._cachedBlacklistFirewallRule.RemoteAddresses = BuildRemoteAddressList(this.GetBlockedFirewallAddressesLocked());
            FirewallManager.Instance.Rules.Add(this._cachedBlacklistFirewallRule);
        }

        public bool EnsureFirewallRule()
        {
            try
            {
                lock (FirewallLock)
                {
                    if (this.GetFirewallRule() == null)
                    {
                        Debug.Print("[BannerlordFirewall] FirewallRule " + this.GetFirewallRuleName() + " not found on your server. Creating...", 0, Debug.DebugColor.Red);
                        this.CreateFirewallRule();
                    }

                    if (this.GetBlacklistFirewallRule() == null)
                    {
                        Debug.Print("[BannerlordFirewall] Blacklist FirewallRule " + this.GetBlacklistFirewallRuleName() + " not found on your server. Creating...", 0, Debug.DebugColor.Red);
                        this.CreateBlacklistFirewallRule();
                    }

                    this.HardenFirewallRuleLocked();
                    this.HardenBlacklistFirewallRuleLocked();
                    this.RefreshFirewallWhitelistLocked();
                    this.HandleConflictingAllowRulesLocked();
                    return this.GetFirewallRule() != null && this.GetBlacklistFirewallRule() != null;
                }
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] Firewall rule could not be created or updated: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                this._cachedFirewallRule = null;
                this._cachedBlacklistFirewallRule = null;
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

            IAddress firewallAddress;
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
                Debug.Print("[BannerlordFirewall] " + firewallAddress.ToString() + " added to pending firewall whitelist", 0, Debug.DebugColor.Green);

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
                Debug.Print("[BannerlordFirewall] " + SafeLogValue(playerName) + " confirmed in game; firewall IP is now active.", 0, Debug.DebugColor.Green);
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
                IAddress removedAddress;
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
                Debug.Print("[BannerlordFirewall] " + SafeLogValue(playerName) + " was removed from the firewall whitelist, whitelisted ip count: " + this.WhitelistedIps.Count.ToString(), 0, Debug.DebugColor.Red);
                return true;
            }
        }

        private int GetWhitelistedCountInSameSubnet24(IAddress newAddress)
        {
            string newSubnet;
            if (!TryGetSubnet24(newAddress, out newSubnet))
            {
                return 0;
            }

            int count = 0;
            foreach (IAddress address in this.WhitelistedIps.Values)
            {
                string subnet;
                if (TryGetSubnet24(address, out subnet) && string.Equals(subnet, newSubnet, StringComparison.Ordinal))
                {
                    count++;
                }
            }

            return count;
        }

        private static bool TryGetSubnet24(IAddress address, out string subnet)
        {
            subnet = null;
            if (address == null)
            {
                return false;
            }

            IPAddress ipAddress;
            if (!IPAddress.TryParse(address.ToString(), out ipAddress) || ipAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = ipAddress.GetAddressBytes();
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
            IFirewallRule firewallRule = this.GetFirewallRule();
            if (firewallRule == null)
            {
                return;
            }

            try
            {
                this.RemoveExpiredBlocksLocked();
                this.RemoveExpiredWhitelistEntriesLocked();
                this.HardenFirewallRuleLocked();
                this.HardenBlacklistFirewallRuleLocked();
                this.HandleConflictingAllowRulesLocked();
                firewallRule.RemoteAddresses = BuildRemoteAddressList(this.WhitelistedIps.Values.ToArray());
            }
            catch (Exception exception)
            {
                Debug.Print("[BannerlordFirewall] Firewall whitelist update failed: " + SafeLogValue(exception.Message), 0, Debug.DebugColor.Red);
                this._cachedFirewallRule = null;
                this._cachedBlacklistFirewallRule = null;
            }
        }

        private void HardenFirewallRuleLocked()
        {
            IFirewallRule firewallRule = this.GetFirewallRule();
            if (firewallRule == null)
            {
                return;
            }

            int port = Module.CurrentModule.StartupInfo.ServerPort;
            firewallRule.IsEnable = true;
            firewallRule.Action = FirewallAction.Allow;
            firewallRule.Direction = FirewallDirection.Inbound;
            firewallRule.Protocol = FirewallProtocol.UDP;
            firewallRule.LocalPorts = new ushort[] { Convert.ToUInt16(port) };
            firewallRule.RemoteAddresses = BuildRemoteAddressList(this.WhitelistedIps.Values.ToArray());
        }

        private void HardenBlacklistFirewallRuleLocked()
        {
            IFirewallRule firewallRule = this.GetBlacklistFirewallRule();
            if (firewallRule == null)
            {
                return;
            }

            int port = Module.CurrentModule.StartupInfo.ServerPort;
            firewallRule.IsEnable = true;
            firewallRule.Action = FirewallAction.Block;
            firewallRule.Direction = FirewallDirection.Inbound;
            firewallRule.Protocol = FirewallProtocol.UDP;
            firewallRule.LocalPorts = new ushort[] { Convert.ToUInt16(port) };
            firewallRule.RemoteAddresses = BuildRemoteAddressList(this.GetBlockedFirewallAddressesLocked());
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

                IAddress removedAddress;
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
                    IAddress removedAddress;
                    DateTime removedLastSeen;
                    bool removedActiveState;
                    DateTime removedActiveSince;
                    this.WhitelistedIps.TryRemove(pair.Key, out removedAddress);
                    this.WhitelistedIpLastSeen.TryRemove(pair.Key, out removedLastSeen);
                    this.ActivePlayers.TryRemove(pair.Key, out removedActiveState);
                    this.ActivePlayerSince.TryRemove(pair.Key, out removedActiveSince);
                }
            }

            this.HardenBlacklistFirewallRuleLocked();
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

            this.HardenBlacklistFirewallRuleLocked();
        }

        private IAddress[] GetBlockedFirewallAddressesLocked()
        {
            DateTime now = DateTime.UtcNow;
            return this.BlockedIpAddresses
                .Where(block => block.Value > now)
                .Select(block => CreateSingleIpOrNull(block.Key))
                .Where(address => address != null)
                .GroupBy(address => address.ToString(), StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(MaxWhitelistedPlayers)
                .ToArray();
        }

        private static IAddress CreateSingleIpOrNull(string ipAddressText)
        {
            if (string.IsNullOrWhiteSpace(ipAddressText))
            {
                return null;
            }

            SingleIP address;
            if (!SingleIP.TryParse(ipAddressText, out address))
            {
                return null;
            }

            return address;
        }

        private void HandleConflictingAllowRulesLocked()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            foreach (IFirewallRule rule in FirewallManager.Instance.Rules)
            {
                if (rule == null ||
                    string.Equals(rule.Name, this.GetFirewallRuleName(), StringComparison.Ordinal) ||
                    string.Equals(rule.Name, this.GetBlacklistFirewallRuleName(), StringComparison.Ordinal))
                {
                    continue;
                }

                if (!rule.IsEnable || rule.Action != FirewallAction.Allow || rule.Protocol != FirewallProtocol.UDP)
                {
                    continue;
                }

                if (rule.LocalPorts == null || !rule.LocalPorts.Contains(Convert.ToUInt16(port)))
                {
                    continue;
                }

                if (rule.RemoteAddresses == null || rule.RemoteAddresses.Length == 0)
                {
                    if (DisableConflictingAllowRules)
                    {
                        rule.IsEnable = false;
                        Debug.Print("[BannerlordFirewall] DISABLED conflicting allow-any UDP rule on port " + port.ToString() + ": " + SafeLogValue(rule.Name), 0, Debug.DebugColor.Red);
                    }
                    else
                    {
                        Debug.Print("[BannerlordFirewall] WARNING: Another enabled allow rule opens UDP port " + port.ToString() + " to everyone: " + SafeLogValue(rule.Name), 0, Debug.DebugColor.Red);
                    }
                }
            }
        }

        private static IAddress[] BuildRemoteAddressList(IAddress[] allowedAddresses)
        {
            IAddress[] cleanAddresses = allowedAddresses
                .Where(address => address != null)
                .GroupBy(address => address.ToString(), StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(MaxWhitelistedPlayers)
                .ToArray();

            if (cleanAddresses.Length > 0)
            {
                return cleanAddresses;
            }

            SingleIP localOnlyAddress;
            if (!SingleIP.TryParse(LocalOnlyFallbackAddress, out localOnlyAddress))
            {
                throw new InvalidOperationException("[BannerlordFirewall] Local fallback IP could not be parsed.");
            }

            return new IAddress[] { localOnlyAddress };
        }

        private static bool TryCreateFirewallAddress(string rawIpAddress, out IAddress firewallAddress, out string rejectReason)
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

            SingleIP parsedAddress;
            if (!SingleIP.TryParse(ipAddress.ToString(), out parsedAddress))
            {
                rejectReason = "firewall address parser rejected it";
                return false;
            }

            firewallAddress = parsedAddress;
            return true;
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

            this.WhitelistedIps = new ConcurrentDictionary<PlayerId, IAddress>();
            this.WhitelistedIpLastSeen = new ConcurrentDictionary<PlayerId, DateTime>();
            this.ActivePlayers = new ConcurrentDictionary<PlayerId, bool>();
            this.ActivePlayerSince = new ConcurrentDictionary<PlayerId, DateTime>();
            this.BlockedPlayers = new ConcurrentDictionary<string, DateTime>();
            this.BlockedIpAddresses = new ConcurrentDictionary<string, DateTime>();
            this.PendingTimeoutCounts = new ConcurrentDictionary<string, int>();
            this.FastDisconnectCounts = new ConcurrentDictionary<string, int>();
            this.IpChangeCounts = new ConcurrentDictionary<string, int>();
            this.LastPlayerIpAddress = new ConcurrentDictionary<string, string>();

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

            this.EnsureFirewallRule();
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
    }
}
