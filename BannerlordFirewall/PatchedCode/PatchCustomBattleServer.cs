using Messages.FromCustomBattleServerManager.ToCustomBattleServer;
using TaleWorlds.Library;
using TaleWorlds.MountAndBlade.Diamond;

namespace BannerlordFirewall.PatchedCode
{
    public class PatchCustomBattleServer
    {
        public static bool PrefixOnClientWantsToConnectCustomGameMessage(ClientWantsToConnectCustomGameMessage message)
        {
            BannerlordFirewall firewall = BannerlordFirewall.Instance;
            if (firewall == null || !firewall.IsNativeFilterAvailable())
            {
                return true;
            }

            if (message == null || message.PlayerJoinGameData == null)
            {
                Debug.Print("[BannerlordFirewall] Empty join message received; firewall whitelist was not changed.", 0, Debug.DebugColor.DarkYellow);
                return true;
            }

            int addedCount = 0;
            int processedCount = 0;
            foreach (PlayerJoinGameData playerData in message.PlayerJoinGameData)
            {
                if (processedCount >= BannerlordFirewall.MaxPlayersPerJoinMessage)
                {
                    Debug.Print("[BannerlordFirewall] Join message exceeded safe player limit; remaining entries were ignored.", 0, Debug.DebugColor.Red);
                    break;
                }

                processedCount++;
                if (firewall.TryWhitelistPlayerIp(playerData.PlayerId, playerData.IpAddress, false))
                {
                    addedCount++;
                }
            }

            if (addedCount > 0)
            {
                firewall.RefreshFirewallWhitelist();
            }

            return true;
        }
    }
}
