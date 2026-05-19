using Messages.FromCustomBattleServerManager.ToCustomBattleServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TaleWorlds.Library;
using TaleWorlds.MountAndBlade.Diamond;
using WindowsFirewallHelper.Addresses;

namespace BannerlordFirewall.PatchedCode
{
    public class PatchCustomBattleServer
    {
        public static bool PrefixOnClientWantsToConnectCustomGameMessage(ClientWantsToConnectCustomGameMessage message)
        {
            if (BannerlordFirewall.Instance.GetFirewallRule() == null) return true;

            // 1. Oyuncu verilerini güvenli bir şekilde listeye ekliyoruz
            foreach (PlayerJoinGameData playerData in message.PlayerJoinGameData)
            {
                // IP boşsa veya 0.0.0.0 ise atla (Firewall'un herkesi engellemesini veya izin vermesini önler)
                if (string.IsNullOrEmpty(playerData.IpAddress) || playerData.IpAddress == "0.0.0.0") continue;

                // Parse hatası alıp çökmemesi için TryParse kullanıyoruz
                if (SingleIP.TryParse(playerData.IpAddress, out SingleIP firewallIp))
                {
                    BannerlordFirewall.Instance.WhitelistedIps[playerData.PlayerId] = firewallIp;
                    Debug.Print("[BannerlordFirewall] " + playerData.IpAddress + " added to whitelisted ip address", 0, Debug.DebugColor.Green);
                }
            }

            // 2. BURASI KRİTİK NOKTA: Windows Firewall kuralını kilit (lock) altında güncelliyoruz
            lock (BannerlordFirewall.FirewallLock)
            {
                BannerlordFirewall.Instance.GetFirewallRule().RemoteAddresses = BannerlordFirewall.Instance.WhitelistedIps.Values.ToArray();
            }

            return true;
        }
    }
}
