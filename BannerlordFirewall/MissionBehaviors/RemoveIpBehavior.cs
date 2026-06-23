using TaleWorlds.Library;
using TaleWorlds.MountAndBlade;

namespace BannerlordFirewall.MissionBehaviors
{
    public class RemoveIpBehavior : MissionNetwork
    {
        public override void OnBehaviorInitialize()
        {
            base.OnBehaviorInitialize();
            Debug.Print("[BannerlordFirewall] RemoveIpBehavior has been initialized.", 0, Debug.DebugColor.Purple);
        }

        public override void OnPlayerConnectedToServer(NetworkCommunicator networkPeer)
        {
            base.OnPlayerConnectedToServer(networkPeer);
            MarkPlayerInGame(networkPeer);
        }

        protected override void HandleNewClientAfterSynchronized(NetworkCommunicator networkPeer)
        {
            base.HandleNewClientAfterSynchronized(networkPeer);
            MarkPlayerInGame(networkPeer);
        }

        public override void OnPlayerDisconnectedFromServer(NetworkCommunicator networkPeer)
        {
            BannerlordFirewall firewall = BannerlordFirewall.Instance;
            if (firewall == null)
            {
                return;
            }

            if (networkPeer == null || networkPeer.PlayerConnectionInfo == null || networkPeer.PlayerConnectionInfo.PlayerID == null)
            {
                return;
            }

            firewall.RemoveWhitelistedPlayer(networkPeer.PlayerConnectionInfo.PlayerID, networkPeer.UserName);
        }

        private static void MarkPlayerInGame(NetworkCommunicator networkPeer)
        {
            BannerlordFirewall firewall = BannerlordFirewall.Instance;
            if (firewall == null)
            {
                return;
            }

            if (networkPeer == null || networkPeer.PlayerConnectionInfo == null || networkPeer.PlayerConnectionInfo.PlayerID == null)
            {
                return;
            }

            firewall.MarkPlayerInGame(networkPeer.PlayerConnectionInfo.PlayerID, networkPeer.UserName);
        }
    }
}
