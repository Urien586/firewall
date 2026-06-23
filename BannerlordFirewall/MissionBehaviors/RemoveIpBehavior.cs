using TaleWorlds.Library;
using TaleWorlds.MountAndBlade;

namespace BannerlordFirewall.MissionBehaviors
{
    public class RemoveIpBehavior : MissionNetwork
    {
        private float _firewallRefreshTimer;

        public override void OnBehaviorInitialize()
        {
            base.OnBehaviorInitialize();
            Debug.Print("[BannerlordFirewall] RemoveIpBehavior has been initialized.", 0, Debug.DebugColor.Purple);
        }

        public override void OnMissionTick(float dt)
        {
            base.OnMissionTick(dt);
            this._firewallRefreshTimer += dt;
            if (this._firewallRefreshTimer < 5f)
            {
                return;
            }

            this._firewallRefreshTimer = 0f;

            BannerlordFirewall firewall = BannerlordFirewall.Instance;
            if (firewall != null)
            {
                firewall.RefreshFirewallWhitelist();
            }
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
