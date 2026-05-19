using BannerlordFirewall.MissionBehaviors;
using BannerlordFirewall.PatchedCode;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TaleWorlds.Library;
using TaleWorlds.MountAndBlade;
using TaleWorlds.MountAndBlade.Diamond;
using TaleWorlds.PlayerServices;
using WindowsFirewallHelper;

namespace BannerlordFirewall
{
    public class BannerlordFirewall : MBSubModuleBase
    {
        public static BannerlordFirewall Instance;

        // Thread çakışmalarını önlemek için merkezi kilit nesnesi
        public static readonly object FirewallLock = new object();

        // Güvenli sözlük yapısı (Thread-safe)
        public ConcurrentDictionary<PlayerId, IAddress> WhitelistedIps;

        // --- HATA VEREN DEĞİŞKENİ BURAYA EKLE ---
        public HarmonyLib.Harmony HarmonyHandle;
        // ----------------------------------------

        private IFirewallRule _cachedFirewallRule;

        public string GetFirewallRuleName()
        {
            int port = Module.CurrentModule.StartupInfo.ServerPort;
            return "Bannerlord Firewall " + port.ToString();
        }

        public IFirewallRule GetFirewallRule()
        {
            if (this._cachedFirewallRule == null)
            {
                this._cachedFirewallRule = FirewallManager.Instance.Rules.SingleOrDefault(r => r.Name == this.GetFirewallRuleName());
            }
            return this._cachedFirewallRule;
        }

        public void CreateFirewallRule()
        {
            this._cachedFirewallRule = FirewallManager.Instance.CreatePortRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                this.GetFirewallRuleName(),
                FirewallAction.Allow,
                Convert.ToUInt16(Module.CurrentModule.StartupInfo.ServerPort),
                FirewallProtocol.UDP
            );
            FirewallManager.Instance.Rules.Add(this._cachedFirewallRule);
        }

        protected override void OnSubModuleLoad()
        {
            base.OnSubModuleLoad();
            Instance = this;

            // Sözlüğü asenkron yapıya uygun başlatıyoruz
            this.WhitelistedIps = new ConcurrentDictionary<PlayerId, IAddress>();

            this.HarmonyHandle = new HarmonyLib.Harmony("mentalrob.bannerlordfirewall.bannerlord");
            var original = typeof(CustomBattleServer).GetMethod("OnClientWantsToConnectCustomGameMessage", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var prefix = typeof(PatchCustomBattleServer).GetMethod("PrefixOnClientWantsToConnectCustomGameMessage", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            this.HarmonyHandle.Patch(original, prefix: new HarmonyLib.HarmonyMethod(prefix));

            if (this.GetFirewallRule() == null)
            {
                Debug.Print("[BannerlordFirewall] FirewallRule " + this.GetFirewallRuleName() + " not found on your server. Creating...", 0, Debug.DebugColor.Red);
                this.CreateFirewallRule();
            }
        }

        public override void OnBeforeMissionBehaviorInitialize(Mission mission)
        {
            Debug.Print("[BannerlordFirewall] Trying to add RemoveIpBehavior...", 0, Debug.DebugColor.DarkYellow);
            mission.AddMissionBehavior(new RemoveIpBehavior());
        }
    }
}