using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetworkScannerLib
{
    public class NetworkScanner
    {
        private Dictionary<Guid, Sniffer> registeredSniffers;
        private Dictionary<Guid, Sniffer> activeSniffers;

        private static readonly NetworkScanner instance = new NetworkScanner();
        private NetworkScanner() { registeredSniffers = new Dictionary<Guid, Sniffer>(); activeSniffers = new Dictionary<Guid, Sniffer>(); }
        public static NetworkScanner Instance { get { return instance; } }

        public List<NetworkInterface> NetworkInterfaces
        {
            get
            {
                return new List<NetworkInterface>(NetworkInterface.GetAllNetworkInterfaces());
            }
        }
        public Guid RegisterInterface(NetworkInterface ifc)
        {

            if (!(ifc != null && IsIpv4(ref ifc)))
            {
                throw new ArgumentException("Given interface does not contain a valid ipv4 address");
            }
            Guid ifcId = Guid.NewGuid();
            if (registeredSniffers.ContainsKey(ifcId))
            {
                throw new InvalidOperationException("Wow! Almost imposible collision ocurred. New randomly generated uid is already registered");
            }

            var data = ExtractAddresses(ref ifc); //IP, Subnet, Mask
            if ((data[0] & data[1] & data[2]) == 0)
            {
                throw new ArgumentException("Could not obtain a valid ip addresses");
            }

            Sniffer sniffer = new Sniffer(data[0], data[1], data[2]);
            registeredSniffers[ifcId] = sniffer;
            return ifcId;
        }

        public void UnregisterInterface(Guid ifcId)
        {
            if (this.registeredSniffers.ContainsKey(ifcId))
            {
                this.registeredSniffers[ifcId].StopSniffing();
                this.registeredSniffers.Remove(ifcId);
            }
            else
            {
                throw new ArgumentException("Cannot unregister not registered interface");
            }
        }
        private uint[] ExtractAddresses(ref NetworkInterface ifc)
        {
            uint[] data = [0, 0, 0];
            foreach (UnicastIPAddressInformation ipInfo in ifc.GetIPProperties().UnicastAddresses)
            {
                if (ipInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    uint ipaddr = BitConverter.ToUInt32(ipInfo.Address.GetAddressBytes(), 0);
                    uint mask = BitConverter.ToUInt32(ipInfo.IPv4Mask.GetAddressBytes(), 0);
                    uint subnet = ipaddr & mask;
                    data[0] = ipaddr;
                    data[1] = subnet;
                    data[2] = mask;
                }
            }

            return data;

        }

        private bool IsIpv4(ref NetworkInterface ifc)
        {
            bool res = false;
            foreach (UnicastIPAddressInformation ipInfo in ifc.GetIPProperties().UnicastAddresses)
            {
                if (ipInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    res = true;
                    break;
                }
            }
            return res;
        }

        public void StartSniffingOnInterface(Guid ifcId)
        {
            if (!this.registeredSniffers.ContainsKey(ifcId))
            {
                throw new ArgumentException($"Cannot sniff on an unregister interface {ifcId}");

            }

            if (this.activeSniffers.ContainsKey(ifcId))
            {
                throw new ArgumentException($"This sniffer is already in use {ifcId}");

            }
            var sniffer = this.registeredSniffers[ifcId];
            this.activeSniffers[ifcId] = sniffer;
            sniffer.StartSniffing();
        }


        public void StopSniffingOnInterface(Guid ifcId)
        {
            if (this.registeredSniffers.ContainsKey(ifcId))
            {
                var sniffer = this.registeredSniffers[ifcId];
                sniffer.StopSniffing();
            }
            else
            {
                throw new ArgumentException("Cannot stop sniffing on an unregister interface");
            }
        }

        public List<IPPacket> GetResultsForInterfaces(Guid ifcId)
        {
            List<IPPacket> packets = new List<IPPacket>();
            if (this.registeredSniffers.ContainsKey(ifcId))
            {
                packets = this.registeredSniffers[ifcId].CapturedData;
            }

            return packets;
        }

        ~NetworkScanner()
        {
            if (this.activeSniffers.Keys.Count != 0)
            {
                foreach (var sniffer in this.activeSniffers)
                {

                    sniffer.Value.StopSniffing();

                }

            }
        }
    }
}
