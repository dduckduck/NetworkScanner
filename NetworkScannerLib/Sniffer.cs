using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace NetworkScannerLib
{
    public class Sniffer
    {
        private readonly uint BUFFER_SIZE = 65507; //Max size
        public List<IPPacket> CapturedData { get; private set; }
        public Dictionary<uint, IPPacket> HostMap { get; private set; }

        //Configuración para la red
        private Socket rawSocket;
        public uint IpAddr { get; private set; }
        public uint SubnetAddr { get; private set; }
        public uint SubnetMask { get; private set; }


        private Thread snifferThread;
        private bool stopSniffing;
        private object lockObject;

        public Sniffer(uint ip, uint subnet, uint mask)
        {
            IpAddr = ip;
            SubnetMask = subnet;
            SubnetAddr = mask;
            CapturedData = new List<IPPacket>();
            HostMap = new Dictionary<uint, IPPacket>();
            //Socket
            byte[] inValue = [1, 0, 0, 0]; //Modo promiscuo
            byte[] outValue = new byte[4];

            rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            rawSocket.Bind(new IPEndPoint(new IPAddress(BitConverter.GetBytes(IpAddr)), 0));
            rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            rawSocket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);


            //configuración sniffer
            stopSniffing = false;
            lockObject = new object();
            snifferThread = new Thread(CaptureTraffic);
        }

        ~Sniffer()
        {
            Console.WriteLine("Captured datagrams {0}", CapturedData.Count);
            if (snifferThread.IsAlive)
            {
                lock (lockObject)
                {
                    stopSniffing = true;
                };
                snifferThread.Join();
            }
            rawSocket.Close();
        }

        private void CaptureTraffic()
        {
            byte[] buffer = new byte[BUFFER_SIZE];
            int received = -1;
            while (true)
            {
                lock (lockObject)
                {
                    if (stopSniffing)
                    {
                        break;
                    }
                }
                try
                {
                    received = rawSocket.Receive(buffer);
                }catch(Exception e)
                {
                    Console.WriteLine("Error ocurred while receiving datagram: {0}", e.Message);
                    received = -1;
                }

                if (received > 0)
                {
                    // Procesar el paquete recibido
                    IPPacket iPPacket = new IPPacket(buffer);
                    Console.WriteLine($"{ConvertIpAddrToString(iPPacket.SourceAddress)}  -> {ConvertIpAddrToString(iPPacket.DestinationAddress)}");
                    if (!HostMap.ContainsKey(iPPacket.SourceAddress))
                    {
                        HostMap[iPPacket.SourceAddress] = iPPacket;
                    }
                    CapturedData.Add(iPPacket);
                }
            }
        }


        public static string ConvertIpAddrToString(uint addr)
        {
            return $"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}";

        }

        public static uint ConvertStringToIpAddr(string ipAddr)
        {
            string[] parts = ipAddr.Split('.');

            if (parts.Length != 4)
            {
                throw new ArgumentException($"Invalid IP were given: {ipAddr}");
            }
            return (uint.Parse(parts[0]) << 24) |
                   (uint.Parse(parts[1]) << 16) |
                   (uint.Parse(parts[2]) << 8) |
                   uint.Parse(parts[3]);
        }

        public static uint ExtractSubnetMask(string ipWithPrefix)
        {
            var parts = ipWithPrefix.Split('/');
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid Cidr were given: {ipWithPrefix}");
            }
            int prefixLength = int.Parse(parts[1]);
            uint mask = (uint.MaxValue << (32 - prefixLength)) & uint.MaxValue;
            return mask;
        }

        public static uint ExtractSubnet(string ipWithPrefix)
        {
            var parts = ipWithPrefix.Split('/');
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid Cidr were given: {ipWithPrefix}");
            }
            string
                ip = parts[0];
            uint subnet = ConvertStringToIpAddr(ip);
            return subnet;
        }

        public static bool SubnetContainsIp(uint ip, uint subnet, uint mask)
        {
            return (ip & mask) == subnet;
        }

        public void StartSniffing()
        {
            if (snifferThread != null && !snifferThread.IsAlive)
            {
                snifferThread.Start();
            }
            else
            {
                throw new InvalidOperationException("The thread is already running and cannot be started again.");
            }
        }

        public void StopSniffing()
        {
            if (snifferThread != null && snifferThread.IsAlive)
            {
                lock (lockObject)
                {
                    stopSniffing = true;
                    Console.WriteLine("Snifer stop sniffing!");
                }
                Console.WriteLine("Waiting for sniffer thread to finish...");
                snifferThread.Join();
            }

        }
    }
}
