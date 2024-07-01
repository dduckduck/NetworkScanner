namespace NetworkScannerLibTests
{
    using NetworkScannerLib;
    public class NetworkScannerTest
    {
        private NetworkScanner networkScanner;
        private readonly string ipTestValue = "192.168.1.137";
        private readonly string cidrTestValue = "192.168.1.0/24";

        public NetworkScannerTest()
        {
            networkScanner = new NetworkScanner(ipTestValue,cidrTestValue);
        }

        [Fact]
        public void ConvertStringToIpAddrTest()
        {
            uint expectedIp = 0xC0A80189;
            uint value = NetworkScanner.ConvertStringToIpAddr(ipTestValue);
            Assert.Equal(expectedIp, value);
            Assert.Throws<ArgumentException>(() => NetworkScanner.ConvertStringToIpAddr("A.B.a.123.1234fa"));
        
        }

        [Fact]
        public void ConvertIpAddrToString()
        {
            uint value = 0xC0A80189;
            string res = NetworkScanner.ConvertIpAddrToString(value);
            Assert.Equal(res, ipTestValue);

        }


        [Fact]
        public void ExtractSubneTest()
        {
            uint expectedValue = 0xC0A80100;
            uint value = NetworkScanner.ExtractSubnet(cidrTestValue);
            Assert.Equal(expectedValue, value);
            Assert.Throws<ArgumentException>(() => NetworkScanner.ExtractSubnet("A.B.a.123./123/addf"));

        }

        [Fact]
        public void ExtractSubnetMaskTest()
        {
            uint expectedValue = 0xFFFFFF00;
            uint value = NetworkScanner.ExtractSubnetMask(cidrTestValue);
            Assert.Equal(expectedValue, value);
            Assert.Throws<ArgumentException>(() => NetworkScanner.ExtractSubnetMask("A.B.a.123./123/addf"));

        }


        [Fact]
        public void SubnetContainsIpTest()
        {
            uint subnet = 0xC0A80100;
            uint mask = 0xFFFFFF00;
            uint ip = 0xC0A80189;

            bool expectedValue = true;
            bool value = NetworkScanner.SubnetContainsIp(ip,subnet,mask);
            Assert.Equal(expectedValue, value);
        }



        [Fact]
        public void StateTest()
        {
            uint expectedIP = 0xC0A80189;
            uint expectedSubnet = 0xC0A80100;
            uint expectedMask = 0xFFFFFF00;


            Assert.Equal(expectedIP, networkScanner.IpAddr);
            Assert.Equal(expectedSubnet, networkScanner.SubnetAddr);
            Assert.Equal(expectedMask, networkScanner.SubnetMask);

        }
    }
}