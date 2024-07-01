namespace NetworkScannerLibTests
{
    using NetworkScannerLib;
    public class PacketTest
    {
        private IPPacket ipPacket;
        private readonly byte[] data = new byte[] { 0x45, 0x00, 0x00, 0x28, 0xC9, 0xE1, 0x40, 0x00, 0x80, 0x06, 0xA6, 0x37, 0xC0, 0xA8, 0x01, 0x89, 0x5F, 0x64, 0x69, 0x21, 0xC6, 0x46, 0x01, 0xBB, 0xE5, 0x29, 0x71, 0x27, 0x3E, 0xBD, 0x8E, 0xEF, 0x50, 0x10, 0x04, 0x02, 0x35, 0x1C, 0x00, 0x00 };

        public PacketTest()
        {

            ipPacket = new IPPacket(data);
        }


        [Fact]
        public void VersionTest()
        {
            byte expectedValue = 0x04;
            Assert.Equal(expectedValue, ipPacket.Version);
        }

        [Fact]
        public void IhlTest()
        {
            byte expectedValue = 0x05;
            Assert.Equal(expectedValue, ipPacket.IHL);
        }

        [Fact]
        public void TypeOfServiceTest()
        {
            byte expectedValue = 0x00;
            Assert.Equal(expectedValue, ipPacket.TypeOfService);
        }

        [Fact]
        public void TotalLengthTest()
        {
            ushort expectedValue = 0x0028;
            Assert.Equal(expectedValue, ipPacket.TotalLength);
        }



        [Fact]
        public void IdentificationTest()
        {
            ushort expectedValue = 0xC9E1;
            Assert.Equal(expectedValue, ipPacket.Identification);
        }

        [Fact]
        public void FlagsTest()
        {
            byte expectedValue = 0x02;
            Assert.Equal(expectedValue, ipPacket.Flags);
        }

        [Fact]
        public void FragmentOffset()
        {
            ushort expectedValue = 0x0000;
            Assert.Equal(expectedValue, ipPacket.FragmentOffset);
        }

        [Fact]
        public void TTLTest()
        {
            byte expectedValue = 0x80;
            Assert.Equal(expectedValue, ipPacket.TTL);
        }

        [Fact]
        public void ProtocolTest()
        {
            byte expectedValue = 0x06;
            Assert.Equal(expectedValue, ipPacket.Protocol);
        }


        [Fact]
        public void HeaderChecksumTest()
        {
            ushort expectedValue = 0xA637;
            Assert.Equal(expectedValue, ipPacket.HeaderChecksum);
        }

        [Fact]
        public void SourceAddressTest()
        {
            uint expectedValue = 0xC0A80189;
            Assert.Equal(expectedValue, ipPacket.SourceAddress);
        }


        [Fact]
        public void DestinationAddressTest()
        {
            uint expectedValue = 0x5F646921;
            Assert.Equal(expectedValue, ipPacket.DestinationAddress);
        }

    }
}