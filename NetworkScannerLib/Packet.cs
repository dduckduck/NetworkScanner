using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkScannerLib
{
     public class IPPacket
    {

        public byte Version { get; private set; } //4 bits: IPV4 o IPV6
        public byte IHL { get; private set; } //4 bits longitud del header. Ej: 5*4=20
        public byte TypeOfService { get; private set; } //8 bits
        public ushort TotalLength { get; private set; } //16 bits
        public ushort Identification { get; private set; } //16 bits
        public byte Flags { get; private set; } // 3 bits
        public ushort FragmentOffset { get; private set; } //13 bits: 
        public byte TTL { get; private set; } //8 bits
        public byte Protocol { get; private set; } //8 bits
        public ushort HeaderChecksum { get; private set; } //16 bits
        public uint SourceAddress { get; private set; } //32 bits
        public uint DestinationAddress { get; private set; }//32 bits

        public IPPacket(byte[] data)
        {
            if (data.Length < 20)
            {
                throw new ArgumentException("Not a valid header");
            }

            //1. Version + IHL: 8 bits
            Version = (byte)(data[0] >> 4 & 0x0F); //4 bits más significativos    0100 0101 >> 4 = 0000 0100 y aplico máscara para aislar los 4 bits menos significativs
            IHL = (byte)(data[0] & 0x0F);  //4 bits menos significativos   0100 0101 & 0000 1111 = 0000 0101
            
            //2. ToS: 8 bits
            TypeOfService = data[1];

            //3. Longitud 16 bits (2 bytes)
            TotalLength = (ushort)(data[2]<<8 | data[3]); //   [0100 0101] << 8 = 0100 0101 0000 0000  OR 0100 0101 = 0100 0101 0101 0101

            //4. Identificacion 16 bits (2 bytes)
            Identification = (ushort)(data[4] << 8 | data[5]);

            //5. Flags 3 bits
            Flags = (byte)(data[6]>>5 & 0x07); // 0100 0101 >> 5 =  0000 0010 & 0x07

            //6. FragmentOffset 13 bits
            FragmentOffset = (ushort)( (data[6] << 3)<<8 | data[7]);

            //7. TTL 8 bits
            TTL = data[8];

            //7. Protocolo 8 bits
            Protocol = data[9];

            //8. ChekcSum 16 bits
            HeaderChecksum = (ushort)(data[10] << 8 | data[11]);

            //9. SourceAddress 32 bits
            SourceAddress = (uint)(data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15]);

            //10. DestinationAddress 32 bits
            DestinationAddress = (uint)(data[16] << 24 | data[17] << 16 | data[18] << 8 | data[19]);
        }

        public override string ToString()
        {
            // Convertir SourceAddress a formato IP legible
            string sourceIP = $"{(SourceAddress >> 24) & 0xFF}.{(SourceAddress >> 16) & 0xFF}.{(SourceAddress >> 8) & 0xFF}.{SourceAddress & 0xFF}";

            // Convertir DestinationAddress a formato IP legible
            string destinationIP = $"{(DestinationAddress >> 24) & 0xFF}.{(DestinationAddress >> 16) & 0xFF}.{(DestinationAddress >> 8) & 0xFF}.{DestinationAddress & 0xFF}";
            const int fieldWidth = -20;
            const int valueWidth = -20;

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("IP Packet Information:");
            sb.AppendLine("-------------------------------------------------");
            sb.AppendLine($"| {"Field",fieldWidth} | {"Value",valueWidth} |");
            sb.AppendLine("-------------------------------------------------");
            sb.AppendLine($"| {"Version",fieldWidth} | {Version,valueWidth} |");
            sb.AppendLine($"| {"IHL",fieldWidth} | {IHL,valueWidth} |");
            sb.AppendLine($"| {"Type of Service",fieldWidth} | {TypeOfService,valueWidth} |");
            sb.AppendLine($"| {"Total Length",fieldWidth} | {TotalLength,valueWidth} |");
            sb.AppendLine($"| {"Identification",fieldWidth} | {Identification,valueWidth} |");
            sb.AppendLine($"| {"Flags",fieldWidth} | {Flags,valueWidth} |");
            sb.AppendLine($"| {"Fragment Offset",fieldWidth} | {FragmentOffset,valueWidth} |");
            sb.AppendLine($"| {"TTL",fieldWidth} | {TTL,valueWidth} |");
            sb.AppendLine($"| {"Protocol",fieldWidth} | {Protocol,valueWidth} |");
            sb.AppendLine($"| {"Header Checksum",fieldWidth} | {HeaderChecksum,valueWidth} |");
            sb.AppendLine($"| {"Source Address",fieldWidth} | {sourceIP,valueWidth} |");
            sb.AppendLine($"| {"Destination Address",fieldWidth} | {destinationIP,valueWidth} |");
            sb.AppendLine("-------------------------------------------------");

            return sb.ToString();
        }



    }
}
