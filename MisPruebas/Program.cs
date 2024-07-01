using NetworkScannerLib;
using System.Net.NetworkInformation;

class Program
{
    public static void Main(string[] args)
    {
        NetworkScanner ns = NetworkScanner.Instance;
        var interfaces = ns.NetworkInterfaces;
        for (int i = 0; i < interfaces.Count; ++i)
        {
            var ifc = interfaces[i];
            Console.WriteLine($"Interfaz [{i}]");
            Console.WriteLine("Nombre: " + ifc.Name);
         //   Console.WriteLine("Descripción: " + ifc.Description);
         //   Console.WriteLine("Tipo: " + ifc.NetworkInterfaceType);
        //    Console.WriteLine("Estado: " + ifc.OperationalStatus);
         //   Console.WriteLine("ID: " + ifc.Id);
            // Obtener las direcciones IP asociadas a esta interfaz
            foreach (UnicastIPAddressInformation ip in ifc.GetIPProperties().UnicastAddresses)
            {
                Console.WriteLine("   IP: " + ip.Address);
            }
            Console.WriteLine("===============================");
        }
        Console.WriteLine("Selecciona número");
        int op = int.Parse(Console.ReadLine());
        var targetInterface = interfaces[op];
        Console.WriteLine($"Seleccionado: {targetInterface.Name}");
        Guid ifcId = ns.RegisterInterface(targetInterface);
        ns.StartSniffingOnInterface(ifcId);
        Console.WriteLine("Husmeando la red durante 10s");
        Thread.Sleep(10000); //10 s
        ns.StopSniffingOnInterface(ifcId);
        Console.WriteLine("Fin del husmeanamiento. Vamos a ver los resultados");

        var results = ns.GetResultsForInterfaces(ifcId);
        foreach (var p in results)
        {

            Console.WriteLine(p.ToString());
        }
        Console.WriteLine("Fin del programa");
    }
}