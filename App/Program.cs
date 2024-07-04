using NetworkScannerLib;
using System.Net.NetworkInformation;


NetworkScanner ns = NetworkScanner.Instance;
var interfaces = ns.NetworkInterfaces;

Console.WriteLine("╔══════════════════════════════════════════════════╗");
Console.WriteLine("║            Lista de Interfaces de Red            ║");
Console.WriteLine("╚══════════════════════════════════════════════════╝\n");

for (int i = 0; i < interfaces.Count; ++i)
{
    var ifc = interfaces[i];
    Console.WriteLine($"Interfaz [{i}]: {ifc.Name}");

    foreach (UnicastIPAddressInformation ip in ifc.GetIPProperties().UnicastAddresses)
    {
        Console.WriteLine($"   - IP: {ip.Address}");
    }
    Console.WriteLine("------------------------------------------------------");
}

Console.Write("\nSelecciona el número de interfaz: ");
int op = int.Parse(Console.ReadLine());

var targetInterface = interfaces[op];

Console.WriteLine($"\nSeleccionado: {targetInterface.Name}");
Guid ifcId = ns.RegisterInterface(targetInterface);

Console.WriteLine("Para terminar precione cualquier tecla");
ns.StartSniffingOnInterface(ifcId);
Console.Read();
ns.StopSniffingOnInterface(ifcId);


Console.WriteLine("╔══════════════════════════════════════════════════╗");
Console.WriteLine("║              Mostrando resultados                ║");
Console.WriteLine("╚══════════════════════════════════════════════════╝\n");

var results = ns.GetResultsForInterfaces(ifcId);
Console.WriteLine("Capturados {0} datagramas", results.Count);
foreach (var p in results)
{
    Console.WriteLine(p.ToString());
}
Console.WriteLine("\nFin del programa");

ns.UnregisterInterface(ifcId);
