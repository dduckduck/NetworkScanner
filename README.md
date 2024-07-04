# Ejemplo de sniffer en c#
Este proyecto es un sniffer sencillo escrito en C# que utiliza únicamente la funcionalidad nativa de .NET. 

# Descripción
Este proyecto demuestra cómo capturar y analizar paquetes de red utilizando C#.
Incluye la capacidad de listar interfaces de red, seleccionar una interfaz para monitorear, y mostrar los resultados de los paquetes capturados.

# Funcionamiento
## Planteamiento teórico
Para interceptar los paquetes que atraviesen la red se utiliza un socket configurado en modo promisuco. Esto se 
Esto último es de especial interes pues es así como se evita el descarte del datagrama por parte del hardware si el mac de destino no coincide con el mac de la interfaz que actúa como sniffer

Una vez se intercepta el paquete, se procesan las cabeceras del paquete. La estructura de estas están recogidas en la sección 3.1 del RFC791.
A partir de estas cabeceras se puede obtener el emisor y receptor, el protocolo utilizado y otros datos. 

## Planteamiento de diseño
                    +----------------+
                    | NetworkScanner |
                    +----------------+
                            |
                            |
              +-------------+-------------+
              |                           |
      +--------------+           +--------------+
      |   Sniffer    |           |   Sniffer    |
      +--------------+           +--------------+
     /       |       \                   |
    /        |        \                  |
   /         |         \                 |
+----------+ +----------+         +------------+
| IPPacket | | IPPacket |         |  IPPacket  |
+----------+ +----------+         +------------+


La entidad NetworkScanner gestiona las interfaces para la monitorización. Cada interfaz está asociada a un Sniffer, el cual captura paquetes en un hilo dedicado. 
De esta manera, NetworkScanner puede realizar sniffing simultáneamente en varias interfaces.


# Ejemplo
```c#
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

```


