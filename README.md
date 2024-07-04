# Ejemplo de sniffer en c#
Este proyecto es un sniffer sencillo para la plataforma Windows escrito en C# que utiliza únicamente la funcionalidad nativa de .NET

---

# Descripción

Este proyecto en C# demuestra cómo capturar y analizar paquetes de red de manera básica. Incluye funcionalidades como listar interfaces de red, seleccionar una interfaz para monitorear y mostrar los resultados de los paquetes capturados.

**Nota importante:** Este repositorio es un mero ejemplo y no deja de ser un proyecto hobby personal que he decidio publicar mientras ampliaba mis conocimientos sobre redes. No debe considerarse como una librería funcional completa.
Para proyectos más serios y completos, recomendaría revisar [SharpPcap](https://github.com/dotpcap/sharppcap).

**Conceptos clave para explorar más a fondo:**
- Sockets: Fundamentales para la comunicación de red a bajo nivel.
- Protocolos: IP, ARP, DHCP, DNS, TCP, UDP: Esenciales para entender cómo se estructuran y gestionan los datos en la red.
- Operaciones bitwise: Importantes para manipular y controlar datos binarios de manera eficiente.
- Paralelismo y sincronización: Métodos para gestionar la concurrencia y aliviar la carga entre diferentes hilos de ejecución, optimizando el rendimiento de aplicaciones de red.

---

# Requisitos
- .NET 8 SDK o superior
- Visual Studio 2022 o superior

---

# Funcionamiento
## Planteamiento teórico
Para interceptar los paquetes que atraviesen la red se utiliza un socket configurado en modo promisuco. Esto último es de especial interes pues es así como se evita el descarte del datagrama por parte del hardware si el MAC de destino no coincide con el MAC de la interfaz que actúa como sniffer

Una vez se intercepta el paquete, se procesan las cabeceras del paquete. La estructura de estas están recogidas en la sección 3.1 del RFC791. A partir de estas cabeceras se puede obtener el emisor y receptor, el protocolo utilizado y otros datos. 

## Planteamiento de diseño
```plaintext
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
```


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


