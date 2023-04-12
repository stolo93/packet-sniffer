// Sniffer.cs
// Author: Samuel Stolarik
// Date: 2023-04-12
// Project: IPK project 2 - Packet Sniffer
namespace ipk_sniffer;

using SharpPcap.LibPcap;
using System.Collections.Concurrent;
using System.Threading;

using SharpPcap;

public class Sniffer
{
    private PcapDevice _device; 
    private int _packetCounter;
    private int _packetLimit; // Default limit if not changed in cli args
    private BlockingCollection<RawCapture> _packetQueue;
    private Thread _processingThread;

    
    /// <summary>
    /// Create a Sniffer object
    /// </summary>
    /// <param name="arguments"></param>
    public Sniffer(Options arguments)
    {
        _device = GetDevice(arguments.Interface);
        _packetCounter = 0;
        _packetLimit = arguments.PacketLimit;
        _packetQueue = new BlockingCollection<RawCapture>();
        _processingThread = new Thread(this.ProcessingThreadFunction);
    }


    /// <summary>
    /// Initialize packet sniffer
    /// </summary>
    public void Initialize()
    {
        _device.Open((DeviceModes.Promiscuous));
        _device.OnPacketArrival += (sender, capture) =>
        {
            _packetQueue.Add(capture.GetPacket());
        };
    }


    /// <summary>
    /// Capture packets and process them in a separate thread
    /// </summary>
    public void CapturePackets()
    {
        _device.StartCapture();
        _processingThread.Start();
        _processingThread.Join();
        _device.StopCapture();
    }
    
    
    public void Filter(Options arguments)
    {
        string filter = "";
        if (arguments.Tcp)
        {
            var newFilter = CreateFilter(FilterType.TCP, arguments.Port);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Udp)
        {
            var newFilter = CreateFilter(FilterType.UDP, arguments.Port);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Icmp4)
        {
            var newFilter = CreateFilter(FilterType.ICMP4);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Icmp6)
        {
            var newFilter = CreateFilter(FilterType.ICMP6);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Arp)
        {
            var newFilter = CreateFilter(FilterType.ARP);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Ndp)
        {
            var newFilter = CreateFilter(FilterType.NDP);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Igmp)
        {
            var newFilter = CreateFilter(FilterType.IGMP);
            filter = AddToFilterUsingOr(filter, newFilter);
        }

        if (arguments.Mld)
        {
            var newFilter = CreateFilter(FilterType.MLD);
            filter = AddToFilterUsingOr(filter, newFilter);
        }
        Console.WriteLine(filter);
        // Set filter on device
        _device.Filter = filter;
    }


    /// <summary>
    /// Add new filter using OR operator
    /// </summary>
    /// <param name="filter"></param>
    /// <param name="new_filter"></param>
    /// <returns></returns>
    private string AddToFilterUsingOr(string filter, string new_filter)
    {
        if (filter == "")
        {
            return new_filter;
        }

        else
        {
            return filter + " or " + new_filter;
        }
    }
    
    
    /// <summary>
    /// Create a correct filter for a specified protocol type
    /// </summary>
    /// <param name="type_name"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private string CreateFilter(FilterType typeName, int port = -1)
    {
        var filterString = "";
        switch (typeName)
        {
            // UDP
            case FilterType.UDP:
                if (port != -1)
                {
                    filterString = "( udp port " + port.ToString() + " )";
                }
                else
                {
                    filterString = "( udp )";
                }
                break;
            
            // TCP
            case FilterType.TCP:
                if (port != -1)
                {
                    filterString = "( tcp port " + port.ToString() + " )";
                }
                else
                {
                    filterString = "( tcp )";
                }
                break;
            
            // ICMP4
            case FilterType.ICMP4:
                filterString = "( icmp )";
                break;
            
            // ICMP6
            case FilterType.ICMP6:
                filterString = "( icmp6 )";
                break;
            
            //ARP
            case FilterType.ARP:
                filterString = "( arp )";
                break;
            
            // ICMPv6 NDP
            case FilterType.NDP:
                filterString =
                    "( icmp6[icmp6type] = icmp6-neighborsolicit or icmp6[icmp6type] = icmp6-routersolicit or icmp6[icmp6type] = icmp6-routeradvert or icmp6[icmp6type] = icmp6-neighboradvert or icmp6[icmp6type] = icmp6-redirect )";
                break;
            
            // IGMP
            case FilterType.IGMP:
                filterString = "( igmp )";
                break;
            
            // MLD
            case FilterType.MLD:
                filterString =
                    "( icmp6[icmp6type] = icmp6-multicastlistenerquery or icmp6[icmp6type] = icmp6-multicastlistenerreportv1 or icmp6[icmp6type] = icmp6-multicastlistenerreportv2 or icmp6[icmp6type] = icmp6-multicastlistenerdone )";
                break;
        }

        return filterString;
    }
    
    
    /// <summary>
    /// List all available devices 
    /// </summary>
    public static void PrintDevices()
    {
        var devices = LibPcapLiveDeviceList.Instance;
        foreach (var dev in devices)
        {
            Console.WriteLine(dev.ToString());
        }
    }
    
    
    /// <summary>
    /// Get device with name specified by device name
    /// </summary>
    /// <param name="deviceName"></param>
    /// <returns></returns>
    /// <exception cref="ArithmeticException"></exception>
    /// <exception cref="ArgumentException"></exception>
    private static PcapDevice GetDevice(string deviceName)
    {
        var devices = LibPcapLiveDeviceList.Instance;
        if (devices.Count <= 0)
        {
            throw new ArithmeticException("No devices found");
        }

        foreach (var dev in devices)
        {
            if (dev.Name == deviceName)
            {
                return dev;
            }
        }

        throw new ArgumentException("{0} device not found", deviceName);
    }

    
    /// <summary>
    /// Process packet as required
    /// </summary>
    /// <param name="packet"></param>
    private void ProcessPacket(RawCapture packet)
    {
        Console.WriteLine(packet.GetPacket().ToString());
    }
    
    
    /// <summary>
    /// Thread function for packet processing
    /// </summary>
    private void ProcessingThreadFunction()
    {
        while (!_packetQueue.IsCompleted && _packetCounter < _packetLimit)
        {
            try
            {
                RawCapture packet = _packetQueue.Take();
                ProcessPacket(packet);
                _packetCounter++;
            }
            catch (InvalidOperationException)
            {
                break;
            }
        }
    }


    private enum FilterType
    {
        TCP,
        UDP,
        ICMP4,
        ICMP6,
        ARP,
        NDP,
        IGMP,
        MLD
    }
}