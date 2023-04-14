// Sniffer.cs
// Author: Samuel Stolarik
// Date: 2023-04-12
// Project: IPK project 2 - Packet Sniffer

namespace ipk_sniffer;

using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Text;
using System.Collections.Concurrent;
using System.Threading;

public class Sniffer
{
    private readonly PcapDevice _device; 
    private int _packetCounter;
    private readonly int _packetLimit; // Default limit if not changed in cli args
    private readonly BlockingCollection<RawCapture> _packetQueue;
    private readonly Thread _processingThread;

    
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
    /// Starts capturing packets on device
    /// then start PacketProcessing thread and waits for the thread to be ended and joined back,
    /// meaning that correct number of packets was handled.
    /// After that, capturing is stopped
    public void CapturePackets()
    {
        _device.StartCapture();
        _processingThread.Start();
        _processingThread.Join();
        _device.StopCapture();
    }
    
    
    /// <summary>
    /// Set filter for PacketSniffer
    /// </summary>
    /// <param name="arguments"></param>
    public void Filter(Options arguments)
    {
        // Set filter on device
        _device.Filter = CreateFilter(arguments);
    }


    /// <summary>
    /// Create a whole filter from the specified arguments
    /// </summary>
    /// <param name="arguments"></param>
    /// <returns></returns>
    private static string CreateFilter(Options arguments)
    {
        StringBuilder filterBuilder = new StringBuilder();
        if (arguments.Tcp) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Tcp, arguments.Port));
        if (arguments.Udp) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Udp, arguments.Port));
        if (arguments.Icmp4) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Icmp4));
        if (arguments.Icmp6) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Icmp6));
        if (arguments.Arp) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Arp));
        if (arguments.Ndp) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Ndp));
        if (arguments.Igmp) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Igmp));
        if (arguments.Mld) AddToFilterUsingOr(filterBuilder, CreateFilterPart(FilterType.Mld));
        
        return filterBuilder.ToString();
    }
    
    
    /// <summary>
    /// Add new filter using OR operator
    /// </summary>
    /// <param name="filterBuilder"></param>
    /// <param name="newFilter"></param>
    /// <returns></returns>
    private static void AddToFilterUsingOr(StringBuilder filterBuilder, string newFilter)
    {
        if (filterBuilder.Length == 0)
        {
            filterBuilder.Append(newFilter);
        }

        else
        {
            filterBuilder.Append(" or ");
            filterBuilder.Append(newFilter);
        }
    }
    
    
    /// <summary>
    /// Create a correct filter for a specified protocol type
    /// </summary>
    /// <param name="typeName"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private static string CreateFilterPart(FilterType typeName, int port = -1)
    {
        var filterString = "";
        switch (typeName)
        {
            // UDP
            case FilterType.Udp:
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
            case FilterType.Tcp:
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
            case FilterType.Icmp4:
                filterString = "( icmp )";
                break;
            
            // ICMP6
            case FilterType.Icmp6:
                filterString = "( icmp6 )";
                break;
            
            //ARP
            case FilterType.Arp:
                filterString = "( arp )";
                break;
            
            // ICMPv6 NDP
            case FilterType.Ndp:
                filterString =
                    "( icmp6[icmp6type] = icmp6-neighborsolicit or icmp6[icmp6type] = icmp6-routersolicit or icmp6[icmp6type] = icmp6-routeradvert or icmp6[icmp6type] = icmp6-neighboradvert or icmp6[icmp6type] = icmp6-redirect )";
                break;
            
            // IGMP
            case FilterType.Igmp:
                filterString = "( igmp )";
                break;
            
            // MLD
            case FilterType.Mld:
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
            Console.WriteLine(dev.Name);
        }
    }
    
    
    /// <summary>
    /// Get device with name specified by device name
    /// </summary>
    /// <param name="deviceName"></param>
    /// <returns></returns>
    /// <exception cref="ArithmeticException"></exception>
    /// <exception cref="ArgumentException"></exception>
    private static PcapDevice GetDevice(string? deviceName)
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

        throw new ArgumentException("Device: " + deviceName +" does not exist" );
    }

    
    /// <summary>
    /// Process packet as required
    /// </summary>
    /// <param name="packet"></param>
    private void ProcessPacket(RawCapture packet)
    {
        Console.WriteLine(PacketParser.ParsePacket(packet));
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
        Tcp,
        Udp,
        Icmp4,
        Icmp6,
        Arp,
        Ndp,
        Igmp,
        Mld
    }
}