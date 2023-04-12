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
}