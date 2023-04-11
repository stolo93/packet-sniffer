// Program.cs
// Author: Samuel Stolarik
// Date: 2023-04-11


using System;
using System.Collections.Concurrent;
using System.Threading;
using SharpPcap;
using SharpPcap.LibPcap;

class Program
{
    private static void Main(string[] args)
    {
        var devices = LibPcapLiveDeviceList.Instance;
        if (devices.Count <= 0)
        {
            Console.WriteLine("No devices found");
            return;
        }

        var device = GetPcapDevice(devices);
        var packetLimit = GetPacketLimit();
        
        // Create packetQueue, open device for capturing and register event handler
        var packetQueue = new BlockingCollection<RawCapture>();
        device.Open(DeviceModes.Promiscuous);
        device.OnPacketArrival += (sender, capture) =>
        {
            packetQueue.Add(capture.GetPacket());
        };
        
        // Start capture on device
        device.StartCapture();
        
        // Create thread for processing queued packets
        var processingThread = new Thread(() =>
        {
            int packetCounter = 0;
            while (!packetQueue.IsCompleted  && (!packetLimit.HasValue || packetCounter < packetLimit))
            {
                try
                {
                    RawCapture packet = packetQueue.Take();
                    ProcessPacket(packet);
                    packetCounter++;
                }
                catch (InvalidOperationException)
                {
                    break;
                }
            }
        });

        // Start processing and wait for the Processing thread to end, then stop capture on device
        processingThread.Start();
        processingThread.Join();
        device.StopCapture();
        
    }

    /// <summary>
    /// Get Packet Capture device
    /// </summary>
    /// <param name="devices"></param>
    /// <returns>PcapDevice</returns>
    private static PcapDevice GetPcapDevice(LibPcapLiveDeviceList devices)
    {
        int i = 0;
        foreach (var dev in devices)
        {
            Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
            i++;
        }
        Console.WriteLine();
        Console.Write("-- Please choose a device to capture: ");
        i = int.Parse(Console.ReadLine());
        return devices[i];
    }

    /// <summary>
    /// Process packet
    /// </summary>
    /// <param name="packet"></param>
    private static void ProcessPacket(RawCapture packet)
    {
        Console.WriteLine(packet.GetPacket().ToString());
    }

    private static int? GetPacketLimit()
    {
        return 10;
    }
}