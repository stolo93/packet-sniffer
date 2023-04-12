// Program.cs
// Author: Samuel Stolarik
// Date: 2023-04-11


using System;
using System.Collections.Concurrent;
using System.Threading;
using SharpPcap;
using SharpPcap.LibPcap;
using CommandLine;

using ipk_sniffer;

class Program
{
    private static void Main(string[] args)
    {
        // Parse cli arguments
        Options parsedOptions = null;
        Parser.Default.ParseArguments<Options>(args)
            .WithParsed<Options>(options => parsedOptions = options)
            .WithNotParsed(errors => Options.HandleParseErrors(errors));

        if (parsedOptions.Interface == "")
        {
            Sniffer.PrintDevices();
            Environment.Exit(0);
        }

        var packetSniffer = new Sniffer(parsedOptions);
        packetSniffer.Initialize();
        packetSniffer.CapturePackets();

    }
}

public class Options
{
    // Interface
    [Option('i', "interface", Required = false, Default = "", HelpText = "Interface name to sniff")]
    public string Interface { get; set; }
    
    // Packet Limit
    [Option('n', Required = false, Default = 1, HelpText = "Number of packets to catch before ending the application")]
    public int PacketLimit { get; set; }

    // TCP
    [Option('t', "tcp", Required = false, Default = false, HelpText = "TCP protocol")]
    public bool Tcp { get; set; }
    
    // UDP
    [Option('u', "udp", Required = false, Default = false, HelpText = "UDP protocol")]
    public bool Udp { get; set; }
    
    // Port
    [Option('p', "port", Required = false, Default = -1, HelpText = "Specify the port for TCP/UDP")]
    public int Port { set; get; }
    
    // ICMPv4
    [Option(longName: "icmp4", Default = false, Required = false, HelpText = "Display only ICMPv4 packets")]
    public bool Icmp4 { set; get; }
    
    // ICMPv6
    [Option(longName: "icmp6", Required = false, Default = false, HelpText = "Display only ICMPv6 packets")]
    public bool Icmp6 { set; get; }
    
    // ARP
    [Option(longName: "arp", Required = false, Default = false, HelpText = "Display only ARP frames")]
    public bool Arp { set; get; }
    
    // NDP
    [Option(longName: "ndp", Required = false, Default = false, HelpText = "Display only ICMPv6 NDP packets")]
    public bool Ndp { set; get; }
    
    // IGMP
    [Option(longName: "igmp", Required = false, Default = false, HelpText = "Display only IGMP packets")]
    public bool Igmp { set; get; }
    
    // MLD
    [Option(longName: "mld", Required = false, Default = false, HelpText = "Display only MLD packets")]
    public bool Mld { set; get; }

    public static void HandleParseErrors(IEnumerable<Error> errors)
    {
        Console.WriteLine("Failed to parse command-line arguments");
        Environment.Exit(1);
    }
    
}
