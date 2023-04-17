// File: Program.cs
// Author: Samuel Stolarik
// Date: 2023-04-11
// Project: IPK project 2 - Packet Sniffer

namespace ipk_sniffer;

using CommandLine;
using System;

/// <summary>
/// Main program static class
/// </summary>
static class Program
{
    /// <summary>
    /// Main function
    /// </summary>
    /// <param name="args"></param>
    private static void Main(string[] args)
    {
        // If no arguments given, the application does nothing (successfully)
        if (args.Length == 0)
        {
            Environment.Exit(0);
        }
        
        // Parse cli arguments
        Options? parsedOptions = null;
        Parser.Default.ParseArguments<Options>(args)
            .WithParsed(options => parsedOptions = options)
            .WithNotParsed(errors => Options.HandleParseErrors());
        if (parsedOptions == null)
        {
            Console.WriteLine("Error: Could not parse arguments");
            Environment.Exit(2);
        }
        Options.CheckArguments(parsedOptions);
                
        if (parsedOptions is { Interface: "" })
        {
            Sniffer.PrintDevices();
            Environment.Exit(0);
        }

        try
        {
            var packetSniffer = new Sniffer(parsedOptions);
            packetSniffer.Initialize();
            packetSniffer.Filter(parsedOptions);
            packetSniffer.CapturePackets();
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            Environment.Exit(1);
        }
    }
}

/// <summary>
/// Argument parser class
/// </summary>
public class Options
{
    /// <summary>
    /// Interface
    /// </summary>
    [Option('i', "interface", Required = false, Default = "", HelpText = "Interface name to sniff")]
    public string? Interface { get; set; }
    
    /// <summary>
    /// Packet Limit
    /// </summary>
    [Option('n', Required = false, Default = 1, HelpText = "Number of packets to catch before ending the application")]
    public int PacketLimit { get; set; }

    /// <summary>
    /// TCP
    /// </summary>
    [Option('t', "tcp", Required = false, Default = false, HelpText = "TCP protocol")]
    public bool Tcp { get; set; }
    
    /// <summary>
    /// UDP
    /// </summary>
    [Option('u', "udp", Required = false, Default = false, HelpText = "UDP protocol")]
    public bool Udp { get; set; }
    
    /// <summary>
    /// Port
    /// </summary>
    [Option('p', "port", Required = false, Default = -1, HelpText = "Specify the port for TCP/UDP")]
    public int Port { set; get; }
    
    /// <summary>
    /// ICMPv4
    /// </summary>
    [Option(longName: "icmp4", Default = false, Required = false, HelpText = "Display only ICMPv4 packets")]
    public bool Icmp4 { set; get; }
    
    /// <summary>
    /// ICMPv6
    /// </summary>
    [Option(longName: "icmp6", Required = false, Default = false, HelpText = "Display only ICMPv6 packets")]
    public bool Icmp6 { set; get; }
    
    /// <summary>
    /// ARP
    /// </summary>
    [Option(longName: "arp", Required = false, Default = false, HelpText = "Display only ARP frames")]
    public bool Arp { set; get; }
    
    /// <summary>
    /// NDP
    /// </summary>
    [Option(longName: "ndp", Required = false, Default = false, HelpText = "Display only ICMPv6 NDP packets")]
    public bool Ndp { set; get; }
    
    /// <summary>
    /// IGMP
    /// </summary>
    [Option(longName: "igmp", Required = false, Default = false, HelpText = "Display only IGMP packets")]
    public bool Igmp { set; get; }
    
    /// <summary>
    /// MLD
    /// </summary>
    [Option(longName: "mld", Required = false, Default = false, HelpText = "Display only MLD packets")]
    public bool Mld { set; get; }

    /// <summary>
    /// Handle errors which may occur while parsing command line arguments 
    /// </summary>
    public static void HandleParseErrors()
    {
        const int incorrectArgsError = 2;
        Environment.Exit(incorrectArgsError);
    }

    /// <summary>
    /// Check correctness of command line arguments
    /// </summary>
    /// <param name="arguments"></param>
    public static void CheckArguments(Options? arguments)
    {
        if (arguments == null)
        {
            Options.HandleParseErrors();
        }
        
        // Port without tcp or udp
        if (arguments != null && arguments.Port != -1)
        {
            if (! (arguments is { Tcp: true } or { Udp: true }))
            {
                Console.WriteLine("Port has to be specified with either TCP and UDP, or both.");
                Options.HandleParseErrors();
            }
        }
        
        
    }
    
}