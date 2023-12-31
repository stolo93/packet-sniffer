// File: PacketParser.cs
// Author: Samuel Stolarik
// Date: 2023-04-13
// Project: IPK project 2 - Packet Sniffer

namespace ipk_sniffer;

using SharpPcap;
using PacketDotNet;
using System;
using System.Text;
using System.Linq;

/// <summary>
/// Parse packet into printable format
/// </summary>
public static class PacketParser
{
    /// <summary>
    /// Parse packet and return it represented as a string
    /// Containing:
    ///     timestamp
    ///     src and dst MAC
    ///     frame length
    ///     src and dst IP
    ///     src and dst port
    ///     packetBytes as a hexdump and ascii
    ///
    /// If the required value is not present in the packet, the field will be empty
    /// </summary>
    /// <param name="rawCapture">Captured packet</param>
    /// <returns>String, containing information retrieved from packet.</returns>
    public static string ParsePacket(RawCapture rawCapture)
    {
        var packetInfo = new PacketInfoParsed
        {
            // Get information from the raw packet
            TimeStamp = GetTimeStamp(rawCapture),
            FrameLenght = GetByteLength(rawCapture)
        };

        // Parse packet using Packet.Net
        Packet packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

        // Get information available from the ethernet layer
        EthernetPacket ethernetPacket = packet.Extract<EthernetPacket>();
        if (ethernetPacket != null)
        {
            packetInfo.SrcMac = FormatMacAddress(ethernetPacket.SourceHardwareAddress.ToString());
            packetInfo.DstMac = FormatMacAddress(ethernetPacket.DestinationHardwareAddress.ToString());
        }

        // Get information available from the IP layer
        IPPacket ipPacket = packet.Extract<IPPacket>();
        if (ipPacket != null)
        {
            packetInfo.SrcIp = ipPacket.SourceAddress.ToString();
            packetInfo.DstIp = ipPacket.DestinationAddress.ToString();
        }

        TcpPacket tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket != null)
        {
            packetInfo.SrcPort = tcpPacket.SourcePort.ToString();
            packetInfo.DstPort = tcpPacket.DestinationPort.ToString();
        }
        
        UdpPacket udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket != null)
        {
            packetInfo.SrcPort = udpPacket.SourcePort.ToString();
            packetInfo.DstPort = udpPacket.DestinationPort.ToString();
        }
        
        packetInfo.ByteOffset = PacketHexDump(packet.Bytes);
        
        return packetInfo.ToString();
    }
        
    /// <summary>
    /// Get timestamp from packet in RFC 3339 format
    /// </summary>
    /// <param name="packet"></param>
    /// <returns>String with timestamp</returns>
    private static string GetTimeStamp(RawCapture packet)
    {
        var iso8601Format = "yyyy-MM-ddTHH:mm:ss.fffK";
        var dateTime = packet.Timeval.Date;
        var timeStamp = TimeZoneInfo.ConvertTime(dateTime, TimeZoneInfo.Local).ToString(iso8601Format);
        return timeStamp;
    }


    /// <summary>
    /// Get packet length in bytes as a string
    /// </summary>
    /// <param name="packet"></param>
    /// <returns>Packet size in bytes followed by the word bytes</returns>
    private static string GetByteLength(RawCapture packet)
    {
        return packet.Data.Length.ToString() + " bytes";
    }


    /// <summary>
    /// Return packetBytes data from the captured packet
    /// </summary>
    /// <param name="packet"></param>
    /// <returns>byte array of packetBytes data</returns>
    private static byte[]? GetPayloadData(Packet packet)
    {
        TcpPacket tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket != null) return tcpPacket.PayloadData;

        UdpPacket udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket != null) return udpPacket.PayloadData;

        ArpPacket arpPacket = packet.Extract<ArpPacket>();
        if (arpPacket != null) return arpPacket.PayloadData;

        IcmpV4Packet icmpV4Packet = packet.Extract<IcmpV4Packet>();
        if (icmpV4Packet != null) return icmpV4Packet.PayloadData;

        IcmpV6Packet icmpV6Packet = packet.Extract<IcmpV6Packet>();
        if (icmpV6Packet != null) return icmpV6Packet.PayloadData;

        IgmpPacket igmpPacket = packet.Extract<IgmpPacket>();
        if (igmpPacket != null) return igmpPacket.PayloadData;

        return null;
    }
    
    
    /// <summary>
    /// Parse packetBytes to required format containing
    /// hex counter, hex dump and ascii dump
    /// Example:
    /// Ox0020: A1 96 E1 18 91 79 95 4C 5C BA BD 9C 3D 4E 4D 3B  .....y.L\...=NM;
    /// </summary>
    /// <param name="packetBytes"></param>
    /// <returns>String representation of the packet in both hex and ascii dump</returns>
    private static string PacketHexDump(byte[]? packetBytes)
    {
        if (packetBytes == null)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        var lineCount = Decimal.Ceiling((decimal)packetBytes.Length / 16);
        // For each line, take 16 bytes from the input and write
        // HexCounter: HexDump  WhiteSpace  AsciiDump
        for (int i = 0 ; i < lineCount; i++)
        {
            var hexCounter = i * 16;
            var data = packetBytes.Skip(hexCounter).Take(16).ToArray();
            var fullLineSize = 48; // 16 bytes per line * 3 (2 hexDigits + whitespace)
            
            sb.Append("Ox" + hexCounter.ToString("X4") + ": "); // Hex counter
            sb.Append(HexLine(data));
            sb.Append(HexDumpPadding(data.Length, fullLineSize));
            sb.Append(AsciiLine(data));
            sb.Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>
    /// Create padding between hex dump and ascii dump, based on the line size
    /// </summary>
    /// <param name="dataLength"></param>
    /// <param name="lineLength"></param>
    /// <returns>String of whitespaces</returns>
    private static string HexDumpPadding(int dataLength, int lineLength)
    {
        var numSpaces = lineLength - dataLength * 3;
        return new string(' ', numSpaces + 1);
    }
    
    /// <summary>
    /// HexDump of byteLine
    /// </summary>
    /// <param name="byteLine"></param>
    /// <returns>String of whitespace separated bytes in hexadecimal form</returns>
    private static string HexLine(byte[]? byteLine)
    {
        if (byteLine == null)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        foreach (byte hexByte in byteLine)
        {
            sb.Append(hexByte.ToString("X2"));
            sb.Append(' ');
        }

        return sb.ToString();
    }
    
    /// <summary>
    /// Ascii dump of byteLine
    /// All non printable characters will be swapped for '.'
    /// </summary>
    /// <param name="byteLine"></param>
    /// <returns>String of ascii characters created from the byteLine</returns>
    private static string AsciiLine(byte[]? byteLine)
    {
        if (byteLine == null)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        foreach (byte asciiByte in byteLine)
        {
            // Non - printable
            if (asciiByte < 32 || asciiByte >= 127)
            {
                sb.Append('.');
            }
            // Printable
            else
            {
                sb.Append(Convert.ToChar(asciiByte));
            }
        }

        return sb.ToString();
    }

    
    /// <summary>
    /// Add ':' in between bytes of MAC address
    /// </summary>
    /// <param name="address"></param>
    /// <returns>String containing formatted MAC address</returns>
    private static string FormatMacAddress(string address)
    {
        StringBuilder sb = new StringBuilder();
        var separator = ':';
        for (int i = 0; i < address.Length; i++)
        {
            sb.Append(address[i]);
            if (i % 2 == 1 && i != address.Length - 1) // Check if it's an odd index and not the last character
            {
                sb.Append(separator);
            }
        }
        
        return sb.ToString();
    }
    
}

/// <summary>
/// Stores parsed packet information
/// </summary>
public class PacketInfoParsed
{
    /// <summary>
    /// Packet time stamp
    /// </summary>
    public string TimeStamp { get; set; } = "";
    /// <summary>
    /// Source MAC address
    /// </summary>
    public string SrcMac { get; set; } = "";
    /// <summary>
    /// Destination MAC address
    /// </summary>
    public string DstMac { get; set; } = "";
    /// <summary>
    /// Frame length in bytes
    /// </summary>
    public string FrameLenght { get; set; } = "";
    /// <summary>
    /// Source IP address
    /// </summary>
    public string SrcIp { get; set; } = "";
    /// <summary>
    /// Destination IP address
    /// </summary>
    public string DstIp { get; set; } = "";
    /// <summary>
    /// Source port
    /// </summary>
    public string SrcPort { get; set; } = "";
    /// <summary>
    /// Destination port
    /// </summary>
    public string DstPort { get; set; } = "";
    /// <summary>
    /// Hex and ascii dump
    /// </summary>
    public string ByteOffset { get; set; } = "";


    /// <summary>
    /// All attributes converted to string containing the required wireshark packet hexdump format
    /// </summary>
    /// <returns>String representation of internal attributes</returns>
    public override string ToString()
    {
        StringBuilder sb = new StringBuilder();
        sb.Append("timestamp: " + TimeStamp + '\n');
        sb.Append("src MAC: " + SrcMac + '\n');
        sb.Append("dst MAC: " + DstMac + '\n');
        sb.Append("frame lenght: " + FrameLenght + '\n');
        sb.Append("src IP: " + SrcIp + '\n');
        sb.Append("dst IP: " + DstIp + '\n');
        sb.Append("src port: " + SrcPort + '\n');
        sb.Append("dst port: " + DstPort + '\n');
        sb.Append('\n');
        sb.Append(ByteOffset + '\n');
        return sb.ToString();
    }
}