package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "eth0" // en0
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func LiveCapture() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet.Dump())
	}
}

func LiveCaptureWithFilter() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	filter := "udp and port 8081"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP port 8081 packets.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		// fmt.Println(packet)
		printPacketInfo(packet)
		DecodePackets(packet.Data())
	}
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Let's see if the packet is UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("%v\n%s\n=================================\n", udp.LayerContents(), udp.LayerContents())
		fmt.Printf("%v\n%s", udp.LayerPayload(), udp.LayerPayload())
		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		// fmt.Println("Sequence number: ", udp.)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func DecodePackets(payload []byte) {
	// If we don't have a handle to a device or a file, but we have a bunch
	// of raw bytes, we can try to decode them in to packet information

	// NewPacket() takes the raw bytes that make up the packet as the first parameter
	// The second parameter is the lowest level layer you want to decode. It will
	// decode that layer and all layers on top of it. The third layer
	// is the type of decoding: default(all at once), lazy(on demand), and NoCopy
	// which will not create a copy of the buffer

	// Create an packet with ethernet, IP, TCP, and payload layers
	// We are creating one we know will be decoded properly but
	// your byte source could be anything. If any of the packets
	// come back as nil, that means it could not decode it in to
	// the proper layer (malformed or incorrect packet type)
	// payload := []byte{2, 4, 6}
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.UDP{},
		gopacket.Payload(payload),
	)
	rawBytes := buffer.Bytes()

	// Decode an ethernet packet
	ethPacket :=
		gopacket.NewPacket(
			rawBytes,
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

	// with Lazy decoding it will only decode what it needs when it needs it
	// This is not concurrency safe. If using concurrency, use default
	ipPacket :=
		gopacket.NewPacket(
			rawBytes,
			layers.LayerTypeIPv4,
			gopacket.Lazy,
		)

	// With the NoCopy option, the underlying slices are referenced
	// directly and not copied. If the underlying bytes change so will
	// the packet
	udpPacket :=
		gopacket.NewPacket(
			rawBytes,
			layers.LayerTypeUDP,
			gopacket.NoCopy,
		)

	fmt.Println(ethPacket)
	fmt.Println(ipPacket)
	fmt.Println(udpPacket)
}
