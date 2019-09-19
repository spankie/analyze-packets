package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

// FindDevices Find all network devices
func FindDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		if len(device.Addresses) == 2 {
			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ") // , device.Description
			for a, address := range device.Addresses {
				fmt.Printf("%v - IP address: %v\n", a, address.IP)
				fmt.Printf("%v - Subnet mask: %v\n", a, address.Netmask)
			}
		}
	}
}

func main() {
	FindDevices()
}
