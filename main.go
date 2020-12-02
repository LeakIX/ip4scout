package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/LeakIX/gopacket/routing"
	"github.com/mostlygeek/arp"
	"gitlab.nobody.run/tbi/core"
	"go.uber.org/ratelimit"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		toScanPorts = []layers.TCPPort{}
		for _, portString := range strings.Split(os.Args[1], ",") {
			port, err := strconv.Atoi(portString)
			if err != nil {
				log.Fatal(err)
			}
			toScanPorts = append(toScanPorts, layers.TCPPort(port))
		}
	}
	log.Printf("Loaded %d ports to scan", len(toScanPorts))
	// Init our random generator
	rand.Seed(time.Now().UnixNano())
	addBLockToPrivate("23.192.0.0/11")
	addBLockToPrivate("23.32.0.0/11")
	addBLockToPrivate("23.64.0.0/14")
	addBLockToPrivate("23.0.0.0/12")
	addBLockToPrivate("104.64.0.0/10")
	addBLockToPrivate("2.21.112.0/20")
	addBLockToPrivate("104.16.0.0/12")
	addBLockToPrivate("198.41.128.0/17")
	addBLockToPrivate("184.24.0.0/13")
	// Compute routing settings for public packets
	router, err := routing.New()
	if err != nil {
		log.Fatal(err)
	}
	iface, gw, src, err := router.Route(net.IP{1, 1, 1, 1})
	if err != nil {
		log.Fatal(err)
	}

	// Open main interface handle for packets r/w
	handle, err := pcap.OpenLive(iface.Name, 1024*256, true, 100*time.Nanosecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Define our BPFFilter to listen for ACK/SYN
	err = handle.SetBPFFilter("ip and port 16655")
	if err != nil {
		log.Fatal(err)
	}
	// Start the listening thread
	go listenForAck(handle)


	// Compute mac for our gateway
	gwMac, err := net.ParseMAC(arp.Search(gw.To4().String()))
	if err != nil {
		log.Fatal(err)
	}
	rl := ratelimit.New(6500, ratelimit.WithoutSlack)
	var portToScan layers.TCPPort
	for {
		rl.Take()
		portToScan = toScanPorts[rand.Int()%len(toScanPorts)]
		if portToScan == 0 {
			portToScan = layers.TCPPort((rand.Int()%9000)+1000)
		}
		sendPacket(handle, iface, src, gwMac, randomPublicIp(), portToScan )
	}

}

// I just listen for SYN/ACK on port 16655 and print things
func listenForAck(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Listening!")
	jsonEncoder := json.NewEncoder(os.Stdout)
	for packet := range packetSource.Packets() {
		var dport layers.TCPPort
		var srcIp net.IP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if !tcpLayer.(*layers.TCP).SYN || !tcpLayer.(*layers.TCP).ACK || tcpLayer.(*layers.TCP).DstPort != 16655 || tcpLayer.(*layers.TCP).RST || tcpLayer.(*layers.TCP).Ack != 1 {
				continue
			}
			dport = tcpLayer.(*layers.TCP).SrcPort
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			srcIp = ipLayer.(*layers.IPv4).SrcIP
			err := jsonEncoder.Encode(&core.HostService{
				Ip:   srcIp.String(),
				Port: fmt.Sprintf("%d", dport),
			})
			if err != nil {
				panic(err)
			}
		}
	}
}

func randomPublicIp() net.IP {
	var ip net.IP
	token := make([]byte, 4)
	for {
		rand.Read(token)
		ip = net.IPv4(token[0], token[1], token[2], token[3])
		if isIpPublic(ip) {
			return ip
		}
	}
}

func addBLockToPrivate(network string) {
	_, net, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal("Error adding to bl")
	}
	privateIPBlocks = append(privateIPBlocks, net)
	log.Println(net.String() + " added to blacklist!")
}

var toScanPorts = []layers.TCPPort{0}

var privateIPBlocks = []*net.IPNet{
	{
		IP:   net.IP{127, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{0, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{192, 168, 0, 0},
		Mask: net.IPMask{255, 255, 0, 0},
	},
	{
		IP:   net.IP{10, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{172, 16, 0, 0},
		Mask: net.IPMask{255, 240, 0, 0},
	},
	{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.IPMask{255, 192, 0, 0},
	},
	{
		IP:   net.IP{224, 0, 0, 0},
		Mask: net.IPMask{224, 0, 0, 0},
	},
	{
		IP:   net.IP{148, 59, 85, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	},
	{
		IP:   net.IP{6,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{7,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{11,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{21,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{22,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{26,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{28,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{29,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{30,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{33,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{55,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{214,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{215,0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
}

func isIpPublic(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

func sendPacket(handle *pcap.Handle, iface *net.Interface, src net.IP, gwMac net.HardwareAddr, ip net.IP, dport layers.TCPPort) {
	buff := gopacket.NewSerializeBuffer()
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       gwMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Version:  4,
		TOS:      0,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src,
		DstIP:    ip,
	}
	tcp := layers.TCP{
		SrcPort: 16655,
		DstPort: dport, // will be incremented during the scan
		SYN:     true,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		log.Fatal(err)
	}
	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip4, &tcp)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.WritePacketData(buff.Bytes())
	if err != nil {
		log.Printf("Failed sending packet for %s:%d sleeping 10 secs and resuming ...", ip.String(), dport)
		time.Sleep(10 * time.Second)
	}
}