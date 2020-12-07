package ip4scout

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/LeakIX/gopacket/routing"
	"github.com/LeakIX/l9format"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	"go.uber.org/ratelimit"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

type RandomCommand struct {
	BlacklistFile      *os.File         `help:"Blacklist file, in CIDR form" short:"b" type:"existingFile"`
	SourcePort         layers.TCPPort   `help:"Source port, default is random" default:"0" short:"s"`
	Ports              string           `help:"list of target ports" short:"p"`
	RateLimit          int              `help:"Max pps" short:"r" default:"1000"`
	DisableRecommended bool             `help:"Disable the recommended blacklist" short:"d"`
	ports          []layers.TCPPort     `kong:"-"`
}


func (cmd *RandomCommand) Run() (err error) {
	rand.Seed(time.Now().UnixNano())
	if len(cmd.Ports) < 1 {
		cmd.ports = append(cmd.ports, layers.TCPPort(0))
	} else {
		cmd.ports, err = ParsePortsList(cmd.Ports)
		if err != nil {
			return err
		}
	}
	if cmd.SourcePort == 0 {
		cmd.SourcePort = layers.TCPPort(rand.Int()%29000)+1000
	}
	if !cmd.DisableRecommended {
		IPBlacklist = append(IPBlacklist, recommendedBlacklist...)
		cmd.AddBLockToBlacklist("23.192.0.0/11")
		cmd.AddBLockToBlacklist("23.32.0.0/11")
		cmd.AddBLockToBlacklist("23.64.0.0/14")
		cmd.AddBLockToBlacklist("23.0.0.0/12")
		cmd.AddBLockToBlacklist("104.64.0.0/10")
		cmd.AddBLockToBlacklist("2.21.112.0/20")
		cmd.AddBLockToBlacklist("104.16.0.0/12")
		cmd.AddBLockToBlacklist("198.41.128.0/17")
		cmd.AddBLockToBlacklist("184.24.0.0/13")
		log.Printf("Recommended blacklist loaded")
	}
	if cmd.BlacklistFile != nil {
		blacklistFileScanner := bufio.NewScanner(cmd.BlacklistFile)
		for blacklistFileScanner.Scan() {
			cmd.AddBLockToBlacklist(blacklistFileScanner.Text())
		}
		log.Printf("Loaded blacklist from %s", cmd.BlacklistFile.Name())
	}
	log.Printf("%d networks in blacklist", len(IPBlacklist))
	log.Printf("Loaded %d ports to scan", len(cmd.ports))
	log.Printf("Using source port %d", cmd.SourcePort)
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
	err = handle.SetBPFFilter(fmt.Sprintf("ip and port %d", cmd.SourcePort))
	if err != nil {
		log.Fatal(err)
	}
	// Start the listening thread
	go cmd.ListenForAck(handle)
	// Compute mac for our gateway
	gwMac, err := net.ParseMAC(arp.Search(gw.To4().String()))
	if err != nil {
		log.Fatal(err)
	}
	rl := ratelimit.New(cmd.RateLimit, ratelimit.WithoutSlack)
	var portToScan layers.TCPPort
	for {
		rl.Take()
		portToScan = cmd.ports[rand.Int()%len(cmd.ports)]
		if portToScan == 0 {
			portToScan = layers.TCPPort((rand.Int()%9000)+1000)
		}
		cmd.SendPacket(handle, iface, src, gwMac, cmd.RandomPublicIp(), portToScan )
	}
}

// I just listen for SYN/ACK on port 16655 and print things
func (cmd *RandomCommand) ListenForAck(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Listening!")
	jsonEncoder := json.NewEncoder(os.Stdout)
	for packet := range packetSource.Packets() {
		var dport layers.TCPPort
		var srcIp net.IP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if !tcpLayer.(*layers.TCP).SYN ||
				!tcpLayer.(*layers.TCP).ACK ||
				tcpLayer.(*layers.TCP).DstPort != layers.TCPPort(cmd.SourcePort) ||
				tcpLayer.(*layers.TCP).RST ||
				tcpLayer.(*layers.TCP).Ack != 1 {
				continue
			}
			dport = tcpLayer.(*layers.TCP).SrcPort
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			srcIp = ipLayer.(*layers.IPv4).SrcIP
			event := &l9format.L9Event{
				EventType: "synack",
				Ip:   srcIp.String(),
				Port: fmt.Sprintf("%d", dport),
				EventSource: "ip4scout",
			}
			event.EventPipeline = append(event.EventPipeline, event.EventSource)
			err := jsonEncoder.Encode(event)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (cmd *RandomCommand) RandomPublicIp() net.IP {
	var ip net.IP
	token := make([]byte, 4)
	for {
		rand.Read(token)
		ip = net.IPv4(token[0], token[1], token[2], token[3])
		if cmd.IsIpPublic(ip) {
			return ip
		}
	}
}

func (cmd *RandomCommand) AddBLockToBlacklist(network string) {
	_, net, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal("Error adding to bl")
	}
	IPBlacklist = append(IPBlacklist, net)
}


func (cmd *RandomCommand) IsIpPublic(ip net.IP) bool {
	for _, block := range IPBlacklist {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

func (cmd *RandomCommand) SendPacket(handle *pcap.Handle, iface *net.Interface, src net.IP, gwMac net.HardwareAddr, ip net.IP, dport layers.TCPPort) {
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
		SrcPort: layers.TCPPort(cmd.SourcePort),
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

var IPBlacklist = []*net.IPNet{
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
}

var recommendedBlacklist = []*net.IPNet{
	// List of easily pissed off people
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