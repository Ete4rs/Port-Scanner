package fin_scan

import (
	"Port-Scanner/argsparse"
	"Port-Scanner/scanner/device"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

func HandleFinScanMethod(s *argsparse.Scan) {
	deviceIP := device.GetDeviceIP()
	if s.MultiThread {
		handle, err := pcap.OpenLive(device.GetDefaultInterface().Name, 65536, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
		var wg sync.WaitGroup
		for _, ip := range s.SingleIP {
			for _, val := range s.Port.Single {
				if checkExcludePort(val, s) {
					wg.Add(2)
					go sendPacket(ip.String(), val, createSynPacket(s.SrcPort, val, &ip, deviceIP), handle, &wg)
					go checkResponse(handle, time.Duration(s.Timeout), ip.String(), val, &wg)
				}
			}
			for _, r := range s.Port.Range {
				for i := r[0]; i <= r[1]; i++ {
					if checkExcludePort(i, s) {
						wg.Add(2)
						go sendPacket(ip.String(), i, createSynPacket(s.SrcPort, i, &ip, deviceIP), handle, &wg)
						go checkResponse(handle, time.Duration(s.Timeout), ip.String(), i, &wg)
					}
				}
			}
		}
		for _, ipNet := range s.Network {
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				for _, val := range s.Port.Single {
					if checkExcludePort(val, s) {
						wg.Add(2)
						go sendPacket(ip.String(), val, createSynPacket(s.SrcPort, val, &ip, deviceIP), handle, &wg)
						go checkResponse(handle, time.Duration(s.Timeout), ip.String(), val, &wg)
					}
				}
				for _, r := range s.Port.Range {
					for i := r[0]; i <= r[1]; i++ {
						if checkExcludePort(i, s) {
							wg.Add(2)
							go sendPacket(ip.String(), i, createSynPacket(s.SrcPort, i, &ip, deviceIP), handle, &wg)
							go checkResponse(handle, time.Duration(s.Timeout), ip.String(), i, &wg)
						}
					}
				}
			}
		}
		wg.Wait()
	} else {
		handle, err := pcap.OpenLive(device.GetDefaultInterface().Name, 65536, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
		for _, ip := range s.SingleIP {
			for _, val := range s.Port.Single {
				if checkExcludePort(val, s) {
					sendPacket(ip.String(), val, createSynPacket(s.SrcPort, val, &ip, deviceIP), handle, nil)
					checkResponse(handle, time.Duration(s.Timeout), ip.String(), val, nil)
				}
			}
			for _, r := range s.Port.Range {
				for i := r[0]; i <= r[1]; i++ {
					if checkExcludePort(i, s) {
						sendPacket(ip.String(), i, createSynPacket(s.SrcPort, i, &ip, deviceIP), handle, nil)
						checkResponse(handle, time.Duration(s.Timeout), ip.String(), i, nil)
					}
				}
			}
		}
		for _, ipNet := range s.Network {
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				for _, val := range s.Port.Single {
					if checkExcludePort(val, s) {
						sendPacket(ip.String(), val, createSynPacket(s.SrcPort, val, &ip, deviceIP), handle, nil)
						checkResponse(handle, time.Duration(s.Timeout), ip.String(), val, nil)
					}
				}
				for _, r := range s.Port.Range {
					for i := r[0]; i <= r[1]; i++ {
						if checkExcludePort(i, s) {
							sendPacket(ip.String(), i, createSynPacket(s.SrcPort, i, &ip, deviceIP), handle, nil)
							checkResponse(handle, time.Duration(s.Timeout), ip.String(), i, nil)
						}
					}
				}
			}
		}
	}
}

func createSynPacket(srcPort, dstPort int, dstIP, srcIP *net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	tcp := layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        123,
		Ack:        12,
		DataOffset: 5,
		FIN:        true,
		SYN:        false,
		RST:        false,
		PSH:        false,
		ACK:        false,
		URG:        false,
		ECE:        false,
		CWR:        false,
		NS:         false,
		Window:     5000,
		Checksum:   0,
		Urgent:     0,
		Options:    nil,
		Padding:    nil,
	}

	ip := layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0,
		SrcIP:      *srcIP,
		DstIP:      *dstIP,
		Options:    nil,
		Padding:    nil,
	}
	err := tcp.SerializeTo(buf, gopacket.SerializeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	err = ip.SerializeTo(buf, gopacket.SerializeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func checkExcludePort(p int, sc *argsparse.Scan) bool {
	for _, ex := range sc.Port.Exclude {
		if p == ex {
			return false
		}
	}
	for _, rex := range sc.Port.ExcludeRange {
		first := rex[0]
		last := rex[1]
		if p >= first && p <= last {
			return false
		}
	}
	return true
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func sendPacket(ip string, port int, buff []byte, handle *pcap.Handle, wg *sync.WaitGroup) {
	err := handle.WritePacketData(buff)
	if err != nil {
		fmt.Printf("%s : %d -> Failed to send", ip, port)
	}
	if wg != nil {
		wg.Done()
	}
}

func checkResponse(handle *pcap.Handle, timeout time.Duration, targetIP string, port int, wg *sync.WaitGroup) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	now := time.Now().Add(timeout * time.Second)
	for packet := range packetSource.Packets() {
		if time.Now().After(now) {
			fmt.Printf("%s : %d -> Close\n", targetIP, port)
			break
		}
		if packet == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			continue
		}
		if packet.NetworkLayer().NetworkFlow().Dst().String() == targetIP &&
			packet.TransportLayer().TransportFlow().Dst().String() == strconv.Itoa(port) {
			fmt.Printf("%s : %d -> Open\n", targetIP, port)
			break
		}
	}
	if wg != nil {
		wg.Done()
	}
}
