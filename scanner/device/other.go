package device

import (
	"fmt"
	"net"
)

func GetDeviceIP() *net.IP {
	iface := GetDefaultInterface()
	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return &ipNet.IP
		}
	}
	return nil
}

func GetDefaultInterface() *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return &iface
		}
	}
	return nil
}
