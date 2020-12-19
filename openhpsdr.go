// Package openhpsdr is a interface to the openHPSDR Radio Boards
// by Dave Larsen KV0S, May 3, 2014
// GPL2
// version 0.1.4
package openhpsdr

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Intface structure
type Intface struct {
	Intname   string
	MAC       string
	Ipv4      string
	Mask      []byte
	Network   string
	Ipv6      string
	Ipv4Bcast string
}

// Interfaces determines the network interfaces connect to this machine.
func Interfaces() (Intfc []Intface, err error) {

	intr, er := net.Interfaces()
	if er != nil {
		err = fmt.Errorf("Interface error %v", err)
		return nil, err
	}

	Intfc = make([]Intface, len(intr))

	for i := range intr {
		//fmt.Println(intr[i].Name, intr[i].HardwareAddr)
		Intfc[i].Intname = intr[i].Name
		Intfc[i].MAC = intr[i].HardwareAddr.String()
		aad, err := intr[i].Addrs()
		if err != nil {
			err = fmt.Errorf("Interface error %v", err)
			return Intfc, err
		}

		Intfc[i].Intname = intr[i].Name

		for j := range aad {
			ip := net.ParseIP(aad[j].String())
			str := aad[j].String()

			//var ip net.IP
			if strings.Contains(str, ".") {
				//ip, _, err := net.ParseCIDR(aad[j].String())
				//ip := net.ParseIP(aad[j].String())
				if runtime.GOOS == "windows" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else if runtime.GOOS == "darwin" {
					ip = net.ParseIP(aad[j].String())
					adstring := strings.Split(aad[j].String(), "/")
					Intfc[i].Ipv4 = adstring[0]
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else {
					ip, _, err = net.ParseCIDR(aad[0].String())
					Intfc[i].Ipv4 = ip.String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				}
				if er != nil {
					err = fmt.Errorf("Parce IP error %v", er)
					return Intfc, err
				}

				//str := strings.Split(Intfc[i].Ipv4, ".")
				var ipd []string
				//ipd = append(ipd, str[0], str[1], str[2], "255")
				ipd = append(ipd, "255", "255", "255", "255")
				Intfc[i].Ipv4Bcast = strings.Join(ipd, ".")
			} else {
				if runtime.GOOS == "windows" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else if runtime.GOOS == "darwin" {
					ip = net.ParseIP(aad[j].String())
					Intfc[i].Ipv4 = aad[j].String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				} else {
					ip, _, err = net.ParseCIDR(aad[0].String())
					Intfc[i].Ipv4 = ip.String()
					Intfc[i].Mask = ip.DefaultMask()
					Intfc[i].Network = ip.Mask(Intfc[i].Mask).String()
				}

				if er != nil {
					err = fmt.Errorf("Parce IP error %v", er)
					return Intfc, err
				}
				//ip, _, err = net.ParseCIDR(aad[1].String())
				//Intfc[i].Ipv6 = ip.To6()
			}
		}
	}
	return Intfc, err
}

//Hpsdrboard structure
type Hpsdrboard struct {
	Status     string
	Board      string
	Protocol   string
	Baddress   string
	Bport      string
	Pcaddress  string
	Macaddress string
	Firmware   string
}

// Discover send the Discovery packet to an interface.
func Discover(addrStr string, bcastStr string, ddelay int, debug string) (strs []Hpsdrboard, err error) {
	var b []byte
	var c []byte
	var str Hpsdrboard

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	b, er := hex.DecodeString("effe02")
	if er != nil {
		err = fmt.Errorf("Hex decode error %v", er)
		return nil, err
	}

	for i := 3; i < 64; i++ {
		b = append(b, 0x00)
	}

	//fmt.Println(addrStr, bcastStr)
	addr, er := net.ResolveUDPAddr("udp", addrStr)
	if er != nil {
		err = fmt.Errorf("Address not resolved %v", er)
		return nil, err
	}

	bcast, er := net.ResolveUDPAddr("udp", bcastStr)
	if er != nil {
		err = fmt.Errorf("Broadcast Address not resolved %v", er)
		return nil, err
	}

	l, er := net.ListenUDP("udp", addr)
	if er != nil {
		err = fmt.Errorf("ListenUDP error %v", er)
		return nil, err
	}
	defer l.Close()

	k, er := l.WriteToUDP(b, bcast)

	if er != nil {
		err = fmt.Errorf("Broadcast not connected %v, %v", k, er)
		return nil, err
	}

	if strings.Contains(debug, "hex") {
		fmt.Println("Discovery ")
		fmt.Printf("sent : %s: %x : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Discover ")
		fmt.Printf("sent : %s: %v : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	}
	l.SetReadDeadline(time.Time(time.Now().Add(time.Duration(ddelay) * time.Second)))

	//fmt.Println( "Before the loop" )
	for i := 0; i < 3; i++ {
		_, ad, _ := l.ReadFromUDP(c)

		if ad != nil {
			if strings.Contains(debug, "hex") {
				fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
			} else if strings.Contains(debug, "dec") {
				fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
			}
			str.Protocol = "p1"
			str.Pcaddress = addrStr

			if c[2] == 2 {
				str.Status = "idle"
			} else if c[2] == 3 {
				str.Status = "running"
			}

			str.Macaddress = fmt.Sprintf("%x:%x:%x:%x:%x:%x", c[3], c[4], c[5], c[6], c[7], c[8])

			if c[10] == 0 {
				str.Board = "Metis"
			} else if c[10] == 1 {
				str.Board = "Hermes"
			} else if c[10] == 2 {
				str.Board = "Griffin"
			} else if c[10] == 3 {
				str.Board = "Unknown"
			} else if c[10] == 4 {
				str.Board = "Angelia"
			} else if c[10] == 5 {
				str.Board = "Orion"
			} else if c[10] == 6 {
				str.Board = "Hermes-lite"
			} else if c[10] == 7 {
				str.Board = "TangerineSDR"
			}

			str.Firmware = fmt.Sprintf("%d.%d", c[9]/10, c[9]%10)

			st := strings.Split(ad.String(), ":")
			str.Baddress = st[0]
			str.Bport = st[1]

			strs = append(strs, str)
		}
	}
	//fmt.Println( "After the loop")

	return strs, err

}

//Setip function sets a new fixed ip for the HPSDR board on your domain.
func Setip(newip string, str Hpsdrboard, debug string, check bool) (st Hpsdrboard, err error) {
	var b []byte
	var c []byte

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	b, er := hex.DecodeString("effe03")
	if er != nil {
		err = fmt.Errorf("Hex decode error %v", er)
		return str, err
	}

	macstr := strings.Split(str.Macaddress, ":")
	//fmt.Println("length of macstr ", len(macstr), macstr)

	for i := 0; i < len(macstr); i++ {
		m := []byte(macstr[i])
		if len(m) < 2 {
			m = []byte("0")
			m = append(m, []byte(macstr[i])[0])
		}
		mm := make([]byte, len(m))
		_, er := hex.Decode(mm, m)
		if er != nil {
			err = fmt.Errorf("Hex decode error %v", er)
			return str, err
		}
		//fmt.Println("index ", i, m, mm)
		b = append(b, mm[0])
	}

	ipstr := strings.Split(newip, ".")
	if len(ipstr) != 4 {
		return str, fmt.Errorf("proposed IPV4 address has %d numbers, must be 4 numbers", len(ipstr))
	}
	ipad := net.ParseIP(str.Baddress)
	msk := ipad.DefaultMask()
	netw := ipad.Mask(msk).String()

	//fmt.Println("newip ", newip, !strings.Contains(newip, "255.255.255.255"))
	check = !strings.Contains(newip, "255.255.255.255")

	if check {
		ntipstr := strings.Split(netw, ".")
		//fmt.Println("length of newip ", len(ipstr), ipstr)
		for i := 0; i < len(ipstr); i++ {
			m, er := strconv.Atoi(ipstr[i])
			if er != nil {
				err = fmt.Errorf("IPv4 string decode error %v", er)
				return str, err
			}
			nm, er := strconv.Atoi(ntipstr[i])
			if er != nil {
				err = fmt.Errorf("IPv4 string decode error %v", er)
				return str, err
			}
			if i == 0 {
				if m == 127 {
					return str, fmt.Errorf("127 reserved for localhost")
				} else if m == 224 {
					return str, fmt.Errorf("224 reserved")
				} else if m == 224 {
					return str, fmt.Errorf("224 reserved")
				} else if m == 169 {
					return str, fmt.Errorf("169 reserved for adhoc networks")
				} else if m == 240 {
					return str, fmt.Errorf("240 reserved")
				}
			}
			if (m != nm) && (nm != 0) {
				return str, fmt.Errorf("changing subnet is not recommended")
			}
			//fmt.Println("index ", i, m, ipstr[i])
			b = append(b, byte(m))
		}
	}

	for i := 9; i < 64; i++ {
		if i > 12 {
			b = append(b, 0x00)
		}
	}

	//pcaddr := fmt.Sprintf("%s:%s", str.Pcaddress, "1024")
	addr, er := net.ResolveUDPAddr("udp", str.Pcaddress)
	if er != nil {
		err = fmt.Errorf("Address not resolved %v", er)
		return str, err
	}

	bcast, er := net.ResolveUDPAddr("udp", "255.255.255.255:1024")
	if er != nil {
		err = fmt.Errorf("broadcast not resolved %v", er)
		return str, err
	}

	l, er := net.ListenUDP("udp", addr)
	if er != nil {
		err = fmt.Errorf("ListenUDP error %v", er)
		return str, err
	}
	defer l.Close()

	k, er := l.WriteToUDP(b, bcast)
	if er != nil {
		err = fmt.Errorf("broadcast string not connected %v %v", k, er)
		return str, err
	}
	if strings.Contains(debug, "hex") {
		fmt.Println("Set IP ")
		fmt.Printf("sent : %s: %x : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Set IP ")
		fmt.Printf("sent : %s: %v : length=%d\n", bcast, b, len(b))
		fmt.Println(" ")
	}
	l.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

	_, ad, _ := l.ReadFromUDP(c)

	if strings.Contains(debug, "hex") {
		fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
		fmt.Println(" ")
	}

	err = nil
	return str, err
}

// Programboard sends a new RBF file to the HPSDR board flash memory.
func Programboard(str Hpsdrboard, input string, debug string) error {
	//var output string
	//output = "output"
	var er error

	// Open the RBF file
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// calculate the Statistics of the RBF file
	fi, err := f.Stat()
	if err != nil {
		fmt.Println("Could not open the file")
	}

	fmt.Println("\n      Programming the HPSDR Board")
	packets := math.Ceil(float64(fi.Size()) / 256.0)
	fmt.Println("    Found rbf file:", input)
	fmt.Println("     Size rbf file:", fi.Size())
	fmt.Println("Size rbf in memory:", ((fi.Size()+255)/256)*256)
	fmt.Println("           Packets:", packets)
	fmt.Println(" ")
	fmt.Printf("           Percent:     ")

	// make a read buffer
	r := bufio.NewReader(f)
	// open output file  THIS CODE USED FOR FILE WRITE OUT OR TESTING
	//fo, err := os.Create(outpustr.Boardstr.Boardstr.Boardstr.Boardit)
	//if err != nil {
	///		log.Fatal(err)
	//	}

	//	defer func() {
	//		err := fo.Close()
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//	}()

	// make a write buffer
	//w := bufio.NewWriter(fo)

	// Open the UDP connections
	addr, err := net.ResolveUDPAddr("udp", str.Pcaddress)
	if err != nil {
		fmt.Println(" Addr not resolved ", err)
	}

	bdaddr := fmt.Sprintf("%s:%s", str.Baddress, "1024")
	baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	if err != nil {
		fmt.Println(" Baddr not resolved ", err)
	}

	//l, err := net.ListenUDP("udp", addr)
	//if err != nil {
	//	fmt.Println(" ListenUDP error ", err)
	//}

	//defer l.Close()

	w, err := net.DialUDP("udp", addr, baddr)
	if err != nil {
		fmt.Println(" DialUDP error ", err)
	}

	defer w.Close()

	// make a buffer to keep chunks that are read
	buf := make([]byte, 256)
	var b []byte
	p := make([]byte, 4)

	pk := int(packets)
	p[0] = byte((pk >> 24) & 0xff)
	p[1] = byte((pk >> 16) & 0xff)
	p[2] = byte((pk >> 8) & 0xff)
	p[3] = byte(pk & 0xff)

	//totalnb := float64(fi.Size())
	tpk := 0
	for {
		// read a chunk
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}

		if n == 0 {
			break
		}

		if n < 256 {
			for i := n; i < 256; i++ {
				buf[i] = 0xFF
			}
			n = 256
		}

		b, err = hex.DecodeString(fmt.Sprintf("effe0301%x", string(p)))
		if err != nil {
			fmt.Println("Hex decode error", err)
		}

		b = append(b, buf...)

		//nb, err := PackettoFile(str, b, w, debug, tpk)
		_, err = PackettoUDP(str, b, w, debug, tpk)
		if err != nil {
			fmt.Println("Read Error:", err)
		}

		tpk++
		if debug == "none" {
			pct := (float64(tpk) / packets) * 100.0
			fmt.Printf("\b\b\b\b%4.0f", pct)
		}
	}
	fmt.Println("\n      Programming Done")

	er = nil
	return er
}

//PackettoFile sends on 256 packet formatted for programming to a file for testing.
func PackettoFile(str Hpsdrboard, buf []byte, w *bufio.Writer, debug string, tpk int) (int, error) {

	// debug prints
	if debug == "hex" {
		fmt.Println("Program Board ")
		fmt.Printf("sent : %s: %x : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	} else if debug == "dec" {
		fmt.Println("Program Board")
		fmt.Printf("sent : %s: %v : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	}

	// write a chunk
	nb, err := w.Write(buf[9:])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(" ")

	err = w.Flush()
	if err != nil {
		log.Fatal(err)
	}

	var er error
	er = nil
	return nb, er
}

//PackettoUDP sends one 256 packet formatted for programming to a UDP address.
func PackettoUDP(str Hpsdrboard, buf []byte, w *net.UDPConn, debug string, tpk int) (int, error) {
	//var b []byte
	var c []byte = make([]byte, 64, 64)
	// debug prints
	if debug == "hex" {
		fmt.Println("Program Board ")
		fmt.Printf("sent : %s: %x : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	} else if debug == "dec" {
		fmt.Println("Program Board")
		fmt.Printf("sent : %s: %v : length=%d packet=%d\n", fmt.Sprintf("%s:%s", str.Baddress, str.Bport), buf, len(buf), tpk+1)
		fmt.Println(" ")
	}

	//bdaddr := fmt.Sprintf("%s:%s", str.Baddress, str.Bport)
	//baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	k, err := w.Write(buf)
	if err != nil {
		fmt.Println(" address not connected ", k, err)
	}

	//	for {
	//	w.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

	n, ad, err := w.ReadFromUDP(c)
	if err != nil {
		return 3, err
	}

	if n > 0 {

		if debug == "hex" {
			fmt.Printf("received : %s: on %s %x : length=%d\n", ad, str.Pcaddress, c, len(c))
			fmt.Println(" ")
		} else if debug == "dec" {
			fmt.Printf("received : %s: on %s %v : length=%d\n", ad, str.Pcaddress, c, len(c))
			fmt.Println(" ")
		}
	} else {
		fmt.Printf("received : Time out %s on %s %v : length=%d\n", ad, str.Pcaddress, c, len(c))
		fmt.Println(" ")
	}

	//}
	var er error
	er = nil
	return 3, er
}

//Erasestatus structure
type Erasestatus struct {
	Seconds int
	State   error
}

//Eraseboard sends the erase command to the HPSDR board direst writes
func Eraseboard(str Hpsdrboard, input string, edelay int, debug string) (erstat Erasestatus, err error) {
	var b []byte
	var c []byte

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	// Open the RBF file and close it, we do not want to coninue is file does not exist.
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
	}

	if debug == "none" {
		erstat.State = fmt.Errorf("erasing the hpsdr board")
	}

	b, er := hex.DecodeString("effe0302")
	if er != nil {
		fmt.Println("Hex decode error", er)
		err = fmt.Errorf("hex decode error %v", er)
		return erstat, err
	}

	for i := 4; i < 64; i++ {
		b = append(b, 0x00)
	}

	addr, err := net.ResolveUDPAddr("udp", str.Pcaddress)
	if err != nil {
		fmt.Println(" Addr not resolved ", err)
		err = fmt.Errorf("address not resolved %v", er)
		return erstat, err
	}

	bdaddr := fmt.Sprintf("%s:%s", str.Baddress, "1024")
	baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	if err != nil {
		fmt.Println(" Baddr not resolved ", err)
		err = fmt.Errorf("broadcast not resolved %v", er)
		return erstat, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		err = fmt.Errorf("listenUDP error %v", er)
		return erstat, err
	}
	defer l.Close()

	k, err := l.WriteToUDP(b, baddr)
	if err != nil {
		err = fmt.Errorf("address not connected %v %v", k, er)
		return erstat, err
	}

	if strings.Contains(debug, "hex") {
		fmt.Println("Erasing Board ")
		fmt.Printf("sent : %s: %x : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Erasing Board")
		fmt.Printf("sent : %s: %v : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	}

	fmt.Print("           Seconds:     ")
	for i := 0; i < edelay; i++ {
		l.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

		n, ad, _ := l.ReadFromUDP(c)

		fmt.Printf("\b\b\b\b%4d", i)
		erstat.Seconds = i
		if n > 0 {
			if strings.Contains(debug, "hex") {
				fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if strings.Contains(debug, "dec") {
				fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if debug == "none" {
				erstat.State = fmt.Errorf("Erasing Done")
				i = edelay
				break
			}
		} else if i+1 == edelay {
			//fmt.Printf("\n      Timeout at %s Seconds\n", edelay)
			erstat.State = fmt.Errorf("timeout at %d Seconds", edelay)
			return erstat, fmt.Errorf("timeout at %d Seconds", edelay)
		} else {
			fmt.Printf("\b\b\b\b%4d", i)
		}
	}

	err = nil
	return erstat, err

}

// Send the erase command to the HPSDR board send to channel
/*func Eraseboardchan(str Hpsdrboard, input string, edelay int, debug string, ci chan int, done chan bool) error {
	var b []byte
	var c []byte

	b = make([]byte, 64, 64)
	c = make([]byte, 64, 64)

	// Open the RBF file and close it, we do not want to coninue is file does not exist.
	f, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}

	if debug == "none" {
		fmt.Println("\n      Erasing the HPSDR Board")
	}

	b, err = hex.DecodeString("effe0302")
	if err != nil {
		fmt.Println("Hex decode error", err)
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
	}

	for i := 4; i < 64; i++ {
		b = append(b, 0x00)
	}

	addr, err := net.ResolveUDPAddr("udp", str.Pcaddress)
	if err != nil {
		fmt.Println(" Addr not resolved ", err)
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
	}

	bdaddr := fmt.Sprintf("%s:%s", str.Baddress, "1024")
	baddr, err := net.ResolveUDPAddr("udp", bdaddr)
	if err != nil {
		fmt.Println(" Baddr not resolved ", err)
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println(" listenUDP error ", err)
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
	}
	defer l.Close()

	k, err := l.WriteToUDP(b, baddr)
	if err != nil {
		fmt.Println(" address not connected ", k, err)
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
	}

	if strings.Contains(debug, "hex") {
		fmt.Println("Erasing Board ")
		fmt.Printf("sent : %s: %x : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	} else if strings.Contains(debug, "dec") {
		fmt.Println("Erasing Board")
		fmt.Printf("sent : %s: %v : length=%d\n", baddr, b, len(b))
		fmt.Println(" ")
	}

	fmt.Print("           Seconds:     ")
	for i := 0; i < edelay; i++ {
		l.SetReadDeadline(time.Time(time.Now().Add(1 * time.Second)))

		n, ad, _ := l.ReadFromUDP(c)

		ci <- i
		fmt.Printf("\b\b\b\b%4d", i)
		if n > 0 {
			if strings.Contains(debug, "hex") {
				fmt.Printf("received : %s: %x : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if strings.Contains(debug, "dec") {
				fmt.Printf("received : %s: %v : length=%d\n", ad, c, len(c))
				fmt.Println(" ")
				i = edelay
				break
			} else if debug == "none" {
				fmt.Println("\n      Erasing Done\n")
				i = edelay
				break
			}
		} else if i+1 == edelay {
			//fmt.Printf("\n      Timeout at %s Seconds\n", edelay)
			return errors.New(fmt.Sprintf("Timeout at %d Seconds", edelay))
		err = errors.New(fmt.Sprintf("ListenUDP error %v", er))
		return str, err
		} else {
			ci <- i
			fmt.Printf("\b\b\b\b%4d", i)
		}
	}
	done <- true

	err = nil
	return erstat, err

} */
