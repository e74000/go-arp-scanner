package main

import (
	"errors"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	gloss "github.com/charmbracelet/lipgloss"
	ouidb "github.com/dutchcoders/go-ouitools"
	"github.com/mdlayher/arp"
	"golang.org/x/term"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	selBox = gloss.NewStyle().
		Border(gloss.RoundedBorder())

	selText = gloss.NewStyle().
		Background(gloss.Color("196"))

	statusBar = gloss.NewStyle().
			Background(gloss.Color("196")).
			Foreground(gloss.Color("0"))

	db *ouidb.OuiDb
)

type model struct {
	selection    int
	selectionMax int

	IFaces     []net.Interface
	IFaceAddrs []net.Addr

	IFace     net.Interface
	IFaceAddr net.Addr

	screen int
	popup  string

	ips   []net.IP
	found map[string]bool

	client *arp.Client

	dspFound []HwIp
}

type HwIp struct {
	ip net.IP
	hw net.HardwareAddr
	ve string
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var err error

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "down":
			if m.selection < m.selectionMax {
				m.selection++
			}
		case "up":
			if m.selection > 0 {
				m.selection--
			}
		case "enter":
			if m.popup != "" {
				m.popup = ""
				return m, nil
			}

			switch m.screen {
			case 0:
				m.IFace = m.IFaces[m.selection]
				m.selection = 0
				m.IFaceAddrs, err = m.IFace.Addrs()

				if len(m.IFaceAddrs) == 0 {
					m.popup = "\n No available addresses for this interface! \n"
					return m, nil
				}

				if err != nil {
					log.Fatal(err)
				}

				m.selectionMax = len(m.IFaceAddrs) - 1

				m.screen = 1
				return m, nil
			case 1:
				m.IFaceAddr = m.IFaceAddrs[m.selection]
				m.selection = 0

				m.ips, err = allValid(m.IFaceAddr)

				if err != nil {
					m.popup = "\n ARP is not supported for IPv6! \n"
					return m, nil
				}

				m.client, err = arp.Dial(&m.IFace)

				if err != nil {
					m.popup = "\n Please run the program as root! \n"
					return m, nil
				}

				scan(m.client, m.ips)

				m.found = make(map[string]bool)
				m.dspFound = make([]HwIp, 0)

				m.screen = 2

				return m, tick()
			}
		}
	case tickMsg:
		_ = m.client.SetReadDeadline(time.Now().Add(time.Millisecond * 250))
		packet, _, _ := m.client.Read()

		if packet == nil {
			return m, tick()
		}

		if packet.Operation == arp.OperationReply {
			if !m.found[packet.SenderIP.String()] {
				m.found[packet.SenderIP.String()] = true

				v := db.Lookup(ouidb.HardwareAddr(packet.SenderHardwareAddr))

				org := ""

				if v != nil {
					org = v.Organization
				}

				m.dspFound = append(m.dspFound, HwIp{
					ip: packet.SenderIP,
					hw: packet.SenderHardwareAddr,
					ve: org,
				})
			}
		}

		return m, tick()
	}

	return m, nil
}

func allValid(addr net.Addr) ([]net.IP, error) {
	var (
		ipNet net.IPNet
	)

	switch v := addr.(type) {
	case *net.IPNet:
		ipNet = *v
	}

	if ip := ipNet.IP.To4(); ip == nil {
		return nil, errors.New("ARP is not supported for IPv6")
	}

	bits, _ := ipNet.Mask.Size()

	out := make([]net.IP, 1<<(32-bits))

	count := 0

	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			testIp := net.IPv4(ipNet.IP.To4()[0], ipNet.IP.To4()[1], byte(i), byte(j))

			if ipNet.Contains(testIp) {
				out[count] = testIp
				count++
			}
		}
	}

	return out, nil
}

func scan(client *arp.Client, ipList []net.IP) {
	for _, ip := range ipList {
		_ = client.Request(ip)
	}
}

func (m model) Init() tea.Cmd {
	return tea.EnterAltScreen
}

func (m model) View() string {
	tx, ty, _ := term.GetSize(int(os.Stdout.Fd()))

	screen := strings.Builder{}

	s := ""

	bar := gloss.JoinHorizontal(gloss.Right, " Press `q` or `ctrl+c` to quit. ")

	screen.WriteString(statusBar.Width(tx).Render(bar))

	if m.popup != "" {
		s = m.popup

		menu := gloss.Place(tx, ty,
			gloss.Center, gloss.Center,
			selBox.Render(s),
			gloss.WithWhitespaceChars("▚"),
			gloss.WithWhitespaceForeground(gloss.Color("235")),
		)

		screen.WriteString(menu)

		return screen.String()
	}

	switch m.screen {
	case 0:
		for i, iFace := range m.IFaces {
			if i == m.selection {
				s += selText.Render(fmt.Sprintf(" %10s %17s %5d ", iFace.Name, iFace.HardwareAddr, iFace.MTU))
			} else {
				s += fmt.Sprintf(" %10s %17s %5d", iFace.Name, iFace.HardwareAddr, iFace.MTU)
			}

			if i != len(m.IFaces)-1 {
				s += "\n"
			}
		}

		menu := gloss.Place(tx, ty,
			gloss.Center, gloss.Center,
			selBox.Render(s),
			gloss.WithWhitespaceChars("▚"),
			gloss.WithWhitespaceForeground(gloss.Color("235")),
		)

		screen.WriteString(menu)

	case 1:
		for i, iFaceAddr := range m.IFaceAddrs {
			if i == m.selection {
				s += selText.Render(fmt.Sprintf(" %42s ", iFaceAddr.String()))
			} else {
				s += fmt.Sprintf(" %42s ", iFaceAddr.String())
			}

			if i != len(m.IFaceAddrs)-1 {
				s += "\n"
			}
		}

		menu := gloss.Place(tx, ty,
			gloss.Center, gloss.Center,
			selBox.Render(s),
			gloss.WithWhitespaceChars("▚"),
			gloss.WithWhitespaceForeground(gloss.Color("235")),
		)

		screen.WriteString(menu)
	case 2:
		for i := 0; i < ty-6; i++ {
			if i >= len(m.dspFound) {
				s += "\n"
				continue
			}

			j := len(m.dspFound) - i - 1

			s += fmt.Sprintf(" %-15s %17s %s ", m.dspFound[j].ip, m.dspFound[j].hw, m.dspFound[j].ve)

			if i != len(m.dspFound)-1 {
				s += "\n"
			}
		}

		menu := gloss.Place(tx, ty,
			gloss.Center, gloss.Center,
			selBox.Render(s),
			gloss.WithWhitespaceChars("▚"),
			gloss.WithWhitespaceForeground(gloss.Color("235")),
		)

		screen.WriteString(menu)
	}

	return screen.String()
}

func main() {
	m := model{}

	var err error

	db = ouidb.New("/lib/ascan/ouidb.txt")

	if db == nil {
		fmt.Println("DB failed to initialise, please check whether /lib/ascan/ouidb.txt exists.")
		os.Exit(-1)
	}

	m.IFaces, err = net.Interfaces()
	m.selectionMax = len(m.IFaces) - 1

	if err != nil {
		fmt.Println("Failed to get interfaces.")
		os.Exit(-1)
	}

	var p = tea.NewProgram(m, tea.WithAltScreen())

	if err = p.Start(); err != nil {
		fmt.Println("Failed to initialise program.")
		os.Exit(-1)
	}
}
