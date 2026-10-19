// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// TestDiscoReplySource uses one remote socket to probe two local addresses.
// A wildcard UDP listener must reply from the address that received each ping,
// even when the default route would choose a different source address.
func TestDiscoReplySource(t *testing.T) {
	for _, tc := range []struct {
		network, peerIP string
		localIPs        []string
	}{
		{"udp4", "127.0.0.1", []string{"127.0.0.2", "127.0.0.3", "127.0.0.2"}},
		{"udp6", "2001:db8:1::1", []string{"2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::2"}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			c := newTestConn(t)
			c.mu.Lock()
			c.testOnlyPacketListener = &net.ListenConfig{}
			c.mu.Unlock()
			c.Rebind()

			peer, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: net.ParseIP(tc.peerIP)})
			if err != nil {
				if tc.network == "udp6" && errors.Is(err, syscall.EADDRNOTAVAIL) {
					t.Skip("requires 2001:db8:1::{1,2,3} on loopback in the test network namespace")
				}
				t.Fatal(err)
			}
			defer peer.Close()
			peerDisco := key.NewDisco()
			peerKey := key.NewNode().Public()
			c.SetNetworkMap(tailcfg.NodeView{}, nodeViews([]*tailcfg.Node{{
				ID: 1, Key: peerKey, DiscoKey: peerDisco.Public(),
				Endpoints: []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()},
			}}))
			c.SetPrivateKey(key.NewNode())

			ruc := &c.pconn4
			receive := c.receiveIPv4()
			if tc.network == "udp6" {
				ruc, receive = &c.pconn6, c.receiveIPv6()
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				buffs := make([][]byte, c.bind.BatchSize())
				for i := range buffs {
					buffs[i] = make([]byte, 2048)
				}
				receive(buffs, make([]int, len(buffs)), make([]conn.Endpoint, len(buffs)))
			}()
			t.Cleanup(func() {
				c.Close()
				<-done
			})

			shared := peerDisco.Shared(c.discoAtomic.Public())
			sendDisco := func(dst netip.AddrPort, m disco.Message) {
				t.Helper()
				msg := peerDisco.Public().AppendTo([]byte(disco.Magic))
				msg = append(msg, shared.Seal(m.AppendMarshal(nil))...)
				if _, err := peer.WriteToUDPAddrPort(msg, dst); err != nil {
					t.Fatal(err)
				}
			}
			seenPongs := make(map[stun.TxID]netip.AddrPort)
			read := func() ([]byte, netip.AddrPort, disco.Message) {
				t.Helper()
				peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				for {
					buf := make([]byte, 2048)
					n, from, err := peer.ReadFromUDPAddrPort(buf)
					if err != nil {
						t.Fatal(err)
					}
					buf = buf[:n]
					if !disco.LooksLikeDiscoWrapper(buf) {
						return buf, from, nil
					}
					payload, ok := shared.Open(buf[discoHeaderLen:])
					if !ok {
						t.Fatal("could not decrypt disco message")
					}
					m, err := disco.Parse(payload)
					if err != nil {
						t.Fatal(err)
					}
					// Raw and UDP receivers can both answer the same probe.
					if pong, ok := m.(*disco.Pong); ok {
						if prev, seen := seenPongs[pong.TxID]; seen {
							if prev != from {
								t.Errorf("duplicate pong from %v, first reply from %v", from, prev)
							}
							continue
						}
						seenPongs[pong.TxID] = from
					}
					return buf, from, m
				}
			}

			// Probe both addresses before reading either response, so an
			// address remembered globally for the remote socket is insufficient.
			pending := make(map[stun.TxID]netip.AddrPort)
			for _, ip := range tc.localIPs[:2] {
				dst := netip.AddrPortFrom(netip.MustParseAddr(ip), ruc.Port())
				ping := &disco.Ping{TxID: stun.NewTxID()}
				pending[ping.TxID] = dst
				sendDisco(dst, ping)
			}
			for range 2 {
				_, from, m := read()
				pong, ok := m.(*disco.Pong)
				if !ok {
					t.Fatalf("reply = %v, want pong", m)
				}
				if dst := pending[pong.TxID]; from != dst {
					t.Errorf("ping to %v: reply from %v", dst, from)
				}
				delete(pending, pong.TxID)
			}

			c.mu.Lock()
			ep, _ := c.peerMap.endpointForNodeKey(peerKey)
			c.mu.Unlock()
			for _, ip := range tc.localIPs {
				dst := netip.AddrPortFrom(netip.MustParseAddr(ip), ruc.Port())
				ping := &disco.Ping{TxID: stun.NewTxID()}
				sendDisco(dst, ping)
				_, from, m := read()
				if from != dst {
					t.Errorf("ping to %v: reply from %v", dst, from)
				}
				pong, ok := m.(*disco.Pong)
				if !ok || pong.TxID != ping.TxID {
					t.Fatalf("reply = %v, want pong for %v", m, ping.TxID)
				}

				// The reciprocal probe and selected data path must keep the same
				// local address, rather than consulting the default route again.
				ep.mu.Lock()
				ep.clearBestAddrLocked()
				ep.startDiscoPingLocked(epAddr{ap: peer.LocalAddr().(*net.UDPAddr).AddrPort()}, mono.Now(), pingDiscovery, 0, nil)
				ep.mu.Unlock()
				_, from, m = read()
				if from != dst {
					t.Errorf("probe from %v, want %v", from, dst)
				}
				probe, ok := m.(*disco.Ping)
				if !ok {
					t.Fatal("expected reciprocal ping")
				}
				sendDisco(dst, &disco.Pong{TxID: probe.TxID, Src: dst})
				if err := tstest.WaitFor(time.Second, func() error {
					ep.mu.Lock()
					defer ep.mu.Unlock()
					if ep.bestAddr.localIP != dst.Addr() {
						return fmt.Errorf("best local address = %v, want %v", ep.bestAddr.localIP, dst.Addr())
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, count := range []int{1, 8} {
					buffs := make([][]byte, count)
					for i := range buffs {
						buffs[i] = make([]byte, packet.GeneveFixedHeaderLength+128)
						buffs[i][packet.GeneveFixedHeaderLength] = 4 // WireGuard transport message
					}
					if err := c.Send(buffs, ep, packet.GeneveFixedHeaderLength); err != nil {
						t.Fatal(err)
					}
					for i := range count {
						got, from, _ := read()
						if from != dst {
							t.Errorf("data from %v, want %v", from, dst)
						}
						if !bytes.Equal(got, buffs[i][packet.GeneveFixedHeaderLength:]) {
							t.Fatalf("data packet = %x, want %x", got, buffs[i][packet.GeneveFixedHeaderLength:])
						}
					}
				}
			}
		})
	}
}

func TestParseUDPPacket(t *testing.T) {
	src4 := netip.MustParseAddrPort("127.0.0.1:12345")
	dst4 := netip.MustParseAddrPort("127.0.0.2:54321")

	src6 := netip.MustParseAddrPort("[::1]:12345")
	dst6 := netip.MustParseAddrPort("[::2]:54321")

	udp4Packet := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01, // source ip
		0x7f, 0x00, 0x00, 0x02, // dest ip

		// UDP header
		0x30, 0x39, // src port
		0xd4, 0x31, // dest port
		0x00, 0x12, // length; 8 bytes header + 10 bytes payload = 18 bytes
		0x00, 0x00, // checksum; unused

		// Payload: disco magic plus 4 bytes
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x00, 0x01, 0x02, 0x03,
	}
	udp6Packet := []byte{
		// IPv6 header
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x12, // payload length
		0x11, // next header: UDP
		0x00, // hop limit; unused

		// Source IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Dest IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,

		// UDP header
		0x30, 0x39, // src port
		0xd4, 0x31, // dest port
		0x00, 0x12, // length; 8 bytes header + 10 bytes payload = 18 bytes
		0x00, 0x00, // checksum; unused

		// Payload: disco magic plus 4 bytes
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x00, 0x01, 0x02, 0x03,
	}

	// Verify that parsing the UDP packet works correctly.
	t.Run("IPv4", func(t *testing.T) {
		src, dst, payload := parseUDPPacket(udp4Packet, false)
		if src != src4 {
			t.Errorf("src = %v; want %v", src, src4)
		}
		if dst != dst4 {
			t.Errorf("dst = %v; want %v", dst, dst4)
		}
		if !bytes.HasPrefix(payload, []byte(disco.Magic)) {
			t.Errorf("payload = %x; must start with %x", payload, disco.Magic)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		src, dst, payload := parseUDPPacket(udp6Packet, true)
		if src != src6 {
			t.Errorf("src = %v; want %v", src, src6)
		}
		if dst != dst6 {
			t.Errorf("dst = %v; want %v", dst, dst6)
		}
		if !bytes.HasPrefix(payload, []byte(disco.Magic)) {
			t.Errorf("payload = %x; must start with %x", payload, disco.Magic)
		}
	})
	t.Run("Truncated", func(t *testing.T) {
		truncateBy := func(b []byte, n int) []byte {
			if n >= len(b) {
				return nil
			}
			return b[:len(b)-n]
		}

		src, dst, payload := parseUDPPacket(truncateBy(udp4Packet, 11), false)
		if payload != nil {
			t.Errorf("payload = %x; want nil", payload)
		}
		if src.IsValid() || dst.IsValid() {
			t.Errorf("src = %v, dst = %v; want invalid", src, dst)
		}

		src, dst, payload = parseUDPPacket(truncateBy(udp6Packet, 11), true)
		if payload != nil {
			t.Errorf("payload = %x; want nil", payload)
		}
		if src.IsValid() || dst.IsValid() {
			t.Errorf("src = %v, dst = %v; want invalid", src, dst)
		}
	})
}

func TestEthernetProto(t *testing.T) {
	htons := func(x uint16) int {
		// Network byte order is big-endian; write the value as
		// big-endian to a byte slice and read it back in the native
		// endian-ness. This is a no-op on a big-endian platform and a
		// byte swap on a little-endian platform.
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], x)
		return int(binary.NativeEndian.Uint16(b[:]))
	}

	if v4 := ethernetProtoIPv4(); v4 != htons(unix.ETH_P_IP) {
		t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, htons(unix.ETH_P_IP))
	}
	if v6 := ethernetProtoIPv6(); v6 != htons(unix.ETH_P_IPV6) {
		t.Errorf("ethernetProtoIPv6 = 0x%04x; want 0x%04x", v6, htons(unix.ETH_P_IPV6))
	}

	// As a way to verify that the htons function is working correctly,
	// assert that the ETH_P_IP value returned from our function matches
	// the value defined in the unix package based on whether the host is
	// big-endian (network byte order) or little-endian.
	if cpu.IsBigEndian {
		if v4 := ethernetProtoIPv4(); v4 != unix.ETH_P_IP {
			t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, unix.ETH_P_IP)
		}
	} else {
		if v4 := ethernetProtoIPv4(); v4 == unix.ETH_P_IP {
			t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, htons(unix.ETH_P_IP))
		} else {
			t.Logf("ethernetProtoIPv4 = 0x%04x, correctly different from 0x%04x", v4, unix.ETH_P_IP)
		}
	}
}

func TestBpfDiscardV4(t *testing.T) {
	// Good packet as a reference for what should not be rejected
	udp4Packet := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01, // source ip
		0x7f, 0x00, 0x00, 0x02, // dest ip

		// UDP header
		0x30, 0x39, // src port
		0xd4, 0x31, // dest port
		0x00, 0x12, // length; 8 bytes header + 10 bytes payload = 18 bytes
		0x00, 0x00, // checksum; unused

		// Payload: disco magic plus 32 bytes for key and 24 bytes for nonce
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}

	vm, err := bpf.NewVM(magicsockFilterV4)
	if err != nil {
		t.Fatalf("failed creating BPF VM: %v", err)
	}

	tests := []struct {
		name    string
		replace map[int]byte
		accept  bool
	}{
		{
			name:    "base-accepted-datagram",
			replace: map[int]byte{},
			accept:  true,
		},
		{
			name: "more-fragments",
			replace: map[int]byte{
				6: 0x20,
			},
			accept: false,
		},
		{
			name: "some-fragment",
			replace: map[int]byte{
				7: 0x01,
			},
			accept: false,
		},
	}

	udp4PacketChanged := make([]byte, len(udp4Packet))
	copy(udp4PacketChanged, udp4Packet)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.replace {
				udp4PacketChanged[k] = v
			}
			ret, err := vm.Run(udp4PacketChanged)
			if err != nil {
				t.Fatalf("BPF VM error: %v", err)
			}

			if (ret != 0) != tt.accept {
				t.Errorf("expected accept=%v, got ret=%v", tt.accept, ret)
			}
		})
	}
}
