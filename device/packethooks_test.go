/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// setIPv4Addr writes addr at off (12 for the source, 16 for the destination)
// and recomputes the header checksum.
func setIPv4Addr(pkt []byte, off int, addr netip.Addr) {
	a := addr.As4()
	copy(pkt[off:off+4], a[:])
	pkt[10], pkt[11] = 0, 0
	ihl := int(pkt[0]&0x0f) * 4
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum))
}

// A peer reached at a stand-in address: dev0 knows dev1 as 9.9.9.2 only,
// and the hooks swap that for dev1's own address 1.0.0.2 both ways.
func TestPacketHooksRewriteAndDrop(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false)
	dev0 := pair[0].dev

	var peerKey NoisePublicKey
	dev0.peers.RLock()
	for k := range dev0.peers.keyMap {
		peerKey = k
	}
	dev0.peers.RUnlock()
	if err := dev0.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(peerKey[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", "9.9.9.2/32",
	)); err != nil {
		t.Fatal(err)
	}

	stand := netip.MustParseAddr("9.9.9.2")
	real := pair[1].ip
	var dropIn atomic.Bool
	var seenOut, seenIn atomic.Int32
	dev0.SetPacketHooks(&PacketHooks{
		Outbound: func(peer NoisePublicKey, pkt []byte) bool {
			if peer != peerKey || pkt[0]>>4 != 4 {
				return false
			}
			seenOut.Add(1)
			setIPv4Addr(pkt, 16, real)
			return true
		},
		Inbound: func(peer NoisePublicKey, pkt []byte) bool {
			if peer != peerKey || pkt[0]>>4 != 4 || dropIn.Load() {
				return false
			}
			seenIn.Add(1)
			setIPv4Addr(pkt, 12, stand)
			return true
		},
	})

	expect := func(t *testing.T, ch chan []byte, want []byte) {
		t.Helper()
		select {
		case got := <-ch:
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("packet did not arrive")
		}
	}

	t.Run("out", func(t *testing.T) {
		pair[0].tun.Outbound <- tuntest.Ping(stand, pair[0].ip)
		want := tuntest.Ping(real, pair[0].ip)
		setIPv4Addr(want, 16, real) // the checksum as the hook computes it
		expect(t, pair[1].tun.Inbound, want)
	})
	t.Run("in", func(t *testing.T) {
		pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, real)
		want := tuntest.Ping(pair[0].ip, stand)
		setIPv4Addr(want, 12, stand)
		expect(t, pair[0].tun.Inbound, want)
	})
	t.Run("in dropped", func(t *testing.T) {
		dropIn.Store(true)
		pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, real)
		select {
		case got := <-pair[0].tun.Inbound:
			t.Fatalf("dropped packet arrived: %x", got)
		case <-time.After(300 * time.Millisecond):
		}
	})
	if seenOut.Load() == 0 || seenIn.Load() == 0 {
		t.Fatalf("hooks not called: out=%d in=%d", seenOut.Load(), seenIn.Load())
	}
	dev0.SetPacketHooks(nil)
}
