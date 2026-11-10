/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// PacketHooks lets the user of a Device look at, rewrite or drop the IP
// packets it carries, knowing which peer each one belongs to.
//
// A hook may change the packet in place, but not its length. It is called
// on the device's packet path, concurrently with itself, and must not block.
type PacketHooks struct {
	// Outbound is called with a packet read from the TUN device once the
	// peer it goes to has been chosen by its destination address, and
	// before it is encrypted. Returning false drops the packet.
	Outbound func(peer NoisePublicKey, packet []byte) bool
	// Inbound is called with a packet received from peer and decrypted,
	// before its source address is checked against the peer's allowed IPs.
	// Returning false drops the packet.
	Inbound func(peer NoisePublicKey, packet []byte) bool
}

// SetPacketHooks installs hooks, replacing any installed before; nil
// removes them. It is safe to call at any time: packets already past the
// point a hook is called at are not seen by the new hooks.
func (device *Device) SetPacketHooks(hooks *PacketHooks) {
	device.packetHooks.Store(hooks)
}
