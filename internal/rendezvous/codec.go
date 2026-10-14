// Package rendezvous speaks the small subset of RustDesk's rendezvous protocol
// needed to ask an OSS hbbs server which peers are currently online.
//
// Two layers are involved:
//
//   - A framing codec (upstream: hbb_common/src/bytes_codec.rs) that prefixes
//     each payload with a little-endian length whose low two bits say how many
//     bytes the header itself occupies.
//   - A protobuf RendezvousMessage carrying OnlineRequest / OnlineResponse.
//
// Only two message types are needed, so they are hand-encoded here rather than
// taking on protoc as a build dependency. See proto.go.
package rendezvous

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// maxPayload is the largest frame the 4-byte header can describe.
const maxPayload = 0x3FFFFFFF

// maxAcceptedFrame bounds what we are willing to allocate for an inbound frame.
// Legitimate OnlineResponses are a few hundred bytes at most; this only guards
// against a malformed or hostile length prefix.
const maxAcceptedFrame = 1 << 20

var errFrameTooLarge = errors.New("rendezvous: frame exceeds maximum payload size")

// encodeFrame prepends the BytesCodec length header to payload.
//
// The header is a little-endian integer of 1-4 bytes holding (len << 2) | marker,
// where marker is the header length minus one. Upstream encode:
//
//	if data.len() <= 0x3F        { buf.put_u8((data.len() << 2) as u8) }
//	else if data.len() <= 0x3FFF { buf.put_u16_le((data.len() << 2) as u16 | 0x1) }
//	...
func encodeFrame(payload []byte) ([]byte, error) {
	n := len(payload)
	var head []byte

	switch {
	case n <= 0x3F:
		head = []byte{byte(n << 2)}
	case n <= 0x3FFF:
		head = make([]byte, 2)
		binary.LittleEndian.PutUint16(head, uint16(n<<2)|0x1)
	case n <= 0x3FFFFF:
		h := uint32(n<<2) | 0x2
		head = make([]byte, 3)
		binary.LittleEndian.PutUint16(head[:2], uint16(h&0xFFFF))
		head[2] = byte(h >> 16)
	case n <= maxPayload:
		head = make([]byte, 4)
		binary.LittleEndian.PutUint32(head, uint32(n<<2)|0x3)
	default:
		return nil, errFrameTooLarge
	}

	out := make([]byte, 0, len(head)+n)
	out = append(out, head...)
	out = append(out, payload...)
	return out, nil
}

// readFrame reads one length-prefixed frame and returns its payload.
//
// Upstream decode: head_len = ((src[0] & 0x3) + 1), then the header is read as a
// little-endian integer and shifted right by two to recover the payload length.
func readFrame(r io.Reader) ([]byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}

	headLen := int(first[0]&0x3) + 1
	head := make([]byte, 4) // zero-padded so we can always decode as uint32
	head[0] = first[0]
	if headLen > 1 {
		if _, err := io.ReadFull(r, head[1:headLen]); err != nil {
			return nil, fmt.Errorf("rendezvous: short frame header: %w", err)
		}
	}

	n := int(binary.LittleEndian.Uint32(head) >> 2)
	if n > maxAcceptedFrame {
		return nil, fmt.Errorf("rendezvous: refusing %d-byte frame (limit %d)", n, maxAcceptedFrame)
	}
	if n == 0 {
		return []byte{}, nil
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("rendezvous: short frame payload: %w", err)
	}
	return payload, nil
}
