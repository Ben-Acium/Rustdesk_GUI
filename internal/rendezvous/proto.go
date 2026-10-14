package rendezvous

import (
	"errors"
	"fmt"
)

// Protobuf field numbers from rustdesk/hbb_common/protos/rendezvous.proto.
//
//	message RendezvousMessage {
//	  oneof union { ... OnlineRequest online_request = 23;
//	                    OnlineResponse online_response = 24; ... }
//	}
//	message OnlineRequest  { string id = 1; repeated string peers = 2; }
//	message OnlineResponse { bytes states = 1; }
const (
	fieldOnlineRequest  = 23
	fieldOnlineResponse = 24

	fieldOnlineRequestID    = 1
	fieldOnlineRequestPeers = 2

	fieldOnlineResponseStates = 1
)

// Protobuf wire types.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

var errTruncated = errors.New("rendezvous: truncated protobuf message")

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// appendTag writes the key byte(s) for a field: (number << 3) | wireType.
func appendTag(b []byte, field, wireType int) []byte {
	return appendVarint(b, uint64(field)<<3|uint64(wireType))
}

// appendBytesField writes a length-delimited field.
func appendBytesField(b []byte, field int, val []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendVarint(b, uint64(len(val)))
	return append(b, val...)
}

func readVarint(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		if i > 9 {
			return 0, 0, errors.New("rendezvous: varint overflows 64 bits")
		}
		v |= uint64(b[i]&0x7F) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errTruncated
}

// encodeOnlineRequest builds a framed RendezvousMessage asking whether each of
// peers is currently online.
//
// selfID populates OnlineRequest.id. The OSS server's handle_online_request
// ignores it entirely (it reads only or.peers and performs no authentication),
// but the field is sent for protocol fidelity.
func encodeOnlineRequest(selfID string, peers []string) ([]byte, error) {
	var inner []byte
	inner = appendBytesField(inner, fieldOnlineRequestID, []byte(selfID))
	for _, p := range peers {
		inner = appendBytesField(inner, fieldOnlineRequestPeers, []byte(p))
	}

	var msg []byte
	msg = appendBytesField(msg, fieldOnlineRequest, inner)
	return encodeFrame(msg)
}

// decodeOnlineResponse pulls the states bitmask out of a RendezvousMessage
// payload. It returns (nil, false, nil) when the message is well-formed but
// carries some other member of the oneof, so callers can keep reading.
func decodeOnlineResponse(msg []byte) (states []byte, ok bool, err error) {
	err = walkFields(msg, func(field, wireType int, val []byte) error {
		if field != fieldOnlineResponse || wireType != wireBytes {
			return nil
		}
		inner := val
		return walkFields(inner, func(f, wt int, v []byte) error {
			if f == fieldOnlineResponseStates && wt == wireBytes {
				states = v
				ok = true
			}
			return nil
		})
	})
	if err != nil {
		return nil, false, err
	}
	return states, ok, nil
}

// walkFields iterates the top-level fields of a protobuf message, invoking fn
// for each. Unknown fields are skipped according to their wire type rather than
// treated as errors, so a server that adds fields later does not break us.
func walkFields(b []byte, fn func(field, wireType int, val []byte) error) error {
	for len(b) > 0 {
		key, n, err := readVarint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		field := int(key >> 3)
		wireType := int(key & 0x7)

		var val []byte
		switch wireType {
		case wireVarint:
			_, n, err := readVarint(b)
			if err != nil {
				return err
			}
			val, b = b[:n], b[n:]
		case wireFixed64:
			if len(b) < 8 {
				return errTruncated
			}
			val, b = b[:8], b[8:]
		case wireBytes:
			length, n, err := readVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if uint64(len(b)) < length {
				return errTruncated
			}
			val, b = b[:length], b[length:]
		case wireFixed32:
			if len(b) < 4 {
				return errTruncated
			}
			val, b = b[:4], b[4:]
		default:
			return fmt.Errorf("rendezvous: unsupported wire type %d for field %d", wireType, field)
		}

		if err := fn(field, wireType, val); err != nil {
			return err
		}
	}
	return nil
}

// statesToBools expands the response bitmask into one bool per requested peer,
// in request order.
//
// Upstream builds it as:
//
//	let states_idx = i / 8;
//	let bit_idx = 7 - i % 8;
//	states[states_idx] |= 0x01 << bit_idx;
//
// i.e. most-significant-bit-first within each byte.
func statesToBools(states []byte, count int) ([]bool, error) {
	if want := (count + 7) / 8; len(states) < want {
		return nil, fmt.Errorf("rendezvous: states bitmask is %d bytes, need %d for %d peers",
			len(states), want, count)
	}
	out := make([]bool, count)
	for i := 0; i < count; i++ {
		out[i] = states[i/8]&(0x01<<(7-uint(i%8))) != 0
	}
	return out, nil
}
