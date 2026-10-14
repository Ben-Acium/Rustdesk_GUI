package rendezvous

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// TestEncodeFrameHeaderBoundaries pins the BytesCodec header layout at every
// size transition: (len << 2) | marker, little-endian, marker = headerLen - 1.
func TestEncodeFrameHeaderBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		payload  int
		wantHead string // hex
	}{
		{"empty", 0, "00"},
		{"one byte", 1, "04"},
		{"max 1-byte header", 0x3F, "fc"},
		{"first 2-byte header", 0x40, "0101"},
		{"max 2-byte header", 0x3FFF, "fdff"},
		{"first 3-byte header", 0x4000, "020001"},
		{"max 3-byte header", 0x3FFFFF, "feffff"},
		{"first 4-byte header", 0x400000, "03000001"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeFrame(make([]byte, tc.payload))
			if err != nil {
				t.Fatalf("encodeFrame: %v", err)
			}
			wantHead, err := hex.DecodeString(tc.wantHead)
			if err != nil {
				t.Fatalf("bad test fixture: %v", err)
			}
			if !bytes.Equal(got[:len(wantHead)], wantHead) {
				t.Errorf("header = %x, want %x", got[:len(wantHead)], wantHead)
			}
			if len(got) != len(wantHead)+tc.payload {
				t.Errorf("frame length = %d, want %d", len(got), len(wantHead)+tc.payload)
			}
			// The marker in the low two bits must equal headerLen-1.
			if marker := int(got[0]&0x3) + 1; marker != len(wantHead) {
				t.Errorf("header length marker = %d, want %d", marker, len(wantHead))
			}
		})
	}
}

func TestFrameRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 0x3F, 0x40, 0x3FFF, 0x4000, 70000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		frame, err := encodeFrame(payload)
		if err != nil {
			t.Fatalf("size %d: encodeFrame: %v", size, err)
		}
		got, err := readFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("size %d: readFrame: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size %d: round trip mismatch", size)
		}
	}
}

// Two frames back to back must decode independently, since the poller reuses a
// single connection across chunks.
func TestReadFrameSequential(t *testing.T) {
	a, _ := encodeFrame([]byte("first"))
	b, _ := encodeFrame(bytes.Repeat([]byte("x"), 300))
	r := bytes.NewReader(append(a, b...))

	got1, err := readFrame(r)
	if err != nil || string(got1) != "first" {
		t.Fatalf("frame 1 = %q, %v", got1, err)
	}
	got2, err := readFrame(r)
	if err != nil || len(got2) != 300 {
		t.Fatalf("frame 2 len = %d, %v", len(got2), err)
	}
	if _, err := readFrame(r); err != io.EOF {
		t.Errorf("third read = %v, want EOF", err)
	}
}

func TestReadFrameRejectsAbsurdLength(t *testing.T) {
	// Claim a ~1GB payload with a 4-byte header and supply nothing.
	frame := []byte{0x03, 0xff, 0xff, 0xff}
	if _, err := readFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("expected refusal of oversized frame, got nil")
	}
}

// TestEncodeOnlineRequestBytes pins the exact protobuf encoding, so a change in
// field numbers or wire types fails here rather than silently returning
// "everything offline" against a real server.
func TestEncodeOnlineRequestBytes(t *testing.T) {
	frame, err := encodeOnlineRequest("me", []string{"123456789"})
	if err != nil {
		t.Fatalf("encodeOnlineRequest: %v", err)
	}

	// Inner OnlineRequest: field 1 (string id) = "me", field 2 (string peers) = "123456789".
	//   0x0a 0x02 "me"  |  0x12 0x09 "123456789"
	inner := append([]byte{0x0a, 0x02}, []byte("me")...)
	inner = append(inner, append([]byte{0x12, 0x09}, []byte("123456789")...)...)

	// RendezvousMessage field 23, wire type 2 -> key = 23<<3|2 = 186 -> varint 0xba 0x01.
	msg := append([]byte{0xba, 0x01, byte(len(inner))}, inner...)
	want := append([]byte{byte(len(msg) << 2)}, msg...)

	if !bytes.Equal(frame, want) {
		t.Errorf("frame  = %x\nwant   = %x", frame, want)
	}
}

func TestDecodeOnlineResponse(t *testing.T) {
	// OnlineResponse { states = 0xA0 }: field 1, wire type 2.
	inner := []byte{0x0a, 0x01, 0xA0}
	// RendezvousMessage field 24 -> key = 24<<3|2 = 194 -> varint 0xc2 0x01.
	msg := append([]byte{0xc2, 0x01, byte(len(inner))}, inner...)

	states, ok, err := decodeOnlineResponse(msg)
	if err != nil || !ok {
		t.Fatalf("decodeOnlineResponse: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(states, []byte{0xA0}) {
		t.Errorf("states = %x, want a0", states)
	}
}

// A different member of the oneof must be reported as "not an OnlineResponse"
// rather than as an error, so the client keeps reading.
func TestDecodeOnlineResponseIgnoresOtherMessages(t *testing.T) {
	// ConfigUpdate is field 14 -> key = 14<<3|2 = 114 -> single varint byte 0x72.
	msg := []byte{0x72, 0x00}
	states, ok, err := decodeOnlineResponse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok || states != nil {
		t.Errorf("ok=%v states=%x, want false/nil", ok, states)
	}
}

// Unknown fields of every wire type must be skipped cleanly.
func TestDecodeOnlineResponseSkipsUnknownFields(t *testing.T) {
	var msg []byte
	msg = append(msg, 0x08, 0x96, 0x01)             // field 1 varint
	msg = append(msg, 0x15, 0x01, 0x02, 0x03, 0x04) // field 2 fixed32
	msg = append(msg, 0x19, 1, 2, 3, 4, 5, 6, 7, 8) // field 3 fixed64
	inner := []byte{0x0a, 0x02, 0xFF, 0x01}         // OnlineResponse states = FF 01
	msg = append(msg, 0xc2, 0x01, byte(len(inner)))
	msg = append(msg, inner...)

	states, ok, err := decodeOnlineResponse(msg)
	if err != nil || !ok {
		t.Fatalf("decodeOnlineResponse: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(states, []byte{0xFF, 0x01}) {
		t.Errorf("states = %x, want ff01", states)
	}
}

// TestStatesToBools pins the MSB-first bit order, including a peer count that
// is not a multiple of eight.
func TestStatesToBools(t *testing.T) {
	cases := []struct {
		name   string
		states []byte
		count  int
		want   []bool
	}{
		{"first peer online", []byte{0x80}, 1, []bool{true}},
		{"first peer offline", []byte{0x00}, 1, []bool{false}},
		{"alternating", []byte{0xAA}, 8, []bool{true, false, true, false, true, false, true, false}},
		{"all online", []byte{0xFF}, 8, func() []bool {
			b := make([]bool, 8)
			for i := range b {
				b[i] = true
			}
			return b
		}()},
		{"spans two bytes, ragged count", []byte{0x01, 0x80}, 9,
			[]bool{false, false, false, false, false, false, false, true, true}},
		{"ignores padding bits", []byte{0xFF}, 3, []bool{true, true, true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := statesToBools(tc.states, tc.count)
			if err != nil {
				t.Fatalf("statesToBools: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("peer %d = %v, want %v (states %x)", i, got[i], tc.want[i], tc.states)
				}
			}
		})
	}
}

func TestStatesToBoolsRejectsShortBitmask(t *testing.T) {
	if _, err := statesToBools([]byte{0xFF}, 9); err == nil {
		t.Fatal("expected error for bitmask shorter than peer count")
	}
}
