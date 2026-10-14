package rendezvous

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DefaultChunkSize caps how many peer IDs go into a single OnlineRequest.
// The server imposes no limit, but smaller requests keep each frame well inside
// the codec's 2-byte header range and bound the blast radius of a malformed reply.
const DefaultChunkSize = 128

// DefaultSelfID is sent as OnlineRequest.id. The OSS server ignores this field.
const DefaultSelfID = "rustdeskgui"

// Client queries an hbbs rendezvous server for peer presence.
type Client struct {
	// Addr is the hbbs NAT port, host:port. For a default server this is the
	// base rendezvous port minus one, i.e. 21115.
	Addr string

	// Timeout bounds a full query: dial, write and read.
	Timeout time.Duration

	// ChunkSize overrides DefaultChunkSize when non-zero.
	ChunkSize int

	// SelfID overrides DefaultSelfID when non-empty.
	SelfID string
}

// Online reports, for each ID in peers, whether hbbs has seen it register within
// its REG_TIMEOUT window (30s). The result is parallel to peers.
//
// All chunks share one TCP connection; the server's handler loops, so it will
// answer several requests in sequence.
func (c *Client) Online(ctx context.Context, peers []string) ([]bool, error) {
	if len(peers) == 0 {
		return nil, nil
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	chunk := c.ChunkSize
	if chunk <= 0 {
		chunk = DefaultChunkSize
	}
	selfID := c.SelfID
	if selfID == "" {
		selfID = DefaultSelfID
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("rendezvous: dial %s: %w", c.Addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	out := make([]bool, 0, len(peers))
	for start := 0; start < len(peers); start += chunk {
		end := min(start+chunk, len(peers))
		batch := peers[start:end]

		states, err := c.exchange(conn, selfID, batch)
		if err != nil {
			return nil, err
		}
		bools, err := statesToBools(states, len(batch))
		if err != nil {
			return nil, err
		}
		out = append(out, bools...)
	}
	return out, nil
}

// exchange sends one OnlineRequest and reads until the matching OnlineResponse
// arrives, skipping any other message the server happens to emit first.
func (c *Client) exchange(conn net.Conn, selfID string, batch []string) ([]byte, error) {
	frame, err := encodeOnlineRequest(selfID, batch)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("rendezvous: write request: %w", err)
	}

	// Bound the skip loop so an unexpected chatty server cannot spin us forever.
	for attempt := 0; attempt < 8; attempt++ {
		payload, err := readFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("rendezvous: %s closed the connection without replying; "+
					"this is what hbbs does when the request reaches the wrong port "+
					"(use the NAT port, the rendezvous port minus one) or comes from loopback: %w",
					c.Addr, err)
			}
			return nil, fmt.Errorf("rendezvous: read response: %w", err)
		}
		states, ok, err := decodeOnlineResponse(payload)
		if err != nil {
			return nil, fmt.Errorf("rendezvous: decode response: %w", err)
		}
		if ok {
			return states, nil
		}
	}
	return nil, fmt.Errorf("rendezvous: no OnlineResponse from %s", c.Addr)
}
