package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
)

type udpReadConn struct {
	net.Conn
	read func([]byte) (int, error)
}

func (c *udpReadConn) Read(p []byte) (int, error) {
	return c.read(p)
}

func TestUDPTransportReadResponse(t *testing.T) {
	response := new(mDNS.Msg)
	response.SetQuestion("example.test.", mDNS.TypeA)
	response.Response = true
	valid, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		data      []byte
		wantErr   error
		wantReply bool
	}{
		{name: "empty", wantErr: io.ErrUnexpectedEOF},
		{name: "malformed", data: []byte{1, 2, 3}},
		{name: "valid", data: valid, wantReply: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &UDPTransport{logger: log.NewNOPFactory().Logger()}
			transport.udpSize.Store(2048)
			conn := &udpReadConn{read: func(p []byte) (int, error) {
				return copy(p, test.data), nil
			}}
			got, err := transport.readResponse(conn)
			if !errors.Is(err, test.wantErr) {
				t.Errorf("readResponse error = %v, want %v", err, test.wantErr)
			}
			if (got != nil) != test.wantReply {
				t.Fatalf("readResponse = %v, want reply %v", got, test.wantReply)
			}
			if got != nil && (got.Id != response.Id || got.Question[0] != response.Question[0]) {
				t.Errorf("readResponse changed the reply: %v", got)
			}
		})
	}
}

type emptyUDPConn struct {
	net.Conn
	written   chan struct{}
	closed    chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
	reads     atomic.Int32
}

func (c *emptyUDPConn) Read([]byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.written:
	}
	// Bound the broken implementation's loop so a failed test cannot spin.
	if c.reads.Add(1) > 32 {
		return 0, errors.New("receive loop kept reading after an empty response")
	}
	return 0, nil
}

func (c *emptyUDPConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.written) })
	return len(p), nil
}

func (c *emptyUDPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestUDPTransportEmptyReadInvalidatesConnection(t *testing.T) {
	transport := &UDPTransport{logger: log.NewNOPFactory().Logger()}
	transport.udpSize.Store(2048)
	var conns []*emptyUDPConn
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(context.Context) (net.Conn, error) {
			conn := &emptyUDPConn{written: make(chan struct{}), closed: make(chan struct{})}
			conns = append(conns, conn)
			return conn, nil
		},
		write:    transport.writeQuery,
		readNext: transport.readResponse,
	})
	t.Cleanup(func() { _ = multiplexer.Close() })
	query := new(mDNS.Msg)
	query.SetQuestion("example.test.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := range 2 {
		_, err := multiplexer.Exchange(ctx, query)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("exchange %d: error = %v, want unexpected EOF", i, err)
		}
		if len(conns) != i+1 {
			t.Fatalf("exchange %d reused the invalid connection", i)
		}
		conn := conns[i]
		select {
		case <-conn.closed:
		case <-ctx.Done():
			t.Fatal("empty-read connection was not closed")
		}
		if got := conn.reads.Load(); got != 1 {
			t.Errorf("exchange %d: made %d reads, want one", i, got)
		}
	}
}
