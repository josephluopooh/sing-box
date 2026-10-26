package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type sshTestEndpoint struct {
	adapter.Endpoint
	address string
}

func (e *sshTestEndpoint) Type() string { return C.TypeTailscale }

func (e *sshTestEndpoint) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", e.address)
}

type sshTestEndpointManager struct {
	adapter.EndpointManager
	endpoint adapter.Endpoint
}

func (m *sshTestEndpointManager) Get(string) (adapter.Endpoint, bool) { return m.endpoint, true }

type sshTestStream struct {
	grpc.ServerStream
	ctx      context.Context
	start    *TailscaleSSHStart
	messages []*TailscaleSSHServerMessage
}

func (s *sshTestStream) Context() context.Context { return s.ctx }

func (s *sshTestStream) Recv() (*TailscaleSSHClientMessage, error) {
	return &TailscaleSSHClientMessage{Message: &TailscaleSSHClientMessage_Start{Start: s.start}}, nil
}

func (s *sshTestStream) Send(message *TailscaleSSHServerMessage) error {
	s.messages = append(s.messages, message)
	return nil
}

func TestTailscaleSSHAuthenticationBanners(t *testing.T) {
	const approval = "Open https://approval.example.test/ssh to authorize this session"
	const denied = "tailnet policy does not permit you to SSH to this node"
	for _, test := range []struct {
		name       string
		first      string
		last       string
		want       string
		untrusted  bool
		wantPrefix string
	}{
		{name: "approval before denial", first: approval, last: denied, want: approval + "\n" + denied},
		{name: "blank later banner", first: approval, last: " \n", want: approval},
		{name: "duplicate banner", first: approval, last: approval, want: approval},
		{name: "single banner", last: denied, want: denied},
		{name: "no banner", wantPrefix: "ssh handshake:"},
		{name: "untrusted key", first: approval, untrusted: true, wantPrefix: "ssh handshake:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			serverConfig := &ssh.ServerConfig{
				NoClientAuth: true,
				BannerCallback: func(ssh.ConnMetadata) string {
					return test.first
				},
				NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
					return nil, &ssh.BannerError{Err: errors.New("authorization denied"), Message: test.last}
				},
			}
			serverConfig.AddHostKey(signer)
			serverDone := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					serverDone <- acceptErr
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _, _, handshakeErr := ssh.NewServerConn(conn, serverConfig)
				serverDone <- handshakeErr
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			endpointManager := &sshTestEndpointManager{endpoint: &sshTestEndpoint{address: listener.Addr().String()}}
			ctx = service.ContextWith[adapter.EndpointManager](ctx, endpointManager)
			startedService := &StartedService{
				serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
				instance:      &Instance{ctx: ctx},
			}
			stream := &sshTestStream{ctx: ctx, start: &TailscaleSSHStart{Username: "test", PeerAddress: "127.0.0.1", EndpointTag: "test"}}
			if !test.untrusted {
				stream.start.HostKeys = []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
			}
			if err := startedService.StartTailscaleSSHSession(stream); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-serverDone:
				if err == nil {
					t.Fatal("server unexpectedly authenticated the client")
				}
			case <-ctx.Done():
				t.Fatal("SSH server did not finish")
			}
			if len(stream.messages) == 0 {
				t.Fatal("no terminal message was sent")
			}
			final := stream.messages[len(stream.messages)-1].GetError()
			if final == nil {
				t.Fatal("session did not end with an error message")
			}
			if test.wantPrefix != "" {
				if !strings.HasPrefix(final.Message, test.wantPrefix) {
					t.Errorf("final message = %q, want prefix %q", final.Message, test.wantPrefix)
				}
			} else if final.Message != test.want {
				t.Errorf("final message = %q, want %q", final.Message, test.want)
			}
			var wantBanners []string
			if !test.untrusted {
				for _, banner := range []string{test.first, test.last} {
					if banner != "" {
						wantBanners = append(wantBanners, banner)
					}
				}
			}
			if len(stream.messages)-1 != len(wantBanners) {
				t.Fatalf("got %d real-time banners, want %d", len(stream.messages)-1, len(wantBanners))
			}
			for i, want := range wantBanners {
				if got := stream.messages[i].GetAuthBanner(); got == nil || got.Message != want {
					t.Errorf("real-time banner %d = %v, want %q", i, got, want)
				}
			}
		})
	}
}
