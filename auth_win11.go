package winrm

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/siemens-cdc/winrm/soap"
)

// ClientAuthRequestWin11 ClientAuthRequestWin11
type ClientAuthRequestWin11 struct {
	transport http.RoundTripper
	dial      func(network, addr string) (net.Conn, error)
}

// Transport Transport
func (c *ClientAuthRequestWin11) Transport(endpoint *Endpoint) error {
	cert, err := tls.X509KeyPair(endpoint.Cert, endpoint.Key)
	if err != nil {
		return err
	}

	dial := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial

	if c.dial != nil {
		dial = c.dial
	}

	//nolint:gosec
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: endpoint.Insecure,
			Certificates:       []tls.Certificate{cert},
			MaxVersion:         tls.VersionTLS12,
			MinVersion:         tls.VersionTLS10,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			//0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0xc012, 0x000a, 0x1301, 0x1302, 0x1303
			//CipherSuites: []uint16{0x002f, 0x0035},
		},
		Dial:                  dial,
		ResponseHeaderTimeout: endpoint.Timeout,
	}

	if endpoint.CACert != nil && len(endpoint.CACert) > 0 {
		certPool, err := readCACerts(endpoint.CACert)
		if err != nil {
			return err
		}

		transport.TLSClientConfig.RootCAs = certPool
	}

	c.transport = transport

	return nil
}

// parseWin11 func reads the response body and return it as a string
func parseWin11(response *http.Response) (string, error) {
	// if we received the content we expected
	if strings.Contains(response.Header.Get("Content-Type"), "application/soap+xml") {
		body, err := io.ReadAll(response.Body)
		defer func() {
			// defer can modify the returned value before
			// it is actually passed to the calling statement
			if errClose := response.Body.Close(); errClose != nil && err == nil {
				err = errClose
			}
		}()
		if err != nil {
			return "", fmt.Errorf("error while reading request body %w", err)
		}

		return string(body), nil
	}

	return "", fmt.Errorf("invalid content type")
}

// Post Post
func (c ClientAuthRequestWin11) Post(client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport}

	req, err := http.NewRequest("POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create Http request %w", err)
	}

	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.Header.Set("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %w", err)
	}

	body, err := parseWin11(resp)
	if err != nil {
		return "", fmt.Errorf("Http response error: %d - %w", resp.StatusCode, err)
	}

	// if we have different 200 Http status code
	// we must replace the error
	defer func() {
		if resp.StatusCode != 200 {
			body, err = "", fmt.Errorf("Http error %d: %s", resp.StatusCode, body)
		}
	}()

	return body, err
}

// NewClientAuthRequestWithDialWin11 NewClientAuthRequestWithDialWin11
func NewClientAuthRequestWithDialWin11(dial func(network, addr string) (net.Conn, error)) *ClientAuthRequestWin11 {
	return &ClientAuthRequestWin11{
		dial: dial,
	}
}
