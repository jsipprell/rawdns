package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
)

type dockerPortMapping struct {
	IpAddress string `json:"HostIp"`
	Port      string `json:"HostPort"`
}

type dockerClient struct {
	sync.Mutex

	Transport *http.Transport
}

type dockerContainer struct {
	Id              string
	Name            string
	PublicIpAddress net.IP `json:"-"`

	NetworkSettings struct {
		Bridge      string
		Gateway     string
		IpAddress   string `json:"IPAddress"`
		IpPrefixLen int    `json:"IPPrefixLen"`
		MacAddress  string
		// TODO Ports ?
		Ports map[string][]dockerPortMapping
	}

	State struct {
		Dead       bool
		Error      string
		ExitCode   int
		Paused     bool
		Restarting bool
		StartedAt  string
		Running    bool
	}

	Config struct {
		Labels map[string]string
	}
}

var (
	commonClient = new(dockerClient)
	dockerDebug  bool
)

type infoMap map[string]interface{}

type cleanupDockerConnection struct {
	m    sync.Mutex
	conn io.ReadCloser
}

func init() {
	if os.Getenv("DOCKER_DEBUG") != "" {
		dockerDebug = true
	}
}

func (c *cleanupDockerConnection) Close() error {
	c.m.Lock()
	defer c.m.Unlock()
	rc := c.conn
	c.conn = nil
	if rc != nil {
		io.Copy(ioutil.Discard, rc)
		return rc.Close()
	}
	return nil
}

func dockerInspectContainers(dockerHost string, filters map[string][]string) (<-chan *dockerContainer, error) {
	cleanup := new(cleanupDockerConnection)

	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u)

	params := make(url.Values)
	u.Path = "/v1.18/containers/json"
	if len(filters) > 0 {
		b, err := json.Marshal(filters)
		if err != nil {
			return nil, err
		}

		params.Set("filters", string(b))
		u.RawQuery = params.Encode()
	}

	if dockerDebug {
		log.Printf("URL = %#v", u)
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		cleanup.conn = resp.Body
		defer cleanup.Close()
	}

	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}

	infos := make([]infoMap, 0)
	if err = json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("no containers found for %#v", u.String())
	}
	C := make(chan *dockerContainer, 20)
	go func() {
		defer resp.Body.Close()
		defer close(C)
		//log.Printf("INFOS: %#v", infos)
		for _, info := range infos {
			if names, ok := info["Names"].([]interface{}); ok && len(names) > 0 {
				for _, name := range names {
					if n, ok := name.(string); ok {
						var publicIP net.IP
						if ports, ok := info["Ports"].([]interface{}); ok && len(ports) > 0 {
							for i, _ := range ports {
								pcfg := ports[i].(map[string]interface{})
								if s := pcfg["IP"].(string); s != "" {
									if publicIP = net.ParseIP(s); publicIP != nil {
										break
									}
								}
							}
						}
						container, err := dockerInspectContainer(dockerHost, n)
						if err == nil {
							if len(publicIP) > 0 {
								container.PublicIpAddress = make(net.IP, len(publicIP))
								copy(container.PublicIpAddress, publicIP)
							}
							C <- container
							break
						}
					}
				}
			}
		}
	}()

	cleanup.conn = nil
	return C, err
}

func dockerInspectContainer(dockerHost, containerName string) (*dockerContainer, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL '%s': %v", dockerHost, err)
	}
	client := httpClient(u)
	req, err := http.NewRequest("GET", u.String()+"/v1.18/containers/"+containerName+"/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("not '200 OK': %v", resp.Status)
	}
	ret := dockerContainer{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JSON response: %v", err)
	}
	return &ret, nil
}

func httpClient(u *url.URL) *http.Client {
	var newTransport bool
	commonClient.Lock()
	defer commonClient.Unlock()
	if commonClient.Transport == nil {
		commonClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
		newTransport = true
	}
	switch u.Scheme {
	case "tcp":
		if tlsConfig == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}

	case "unix":
		path := u.Path
		if newTransport {
			commonClient.Transport.Dial = func(proto, addr string) (net.Conn, error) {
				return net.Dial("unix", path)
			}
		}
		u.Scheme = "http"
		u.Host = "unix-socket"
		u.Path = ""
	}
	return &http.Client{Transport: commonClient.Transport}
}
