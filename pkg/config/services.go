package config

type SystemService struct {
	DHCP                 DHCPService
	DNS                  DNSService
	DynamicDNS           DynDNSService
	Finger               FingerService
	FTP                  FTPService
	NetConf              NetConfService
	OutboundSSH          OutSSHService
	ServiceDeployment    DeploymentService
	SSH                  SSHService
	SubscriberManagement SubscriberService
	Telnet               TelnetService
	TFPTServer           TFTPService
	WebManagement        WebMgmtService
	WebAPI               WebAPIService
	XNMClearText         XNMClearService
	XNMSSL               XNMSSLService
}

type DHCPService struct {
	Pools         []DHCPPool    `json:"pools,omitempty"`
	StaticBinding string        `json:"static-binding"`
	TraceOpts     DHCPTraceOpts `json:"trace-opts,omitempty"`
	DHCPGenerics
}

type DHCPTraceOpts struct {
	TraceOpts
	Flag DHCPTraceFlag `json:"flag,omitempty"`
}

type DHCPTraceFlag struct {
	All      bool `json:"all,omitempty"`
	Binding  bool `json:"binding,omitempty"`
	Client   bool `json:"client,omitempty"`
	Config   bool `json:"config,omitempty"`
	Conflict bool `json:"conflict,omitempty"`
	Event    bool `json:"event,omitempty"`
	Ifdb     bool `json:"ifdb,omitempty"`
	Io       bool `json:"io,omitempty"`
	Lease    bool `json:"lease,omitempty"`
	Main     bool `json:"main,omitempty"`
	Misc     bool `json:"misc,omitempty"`
	Option   bool `json:"option,omitempty"`
	Packet   bool `json:"packet,omitempty"`
	Pool     bool `json:"pool,omitempty"`
	Protocol bool `json:"protocol,omitempty"`
	Relay    bool `json:"relay,omitempty"`
	RTSock   bool `json:"rtsock,omitempty"`
	Scope    bool `json:"scope,omitempty"`
	Signal   bool `json:"signal,omitempty"`
	Trace    bool `json:"trace,omitempty"`
	UI       bool `json:"ui,omitempty"`
}

type DHCPPool struct {
	Network        string   `json:"network,omitempty"`
	Netmask        int      `json:"netmask,omitempty"`
	ExcludeAddress []string `json:"exclude-address,omitempty"`
	DHCPGenerics
}

type DHCPOption struct {
	OptID int
	Value string
}

type DHCPGenerics struct {
	Groups
	BootFile         string       `json:"boot-file,omitempty"`
	BootServer       string       `json:"boot-server,omitempty"`
	DefaultLeaseTime int          `json:"default-lease-time,omitempty"`
	DomainName       string       `json:"domain-name,omitempty"`
	DomainSearch     []string     `json:"domain-search,omitempty"`
	MaxLeaseTime     int          `json:"max-lease-time,omitempty"`
	NameServer       string       `json:"name-server,omitempty"`
	NextServer       string       `json:"next-server,omitempty"`
	DHCPOptions      []DHCPOption `json:"dhcp-options,omitempty"`
	PropPPPSettings  string       `json:"propagate-ppp-settings,omitempty"`
	PropSettings     string       `json:"propagate-settings,omitempty"`
	Router           string       `json:"router,omitempty"`
	ServerIdentifier string       `json:"dhcp-server-id,omitempty"`
	SIPServer        string       `json:"sips-server,omitempty"`
	WINSServer       string       `json:"wins-server,omitempty"`
}

type DNSService struct {
	Groups
	Proxy      DNSProxy     `json:"dns-proxy,omitempty"`
	Sec        DNSSec       `json:"dnssec,omitempty"`
	Forwarders []string     `json:"forwarders,omitempty"`
	MaxCache   int          `json:"max-cache-ttl,omitempty"`
	MaxNCache  int          `json:"mac-ncache-ttl,omitempty"`
	TraceOpts  DNSTraceOpts `json:"trace-opts,omitempty"`
}

type DNSProxy struct {
	Groups
	Cache         string `json:"cache,omitempty"`
	DefaultDomain string `json:"default-domain,omitempty"`
	Interface     string `json:"interface,omitempty"`
	PropSetting   bool   `json:"propagate-setting,omitempty"`
}

type DNSSec struct {
	Groups
	Disable       bool     `json:"disable,omitempty"`
	DLV           DNSDLV   `json:"dlv,omitempty"`
	SecureDomains []string `json:"secure-domains,omitempty"`
	TrustedKeys   []DNSKey `json:"trusted-keys,omitempty"`
}

type DNSDLV struct {
	Domain        string `json:"domain,omitempty"`
	TrustedAnchor string `json:"trusted-anchor,omitempty"`
}

type DNSKey struct {
	Groups
	Key         string `json:"key,omitempty"`
	LoadKeyFile string `json:"key-file-url,omitempty"`
}

type DNSTraceOpts struct {
	TraceOpts
	Category string       `json:"category,omitempty"`
	Flag     DNSTraceFlag `json:"flag,omitempty"`
}

type DNSTraceFlag struct {
	All    bool `json:"all,omitempty"`
	Config bool `json:"config,omitempty"`
	DDNS   bool `json:"ddns,omitempty"`
	RTSock bool `json:"rtsock,omitempty"`
	Trace  bool `json:"trace,omitempty"`
	UI     bool `json:"ui,omitempty"`
}

type DynDNSService struct {
	Groups
	DDNSClient DynDNSClient
}

type DynDNSClient struct {
	Groups
	Hostname  string `json:"hostname,omitempty"`
	Agent     string `json:"agent,omitempty"`
	Interface string `json:"interface,omitempty"`
	Server    string `json:"server,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

type FingerService struct {
	Groups
	ConnLimit int `json:"connection-limit,omitempty"`
	RateLimit int `json:"rate-limit,omitempty"`
}

type FTPService struct {
	Groups
	ConnLimit int `json:"connection-limit,omitempty"`
	RateLimit int `json:"rate-limit,omitempty"`
}

type NetConfService struct {
	Groups
	SSH       NetConfSSH       `json:"ssh,omitempty"`
	TraceOpts NetConfTraceOpts `json:"trace-opts,omitempty"`
}

type NetConfSSH struct {
	ConnLimit int `json:"connection-limit,omitempty"`
	RateLimit int `json:"rate-limit,omitempty"`
	Port      int `json:"port,omitempty"`
}

type NetConfTraceOpts struct {
	TraceOpts
	Flag NetConfTraceFlag `json:"flag,omitempty"`
}

type NetConfTraceFlag struct {
	All      bool `json:"all,omitempty"`
	Incoming bool `json:"incoming,omitempty"`
	Outgoing bool `json:"outgoing,omitempty"`
}

type OutSSHService struct {
	Groups
	Clients   []OutSSHClient  `json:"client,omitempty"`
	TraceOpts OutSSHTraceOpts `json:"trace-opts,omit-empty"`
}

type OutSSHClient struct {
	Groups
	ID            string          `json:"id,omitempty"`
	DeviceID      string          `json:"device-id"`
	KeepAlive     OutSSHKeepAlive `json:"keep-alive,omitempty"`
	ReconStrategy string          `json:"reconnect-strategy,omitempty"`
	Secret        string          `json:"secret"`
	Services      string          `json:"services,omitempty"`
}

type OutSSHKeepAlive struct {
	Groups
	Retry   int `json:"retry,omitempty"`
	timeout int `json:"timeout,omitempty"`
}

type OutSSHTraceOpts struct {
	TraceOpts
	Flag OutSSHTraceFlag `json:"flag,omitempty"`
}

type OutSSHTraceFlag struct {
	All           bool `json:"all,omitempty"`
	Configuration bool `json:"configuration,omitempty"`
	Connectivity  bool `json:"connectivity,omitempty"`
}

type DeploymentService struct {
	Groups
	LocalCert     string              `json:"local-certificate,omitempty"`
	Servers       []string            `json:"servers,omitempty"`
	SourceAddress string              `json:"source-address,omitempty"`
	TraceOpts     DeploymentTraceOpts `json:"trace-opts,omitempty"`
}

type DeploymentTraceOpts struct {
	TraceOpts
	Flag DeploymentTraceFlag `json:"flag,omitempty"`
}

type DeploymentTraceFlag struct {
	All         bool `json:"all,omitempty"`
	Application bool `json:"application,omitempty"`
	Beep        bool `json:"beep,omitempty"`
	IO          bool `json:"io,omitempty"`
	Profile     bool `json:"profile,omitempty"`
}

type SSHService struct {
	Groups
	Ciphers             []string       `json:"ciphers,omitempty"`
	ClientAliveMax      int            `json:"client-alive-count-max,omitempty"`
	ClientAliveInterval int            `json:"client-alive-interval,omitempty"`
	ConnLimit           int            `json:"connection-limit,omitempty"`
	HostKeyAlgo         SSHHostKeyAlgo `json:"hostkey-algorithm,omitempty"`
	KeyExchange         []string       `json:"key-exchange,omitempty"`
	Macs                []string       `json:"macs,omitempty"`
	MaxPreAuth          int
	MaxSessionsPer      int
	TCPForward          bool
	ProtocolVersion     string
	RateLimit           int
	RootLogin           SSHRootLogin
}

type SSHHostKeyAlgo struct {
	Groups
	SSHDSS     SSHAlgoDSS
	SSHECDSA   SSHAlgoECDSA
	SSHRSA     SSHAlgoRSA
	SSHED25519 bool
}

type SSHAlgoDSS struct {
	Groups
	Enabled bool
}

type SSHAlgoRSA struct {
	Groups
	Enabled bool
}

type SSHAlgoECDSA struct {
	Groups
	Enabled bool
}

type SSHRootLogin struct {
	Allow    bool
	Password bool
}

type SubscriberService struct {
	Groups
	EnforceStrictScale  bool
	GRESRouteFlushDelay int
	Maintain            SubscriberMaintain
	TraceOpts           SubscriberTraceOpts
}

type SubscriberMaintain struct {
	Groups
	InterfaceDelete bool
}

type SubscriberTraceOpts struct {
	TraceOpts
	Flag SubscriberTraceFlags
}

type SubscriberTraceFlags struct {
	All       bool
	Database  bool
	General   bool
	ISSU      bool
	Server    bool
	SessionDB bool
	UI        bool
}

type TelnetService struct {
}
type TFTPService struct {
}
type WebMgmtService struct {
}
type WebAPIService struct {
}
type XNMClearService struct {
}
type XNMSSLService struct {
}
