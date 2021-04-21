package config

type System struct {
	Services SystemService
	Security SystemSecurity
	Chassis  SystemChassis
}

type Groups struct {
	ApplyGroups       []string `json:"apply-groups,omitempty"`
	ApplyGroupsExcept []string `json:"apply-groups-except,omitempty"`
}

type TraceOpts struct {
	Groups
	DebugLevel  int       `json:"debug-level,omitempty"`
	File        TraceFile `json:"file,omitempty"`
	Level       string    `json:"level,omitempty"`
	RemoteTrace bool      `json:"no-remote-trace,omitempty"`
}

type TraceFile struct {
	FileName      string `json:"filename,omitempty"`
	Files         int    `json:"files,omitempty"`
	Match         string `json:"match,omitempty"`
	Size          int    `json:"size,omitempty"`
	WorldReadable bool   `json:"world-readable,omitempty"`
}
