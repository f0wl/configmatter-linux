package main

// Structures to accept extracted BlackMatter Ransomware configuration data
// different feature sets (cfg_*) can be individually enabled or disabled

type cfg_disk struct {
	Enable         string `json:"enable"`
	Type           string `json:"type"`
	Dark_size      string `json:"dark-size"`
	White_size     string `json:"white-size"`
	Min_size       string `json:"min-size"`
	Extension_list string `json:"extension-list"` // Files with these extensions will be encrypted
}

type cfg_log struct {
	Enable string `json:"enable"`
	Level  string `json:"level"` // Verbosity of the log output
	Path   string `json:"path"`  // Path for the log file
}

type cfg_message struct {
	Enable  string `json:"enable"`
	Name    string `json:"file-name"`              // File name of the ransomnote
	Content string `json:"file-content,omitempty"` // Contents of the ransomnote
}

type cfg_landing struct {
	Enable string   `json:"enable"`
	ID     string   `json:"bot-id"` // Identifier for C2 communication
	Key    string   `json:"key"`    // AES key to encrypt C2 communication
	URLs   []string `json:"urls"`   // C2 URLs
}

type cfg_killvm struct {
	Enable string   `json:"enable"`
	Ignore []string `json:"ignore-list"` // Ignore virtual machines with these names
}

type cfg_killprocess struct {
	Enable string   `json:"enable"`
	List   []string `json:"list"` // Kill processes / daemons
}

type BlackmatterConfigEnc struct {
	RSA_Key     string          `json:"rsa"`                // RSA-4096 Public Key
	Self_Delete string          `json:"remove-self"`        // remove the executable after encryption
	Concurrency string          `json:"worker-concurrency"` // multi-threaded operation
	Disk        cfg_disk        `json:"disk"`               // Encryption
	Log         cfg_log         `json:"log"`                // Logging
	Message     cfg_message     `json:"message"`            // Ransomnote
	Landing     cfg_landing     `json:"landing"`            // Command&Control
	KillVM      cfg_killvm      `json:"kill-vm"`            // VM Allow-List
	KillProcess cfg_killprocess `json:"kill-process"`       // Process Block-list
}

type BlackmatterConfigDec struct {
	RSA_Key     string      `json:"rsa"`                // RSA-4096 Private Key
	Self_Delete string      `json:"remove-self"`        // remove the executable after encryption
	Concurrency string      `json:"worker-concurrency"` // multi-threaded operation
	Disk        cfg_disk    `json:"disk"`               // Encryption
	Log         cfg_log     `json:"log"`                // Logging
	Message     cfg_message `json:"message"`            // Ransomnote
}
