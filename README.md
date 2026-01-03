# Suricata Log Tailer for pfSense

A lightweight Go application that monitors [Suricata IDS/IPS EVE log files](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
for alert logs and sends formatted notifications to [ntfy](https://docs.ntfy.sh/) in real-time.

## Features

- 📊 **Real-time monitoring** - Watches Suricata eve.json log files using [fsnotify](https://github.com/fsnotify/fsnotify)
- 🎨 **Customizable templates** - Format alerts using [Go templates](https://pkg.go.dev/text/template) with Markdown support
- 🔄 **Log rotation handling** - Automatically handles log file rotation
- 📝 **pfSense syslog integration** - Logs errors and warnings to pfSense system logs

<img alt="ntfy Notification" src="https://github.com/user-attachments/assets/f7527fa6-ebc3-4a49-ac23-e7ff428646fa" />

## Installation

### Prerequisites

- pfSense Suricata installed
- Go (for building)

### Installation on pfSense

```bash
# Copy binary to appropriate location
cp suricata-tailer /usr/local/bin/
chmod +x /usr/local/bin/suricata-tailer

# Create config directory
mkdir -p /usr/local/etc/suricata-tailer

# Copy config file
cp config.yaml /usr/local/etc/suricata-tailer/
```

## Configuration

Create a [`config.yaml`](config.yaml) file:

### Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `template` | Go template for formatting alerts | See above |
| `glob_path` | Pattern to match Suricata log files | `/var/log/suricata/*/eve.json` |
| `endpoint` | HTTP endpoint for notifications | `https://ntfy.sh/topic` |
| `headers` | HTTP headers to include in requests | Authorization, Content-Type, etc. |

### Template Variables

The template has access to all fields in Suricata's eve.json format. Common fields include:

- `.timestamp` - Alert timestamp
- `.event_type` - Type of event (alert, http, dns, etc.)
- `.src_ip` / `.src_port` - Source IP and port
- `.dest_ip` / `.dest_port` - Destination IP and port
- `.proto` - Protocol (TCP, UDP, etc.)
- `.alert.signature` - Alert signature/rule name
- `.alert.severity` - Severity level (1=high, 2=medium, 3=low)
- `.alert.category` - Alert category
- `.http.*` - HTTP-specific fields (if applicable)
- `.flow.*` - Flow statistics

## Usage

### Running Manually

```bash
# Run with config in current directory
./suricata-tailer 

# Run with custom config path
./suricata-tailer -config <path to config.yaml>
```

### Running as a service

<img alt="Setup shellcmd" src="https://github.com/user-attachments/assets/a30e84f2-34ad-4c41-addb-3b2a2ef0ab9b" />


## Acknowledgments

- Built with [fsnotify](https://github.com/fsnotify/fsnotify) for file watching
- Uses [go-yaml](https://github.com/goccy/go-yaml) for configuration parsing
