# sysconf

A minimal, idempotent configuration management tool for Linux systems. Think Ansible, but simpler and Python-native.

## Quick Start

```bash
# Clone to your new system
git clone https://github.com/YOUR_USERNAME/sysconf.git ~/sysconf
cd ~/sysconf

# Preview what would change
./sysconf.py apply --dry-run

# Apply full configuration
./sysconf.py apply

# Or apply specific parts
./sysconf.py packages --groups common,server
./sysconf.py dotfiles
./sysconf.py security
```

## Project Structure

```
sysconf/
├── sysconf.py          # CLI entry point
├── lib/
│   ├── packages.py     # Cross-distro package management
│   ├── services.py     # systemd helpers
│   ├── files.py        # File templating, symlinks, permissions
│   └── security.py     # SSH/firewall hardening
├── configs/
│   ├── ssh/            # SSH hardening configs
│   ├── nginx/          # Nginx configs and templates
│   ├── fail2ban/       # Fail2ban jail configuration
│   ├── systemd/        # Service file templates
│   └── dotfiles/       # User dotfiles (bashrc, vimrc, etc.)
├── packages.toml       # Declarative package manifest
├── secrets.example/    # Template for secrets (actual secrets gitignored)
└── pyproject.toml      # Python project config
```

## Features

- **Cross-distro support**: Works with apt (Debian/Ubuntu), pacman (Arch), dnf (Fedora)
- **Idempotent operations**: Safe to run repeatedly - only changes what's needed
- **Declarative packages**: Define packages in TOML, with per-distro name mapping
- **Jinja2 templating**: Generate configs with variable substitution
- **Security hardening**: SSH, fail2ban, firewall configurations included
- **Dry-run mode**: Preview changes before applying

## Configuration

### packages.toml

Define packages in groups with optional distro-specific aliases:

```toml
[common]
packages = ["vim", "git", "tmux", "htop"]

[server]
packages = ["nginx", "fail2ban", "certbot"]

[aliases.pacman]
python3 = "python"  # Different name on Arch
```

### Secrets

Create a `secrets/` directory (gitignored) with sensitive values:

```
secrets/
├── db-password
└── api-key
```

Or use environment variables (take precedence):
```bash
export DB_PASSWORD="..."
```

### Templates

Use Jinja2 templates in `configs/` for dynamic configuration:

```jinja2
# configs/nginx/site.conf.j2
server {
    server_name {{ domain }};
    proxy_pass http://127.0.0.1:{{ port }};
}
```

## Commands

| Command | Description |
|---------|-------------|
| `apply` | Apply full configuration |
| `packages` | Install packages from manifest |
| `dotfiles` | Deploy user dotfiles |
| `services` | Enable/configure services |
| `security` | Apply security hardening |
| `info` | Show system information |

### Options

- `--dry-run, -n`: Show what would change without making changes
- `--verbose, -v`: Enable verbose output
- `--groups`: Specify package groups (comma-separated)

## Requirements

- Python 3.11+ (or 3.10 with `tomli` package)
- Root/sudo access for system configuration
- Optional: `jinja2` for advanced templating

## License

MIT
