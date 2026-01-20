# sysconf

Personal system configuration management.

## Usage

```bash
./sysconf.py apply              # Apply full configuration
./sysconf.py packages           # Install packages only
./sysconf.py dotfiles           # Deploy dotfiles only
./sysconf.py services           # Configure services only
./sysconf.py security           # Apply security hardening
./sysconf.py tailscale          # Configure Tailscale VPN
./sysconf.py webpages           # Deploy web applications
./sysconf.py secrets            # Manage .env files
./sysconf.py toolchains         # Install Go, Rust, Node, etc.
./sysconf.py clean              # Remove deployed configurations
```

All commands support `--dry-run` and `--verbose`.

## Setup

```bash
cp secrets.example.toml secrets/config.toml
vim secrets/config.toml       # Add SSH key path, certbot email

vim configs/webpages.toml     # Configure your sites
```
