# WireGuard installer

![Lint](https://github.com/angristan/wireguard-install/workflows/Lint/badge.svg)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/angristan)

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic through an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6. Please check the [issues](https://github.com/angristan/wireguard-install/issues) for ongoing development, bugs and planned features! You might also want to check the [discussions](https://github.com/angristan/wireguard-install/discussions) for help.

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!

### Options

```
Usage: ./wireguard-install.sh [options]
Options:
  -c, --config <path>  Path to the configuration file (default: ./setup.conf)
  -f, --force          Force reinstall if already installed
  -l, --log <path>     Path to the log directory (default: .)
  -h, --help           Show this help message
```

### Headless Install

You can run the script in headless mode by creating a `setup.conf` file. You can use the `setup.conf.example` as a template.

```bash
cp setup.conf.example setup.conf
# Edit setup.conf
./wireguard-install.sh --config setup.conf
```

### Private service forwarding

Headless installations can publish an explicitly approved private service on
an address routed to WireGuard clients. Rules are separated by spaces and use
the format
`protocol|listen_ip|listen_port|target_ip|target_port|snat_ip`:

```bash
SERVER_WG_IPV4=10.66.66.1
PRIVATE_FORWARD_RULES="tcp|10.66.66.1|8006|10.0.5.10|8006|10.0.1.200"
```

Each rule creates interface- and source-restricted DNAT, forwarding, return,
and SNAT rules in the generated WireGuard configuration. The listener must be
`SERVER_WG_IPV4` or an explicit `/32` in client `ALLOWED_IPS`, only IPv4 targets
are supported, and the SNAT address must be assigned to the WireGuard server.
This permits a narrowly routed public `/32` to select a private service without
changing client DNS or the default route. Set `PRIVATE_FORWARD_RULES=""` and
run with `--update` to remove previously generated forwards.

Headless installations can also route an explicit private destination already
present in the clients' `AllowedIPs`. Rules are separated by spaces and use
`protocol|target_ip|target_port|protected_subnet|snat_ip`:

```bash
ALLOWED_IPS="10.66.66.0/24,10.0.5.20/32"
PRIVATE_ROUTE_RULES="tcp|10.0.5.20|443|10.0.5.0/24|10.0.1.200"
```

The generated policy accepts only the declared target and port, rejects other
VPN traffic to its protected subnet, and uses SNAT for a deterministic return
path. Set `PRIVATE_ROUTE_RULES=""` and run with `--update` to remove the rules.
Existing client configuration files must be updated separately when
`AllowedIPs` changes.

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

Contributions are welcome! Here's how you can help:

### Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

We use [shellcheck](https://github.com/koalaman/shellcheck) and [shfmt](https://github.com/mvdan/sh) to enforce bash styling guidelines and good practices. They are executed for each commit / PR with GitHub Actions, so you can check the configuration [here](https://github.com/angristan/wireguard-install/blob/master/.github/workflows/lint.yml).

## Say thanks

You can [say thanks](https://saythanks.io/to/angristan) if you want!

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=angristan/wireguard-install&type=Date)](https://star-history.com/#angristan/wireguard-install&Date)
