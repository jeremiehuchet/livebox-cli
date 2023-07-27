# livebox-cli

Minimal rust cli to invoke a limited set of livebox sysbus operations.

## Help

```
$ livebox-cli --help
Usage: livebox-cli [OPTIONS] --password <PASSWORD> <COMMAND>

Commands:
  show      Invoke sysbus method
  firewall  Edit firewall NAT rules
  help      Print this message or the help of the given subcommand(s)

Options:
      --base-url <LIVEBOX_API_BASEURL>  Livebox base url [env: LIVEBOX_API_BASEURL=] [default: http://livebox.home]
  -u, --username <USERNAME>             Livebox administration username [default: admin]
  -p, --password <PASSWORD>             Livebox administration password
  -q, --query <QUERY>                   json path expression to filter output (ex: `$.IPAddress`)
  -r, --raw                             output raw strings, not JSON text
  -h, --help                            Print help
```

### Show

```
$ livebox-cli show --help
Invoke sysbus method on

Usage: livebox-cli --password <PASSWORD> show --service <SERVICE> --method <METHOD>

Options:
  -s, --service <SERVICE>  service name (ex: `NMC`)
  -m, --method <METHOD>    method name (ex: `getWANStatus`)
  -h, --help               Print help
```

### Firewall

```
firewall --help
Usage: livebox-cli --password <PASSWORD> firewall <COMMAND>

Commands:
  add      
  enable   
  disable  
  remove   
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Examples

### Invoke sysbus methos

`livebox-cli --user admin --password secret exec --service NMC --method getWANStatus`

```json
{
  "data": {
    "ConnectionState": "Bound",
    "DNSServers": "163.134.239.9,59.50.158.77",
    "GponState": "O5_Operation",
    "IPAddress": "55.27.2.115",
    "IPv6Address": "4e95:624a:8079:0784:6922:e6e7:b878:5815",
    "IPv6DelegatedPrefix": "4e95:624a:8079:0784::/56",
    "LastConnectionError": "None",
    "LinkState": "up",
    "LinkType": "gpon",
    "MACAddress": "BA-D3-52-DA-DB-30",
    "Protocol": "dhcp",
    "RemoteGateway": "212.168.252.207",
    "WanState": "up"
  },
  "status": true
}
```

### Filter output using JsonPath



`livebox-cli --user admin --password secret --query $.data.IPAddress --raw exec --service NMC --method getWANStatus`

```
55.27.2.115
```
