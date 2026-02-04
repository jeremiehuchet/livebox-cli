# livebox-cli

Minimal rust cli to invoke a limited set of livebox sysbus operations.

## Help

```
$ livebox-cli --help
Usage: livebox-cli [OPTIONS] --password <PASSWORD> <COMMAND>

Commands:
  exec  Invoke sysbus method
  nat   Edit NAT rules
  help  Print this message or the help of the given subcommand(s)

Options:
      --base-url <LIVEBOX_API_BASEURL>  Livebox base url [env: LIVEBOX_API_BASEURL=] [default: http://livebox.home]
  -u, --username <USERNAME>             Livebox administration username [default: admin]
  -p, --password <PASSWORD>             Livebox administration password
  -k, --insecure                        Allow insecure server connections when using SSL (default: false, verifies certificates)
  -q, --query <QUERY>                   json path expression to filter output (ex: `$.IPAddress`)
  -r, --raw                             output raw strings, not JSON text
  -h, --help                            Print help
```

### Show

```
$ livebox-cli exec --help
Invoke sysbus method

Usage: livebox-cli --password <PASSWORD> exec --service <SERVICE> --method <METHOD>

Options:
  -s, --service <SERVICE>  service name (ex: `NMC`)
  -m, --method <METHOD>    method name (ex: `getWANStatus`)
  -h, --help               Print help
```

### Firewall

```
$ livebox-cli nat --help
Edit NAT rules

Usage: livebox-cli --password <PASSWORD> nat <COMMAND>

Commands:
  list
  add      
      --id <ID>                         A unique identifier
      --description <DESCRIPTION>       A description
  -p, --protocol <PROTOCOL>             The protocol to forward [possible values: tcp, udp, all]
      --source <SOURCE_HOST>            The allowed source hosts
      --sport <SOURCE_PORT>             The exposed port
      --destination <DESTINATION_HOST>  The destination host
      --dport <DESTINATION_PORT>        The destination port
  enable   
  disable  
  remove   
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Examples

### Invoke sysbus methos

`livebox-cli --username admin --password secret exec --service NMC --method getWANStatus`

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

`livebox-cli --username admin --password secret --query $.data.IPAddress --raw exec --service NMC --method getWANStatus`

```
55.27.2.115
```
