# Before modify this, read Wireguard documentation at:
# https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8#CONFIGURATION%20FILE%20FORMAT
# https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8#CONFIGURATION

# DON'T comment out, if you don't need some of them, leave them as blank.
# config start with server means that it will be contained in server side config, not logical server related config
# and vice versa

client_number = 256

# make sure *_range both have enough space, i.e. > client_number
ipv4_range = "192.168.2.1/24"
ipv6_range = "2001:DB8::8A2E:370:7334/56"
ipv6_new_prefix = "64"

# DON'T support manually setting preshared key due to security consideration.
preshared_key_flag = True

# we don't have server_public_key here, because we generate it
# we don't have server_preshared_key here, because we manage it via preshared_key_flag
# we don't have server_allowed_ips here, because client rarely have multiple ip in client_*_range
# we don't have server_endpoint here, because client rarely have same "endpoint"(external ip-port tuple)
server_persistent_keepalive = ""
# we don't have server_private_key here, because we generate it
server_listen_port = "51820"
server_fwmark = ""
server_dns = ""
server_mtu = ""
server_table = ""
server_preup = ""
server_postup = "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
server_predown = ""
server_postdown = "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
server_saveconfig = ""

# we don't have client_public_key here, because we generate it
# we don't have client_preshared_key here, because we manage it via preshared_key_flag
client_allowed_ips = "0.0.0.0/0, ::/0"
client_endpoint = "example.com:51820"
client_persistent_keepalive = ""
# we don't have client_private_key here, because we generate it
# we don't have client_listen_port here, because client rarely need to listen on specific port
client_fwmark = ""
client_dns = "8.8.8.8"
client_mtu = ""
client_table = ""
client_preup = ""
client_postup = ""
client_predown = ""
client_postdown = ""
client_saveconfig = ""

# read source code before using it.
experimental_assign_64_block_flag = True
experimental_postfix = "114:514"
