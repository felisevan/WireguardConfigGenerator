# coding=utf-8
import base64
import ipaddress
import os

import nacl.public

from config import *


def generate_peer(
    public_key, preshared_key, allowed_ips, endpoint, persistent_keepalive
):
    ret = f"[Peer]\nPublicKey = {public_key}\n"
    if preshared_key:
        ret += f"PresharedKey = {preshared_key}\n"
    if allowed_ips:
        ret += f"AllowedIPs = {allowed_ips}\n"
    if endpoint:
        ret += f"Endpoint = {endpoint}\n"
    if persistent_keepalive:
        ret += f"PersistentKeepalive = {persistent_keepalive}\n"
    ret += "\n"

    return ret


def generate_interface(
    private_key,
    listen_port,
    fw_mark,
    address,
    dns,
    mtu,
    table,
    pre_up,
    post_up,
    pre_down,
    post_down,
    save_config,
):
    ret = f"[Interface]\nPrivateKey = {private_key}\n"
    if listen_port:
        ret += f"ListenPort = {listen_port}\n"
    if fw_mark:
        ret += f"FwMark = {fw_mark}\n"
    if address:
        ret += f"Address = {address}\n"
    if dns:
        ret += f"DNS = {dns}\n"
    if mtu:
        ret += f"MTU = {mtu}\n"
    if table:
        ret += f"Table = {table}\n"
    if pre_up:
        ret += f"PreUp = {pre_up}\n"
    if post_up:
        ret += f"PostUp = {post_up}\n"
    if pre_down:
        ret += f"PreDown = {pre_down}\n"
    if post_down:
        ret += f"PostDown = {post_down}\n"
    if save_config:
        ret += f"SaveConfig = {save_config}\n"
    ret += "\n"

    return ret


def generate_config(interface, peers):
    ret = interface
    for i in peers:
        ret += i

    return ret


def generate_key():
    private_key_object = nacl.public.PrivateKey.generate()
    private_key = bytes(private_key_object)
    public_key = bytes(private_key_object.public_key)
    return base64.b64encode(private_key).decode(), base64.b64encode(public_key).decode()


def generate_psk():
    return base64.b64encode(os.urandom(32)).decode()


def generate_ipv4_list(cidr, num):
    cidr = ipaddress.IPv4Network(cidr, False)
    return list(map(lambda x: str(x), list(cidr.hosts())[0 : num + 1]))


def generate_ipv6_list(cidr, num, new_prefix):
    cidr = ipaddress.IPv6Network(cidr, False).subnets(new_prefix=int(new_prefix))
    return list(map(lambda x: str(x), list(cidr)[0 : num + 1]))


def experimental_illegal_ipv6_postfix_assign(ipv6_block, postfix, number):
    """
    2001:0db8:85a3:0000:0000:8a2e:0370:7334/64
      |    |    |    |    |    |    |    |
      1    2    3    4    5    6    7    8

    Group 1-4 is preserved since the mask is 64
    The postfix will take the place of group 5-7
    And group 8 will increase from 1

    :param ipv6_block: A string that is a notation for IPv6 /64 block.
    :param postfix: A postfix excludes the last group. The colones that at the start and the end MUST be excluded.
    :param number: Required number of generated IPs.
    :return: A list contains IPv6 address string
    """

    group = ipv6_block.split(":")
    ret = list()
    for i in range(number):
        ret.append(f"{group[0]}:{group[1]}:{group[2]}:{group[3]}:{postfix}:{str(i)}/64")
    return ret


def process():
    if not (client_number and (ipv4_range or ipv6_range)):
        print("missing critical config")
        exit()

    key_pairs = list()
    # add 1 for server
    for i in range(client_number + 1):
        key_pairs.append(generate_key())

    preshared_keys = list()
    for i in range(client_number):
        if preshared_key_flag:
            preshared_keys.append(generate_psk())
        else:
            preshared_keys.append("")

    server_config = None
    client_configs = list()

    ipv4_list = list()
    ipv6_list = list()
    server_address = ""

    if ipv4_range and ipv6_range:
        ipv4_list = generate_ipv4_list(ipv4_range, client_number + 1)
        if experimental_assign_64_block_flag:
            ipv6_list = experimental_illegal_ipv6_postfix_assign(
                ipv6_range, experimental_postfix, client_number + 1
            )
        else:
            ipv6_list = generate_ipv6_list(
                ipv6_range, client_number + 1, ipv6_new_prefix
            )
        server_address = (
            ipv4_list[0] + "/" + ipv4_range.split("/")[1] + ", " + ipv6_list[0]
        )
    elif ipv4_range:
        ipv4_list = generate_ipv4_list(ipv4_range, client_number + 1)
        for i in range(len(ipv4_list)):
            ipv6_list.append("")
        server_address = ipv4_list[0]
    elif ipv6_range:
        if experimental_assign_64_block_flag:
            ipv6_list = experimental_illegal_ipv6_postfix_assign(
                ipv6_range, experimental_postfix, client_number + 1
            )
        else:
            ipv6_list = generate_ipv6_list(
                ipv6_range, client_number + 1, ipv6_new_prefix
            )
        for i in range(len(ipv6_list)):
            ipv4_list.append("")
        server_address = ipv6_list[0]
    else:
        exit()

    server_interface = generate_interface(
        key_pairs[0][0],
        server_listen_port,
        server_fwmark,
        server_address,
        server_dns,
        server_mtu,
        server_table,
        server_preup,
        server_postup,
        server_predown,
        server_postdown,
        server_saveconfig,
    )
    server_peers = list()
    client_interface = list()
    client_peer = list()
    client_address = ""

    for key_pair, ipv4, ipv6, psk in zip(
        key_pairs[1:], ipv4_list[1:], ipv6_list[1:], preshared_keys
    ):
        if ipv4 and ipv6:
            client_address = ipv4 + ", " + ipv6
        elif ipv4:
            client_address = ipv4
        elif ipv6:
            client_address = ipv6
        else:
            exit()
        server_peers.append(
            generate_peer(
                key_pair[1], psk, client_address, "", server_persistent_keepalive
            )
        )
        client_interface.append(
            generate_interface(
                key_pair[0],
                "",
                client_fwmark,
                client_address,
                client_dns,
                client_mtu,
                client_table,
                client_preup,
                client_postup,
                client_predown,
                client_postdown,
                client_saveconfig,
            )
        )
        client_peer.append(
            generate_peer(
                key_pairs[0][1],
                psk,
                client_allowed_ips,
                client_endpoint,
                client_persistent_keepalive,
            )
        )

    server_config = generate_config(server_interface, server_peers)
    for i, p in zip(client_interface, client_peer):
        client_configs.append(generate_config(i, [p]))

    try:
        os.mkdir("conf")
    except FileExistsError as e:
        pass

    with open("conf/server.conf", "w") as f:
        f.write(server_config)
    for i in range(len(client_configs)):
        with open(f"conf/client_{i + 1}.conf", "w") as f:
            f.write(client_configs[i])

    print("Generated at ./conf dir.")


if __name__ == "__main__":
    process()
