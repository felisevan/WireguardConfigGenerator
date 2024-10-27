# coding=utf-8
import base64
import ipaddress
import itertools
import json
import os
from dataclasses import dataclass
from operator import le

import nacl.public


@dataclass
class PeerConfig:
    public_key: str
    preshared_key: str = ""
    allowed_ips: str = ""
    endpoint: str = ""
    persistent_keepalive: str = ""

    def generate(self) -> str:
        config_items = [
            "[Peer]",
            f"PublicKey = {self.public_key}",
            f"PresharedKey = {self.preshared_key}" if self.preshared_key else "",
            f"AllowedIPs = {self.allowed_ips}" if self.allowed_ips else "",
            f"Endpoint = {self.endpoint}" if self.endpoint else "",
            f"PersistentKeepalive = {self.persistent_keepalive}"
            if self.persistent_keepalive
            else "",
            "",
        ]
        return "\n".join(filter(None, config_items))


@dataclass
class InterfaceConfig:
    private_key: str
    listen_port: str = ""
    fw_mark: str = ""
    address: str = ""
    dns: str = ""
    mtu: str = ""
    table: str = ""
    pre_up: str = ""
    post_up: str = ""
    pre_down: str = ""
    post_down: str = ""
    save_config: str = ""

    def generate(self) -> str:
        config_items = [
            "[Interface]",
            f"PrivateKey = {self.private_key}",
            f"ListenPort = {self.listen_port}" if self.listen_port else "",
            f"FwMark = {self.fw_mark}" if self.fw_mark else "",
            f"Address = {self.address}" if self.address else "",
            f"DNS = {self.dns}" if self.dns else "",
            f"MTU = {self.mtu}" if self.mtu else "",
            f"Table = {self.table}" if self.table else "",
            f"PreUp = {self.pre_up}" if self.pre_up else "",
            f"PostUp = {self.post_up}" if self.post_up else "",
            f"PreDown = {self.pre_down}" if self.pre_down else "",
            f"PostDown = {self.post_down}" if self.post_down else "",
            f"SaveConfig = {self.save_config}" if self.save_config else "",
            "",
        ]
        return "\n".join(filter(None, config_items))


def load_param(filename="config.json") -> dict:
    with open(filename, "r") as f:
        return json.load(f)


def generate_key() -> tuple[str, str]:
    private_key_object = nacl.public.PrivateKey.generate()
    return (
        base64.b64encode(bytes(private_key_object)).decode(),
        base64.b64encode(bytes(private_key_object.public_key)).decode(),
    )


def generate_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def generate_ipv4_list(cidr: str, num: int) -> list[str]:
    return list(
        map(str, itertools.islice(ipaddress.IPv4Network(cidr, False).hosts(), num))
    )


def generate_ipv6_list(cidr: str, num: int) -> list[str]:
    return list(
        map(str, itertools.islice(ipaddress.IPv6Network(cidr, False).hosts(), num))
    )


def process() -> None:
    param = load_param()
    client_number = param["client_number"]
    # 1 for server
    total_number = client_number + 1
    ipv4_range = param["ipv4_range"]
    ipv6_range = param["ipv6_range"]
    preshared_key_flag = param["preshared_key_flag"]

    server_param = param["server"]
    client_param = param["client"]

    #  don't have server_public_key here, because we generate it
    #  don't have server_preshared_key here, because we manage it via preshared_key_flag
    #  don't have server_allowed_ips here, because client rarely have multiple ip in client_*_range
    #  don't have server_endpoint here, because client rarely have same "endpoint"(external ip-port tuple)
    #  don't have server_private_key here, because we generate it
    #  don't have client_public_key here, because we generate it
    #  don't have client_preshared_key here, because we manage it via preshared_key_flag
    #  don't have client_private_key here, because we generate it
    #  don't have client_listen_port here, because client rarely need to listen on specific port

    if not (client_number and (ipv4_range or ipv6_range)):
        raise SyntaxError("missing critical config")

    key_pairs = [generate_key() for _ in range(total_number)]
    preshared_keys = [
        generate_psk() if preshared_key_flag else "" for _ in range(client_number)
    ]

    ipv4_list = generate_ipv4_list(ipv4_range, total_number) if ipv4_range else []
    ipv6_list = generate_ipv6_list(ipv6_range, total_number) if ipv6_range else []

    server_address = ""
    if ipv4_list and ipv6_list:
        if (
            len(ipv4_list) < total_number
            or len(ipv6_list) < total_number
            or len(ipv4_list) != len(ipv6_list)
        ):
            raise ValueError(
                f"Cannot create sufficient clients: {client_number}. IPv4: {len(ipv4_list)-1}, IPv6: { len(ipv6_list)-1}"
            )
        server_address = f"{ipv4_list[0]}/{ipv4_range.split('/')[1]}, {ipv6_list[0]}/{ipv6_range.split('/')[1]}"
    elif ipv4_list:
        if len(ipv4_list) < total_number:
            raise ValueError(
                f"Cannot create sufficient clients: {client_number}. IPv4: {len(ipv4_list)-1}"
            )
        server_address = f"{ipv4_list[0]}/{ipv4_range.split('/')[1]}"
        ipv6_list = [""] * len(ipv4_list)
    elif ipv6_list:
        if len(ipv6_list) < total_number:
            raise ValueError(
                f"Cannot create sufficient clients: {client_number}. IPv6: { len(ipv6_list)-1}"
            )
        server_address = f"{ipv6_list[0]}/{ipv6_range.split('/')[1]}"
        ipv4_list = [""] * len(ipv6_list)

    # Server Interface Configuration
    server_interface = InterfaceConfig(
        private_key=key_pairs[0][0],
        listen_port=server_param["listen_port"],
        fw_mark=server_param["fwmark"],
        address=server_address,
        dns=server_param["dns"],
        mtu=server_param["mtu"],
        table=server_param["table"],
        pre_up=server_param["preup"],
        post_up=server_param["postup"],
        pre_down=server_param["predown"],
        post_down=server_param["postdown"],
        save_config=server_param["saveconfig"],
    )

    server_config: list[InterfaceConfig | PeerConfig] = [server_interface]
    client_configs: list[tuple[InterfaceConfig, PeerConfig]] = []

    for key_pair, ipv4, ipv6, psk in zip(
        key_pairs[1:], ipv4_list[1:], ipv6_list[1:], preshared_keys
    ):
        # using /32 for v4 and /128 for v6
        client_address = f"{ipv4}, {ipv6}".strip(", ")

        server_peer = PeerConfig(
            public_key=key_pair[1],
            preshared_key=psk,
            allowed_ips=client_address,
            persistent_keepalive=server_param["persistent_keepalive"],
        )
        server_config.append(server_peer)

        client_interface = InterfaceConfig(
            private_key=key_pair[0],
            address=client_address,
            fw_mark=client_param["fwmark"],
            dns=client_param["dns"],
            mtu=client_param["mtu"],
            table=client_param["table"],
            pre_up=client_param["preup"],
            post_up=client_param["postup"],
            pre_down=client_param["predown"],
            post_down=client_param["postdown"],
            save_config=client_param["saveconfig"],
        )

        client_peer = PeerConfig(
            public_key=key_pairs[0][1],
            preshared_key=psk,
            allowed_ips=client_param["allowed_ips"],
            endpoint=client_param["endpoint"],
            persistent_keepalive=client_param["persistent_keepalive"],
        )

        client_configs.append((client_interface, client_peer))

    server_config_str = "\n\n".join([c.generate() for c in server_config])
    client_config_strs = [
        "\n\n".join([c[0].generate(), c[1].generate()]) for c in client_configs
    ]

    try:
        os.mkdir("conf")
    except FileExistsError as e:
        pass

    with open("conf/server.conf", "w") as f:
        f.write(server_config_str)
    for i in range(len(client_configs)):
        with open(f"conf/client_{i + 1}.conf", "w") as f:
            f.write(client_config_strs[i])


if __name__ == "__main__":
    process()
