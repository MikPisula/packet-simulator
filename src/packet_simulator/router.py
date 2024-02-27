import subprocess
import json
import ipaddress
from .packet import Packet

# class _RoutingResult:
#     def __init__(self, direction, route):
#         self.direction = direction  # in out forward? yeah that seems reasonable
#         self.route = route

#     def __repr__(self):
#         return (
#             f"{self.__class__.__name__}(direction={self.direction}, route={self.route})"
#         )

#     def __iter__(self):
#         yield self.direction
#         yield self.route


# http://linux-ip.net/html/part-concepts.html
class Router:
    def __init__(self, interfaces: dict = None, routes: dict = None):
        if routes is None:
            routes = self.get_system_routes()

        if interfaces is None:
            interfaces = self.get_system_interfaces()

        self.interfaces = self.parse_interfaces(interfaces)
        self.routes = self.parse_routes(routes)

    def get_system_routes(self):
        ip_route = subprocess.run(
            ["ip", "-j", "route", "show", "table", "all"], capture_output=True, text=True, check=True
        )

        parsed_routes = json.loads(ip_route.stdout)
        return parsed_routes

    def parse_routes(self, raw_routes: dict):
        routes = []

        for parsed_route in raw_routes:
            # TODO: refactor this to use a Route class
            routes.append(
                {
                    "iface": parsed_route["dev"],
                    "metric": (
                        parsed_route["metric"] if "metric" in parsed_route else None
                    ),
                    "flags": parsed_route["flags"],
                    "destination": (
                        ipaddress.ip_network("0.0.0.0/0")
                        if parsed_route["dst"] == "default"
                        else ipaddress.ip_network(parsed_route["dst"])
                    ),
                    "gateway": (
                        ipaddress.ip_address(parsed_route["gateway"])
                        if "gateway" in parsed_route
                        else None
                    ),
                    "prefsrc": (
                        ipaddress.ip_address(parsed_route["prefsrc"])
                        if "prefsrc" in parsed_route
                        else None
                    ),
                    "scope": (
                        parsed_route["scope"] if "scope" in parsed_route else "global"
                    ),
                }
            )

        return routes

    def get_system_interfaces(self):
        ip_address = subprocess.run(
            ["ip", "-j", "address"], capture_output=True, text=True, check=True
        )

        parsed_interfaces = json.loads(ip_address.stdout)
        return parsed_interfaces

    def parse_interfaces(self, raw_interfaces: dict):
        interfaces = []

        for parsed_interface in raw_interfaces:
            interfaces.append(
                {
                    "iface": parsed_interface["ifname"],
                    "mtu": parsed_interface["mtu"],
                    "qdisc": parsed_interface["qdisc"],
                    "addresses": [
                        {
                            "family": address["family"],
                            "address": (
                                ipaddress.IPv4Address(address["local"])
                                if address["family"] == "inet"
                                else ipaddress.IPv6Address(address["local"])
                            ),
                            "network": (
                                ipaddress.IPv4Network(
                                    (address["local"], address["prefixlen"]),
                                    strict=False,
                                )
                                if address["family"] == "inet"
                                else ipaddress.IPv6Network(
                                    (address["local"], address["prefixlen"]),
                                    strict=False,
                                )
                            ),
                        }
                        for address in parsed_interface["addr_info"]
                    ],
                }
            )

        return interfaces

    def route(self, packet: Packet) -> dict:
        packet_route = None

        # TODO: delete this stupid obsolete code because it's stupid and obsolete
        # for interface in self.interfaces:
        #     for address in interface["addresses"]:
        #         if packet.destination == address["address"]:
        #             # this packet is destined for our host
        #             # packet.iiface =
        #             return None

        # http://linux-ip.net/html/routing-selection.html
        # TODO: support multiple routing tables
        # TODO: implement metrics
        for route in self.routes:
            if packet.destination in route["destination"]:
                if packet_route == None:
                    packet_route = route
                elif (
                    packet_route["destination"].prefixlen
                    < route["destination"].prefixlen
                ):
                    packet_route = route
                # elif (
                #     packet_route["destination"].prefixlen
                #     == route["destination"].prefixlen
                # ):
                #     raise Exception("How did this happen.")

        packet.oiface = packet_route["iface"]

        print(
            f"[router] Using route: {packet_route['destination']} via {packet_route['iface']}"
        )

        if packet_route == None:
            raise Exception(f"No route to {packet.destination} could be found.")

        # TODO: refactor to use Route class
        return packet_route
