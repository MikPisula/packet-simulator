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
        self.tables = self.parse_routes(routes)

    def get_system_routes(self):
        ip_route = subprocess.run(
            ["ip", "-j", "route", "show", "table", "all"],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed_routes = json.loads(ip_route.stdout)
        return parsed_routes

    def parse_routes(self, raw_routes: dict):
        routes = {}

        for raw_route in raw_routes:
            # TODO: refactor this to use a Route class
            # TODO: support blackhole routes

            if "table" in raw_route:
                table = raw_route["table"]
            else:
                table = "main"

            if table not in routes:
                routes[table] = []

            route = {}

            route["destination"] = (
                ipaddress.ip_network("0.0.0.0/0")
                if raw_route["dst"] == "default"
                else ipaddress.ip_network(raw_route["dst"])
            )

            if "type" in raw_route and raw_route["type"] == "blackhole":
                route["type"] = "blackhole"
            else:
                route["iface"] = raw_route["dev"]

            route["metric"] = raw_route["metric"] if "metric" in raw_route else None
            route["flags"] = raw_route["flags"]
            route["destination"] = (
                ipaddress.ip_network("0.0.0.0/0")
                if raw_route["dst"] == "default"
                else ipaddress.ip_network(raw_route["dst"])
            )
            route["gateway"] = (
                ipaddress.ip_address(raw_route["gateway"])
                if "gateway" in raw_route
                else None
            )
            route["prefsrc"] = (
                ipaddress.ip_address(raw_route["prefsrc"])
                if "prefsrc" in raw_route
                else None
            )
            route["scope"] = raw_route["scope"] if "scope" in raw_route else "global"

            routes[table].append(route)

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

        # http://linux-ip.net/html/routing-selection.html
        # TODO: support multiple routing tables
        # TODO: implement metrics
        for table in self.tables:
            for route in table:
                if packet.destination in table["destination"]:
                    if packet_route == None:
                        packet_route = table
                    elif (
                        packet_route["destination"].prefixlen
                        < table["destination"].prefixlen
                    ):
                        packet_route = table
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
