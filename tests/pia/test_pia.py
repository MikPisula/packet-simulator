import json
import ipaddress
from packet_simulator import Simulator, Packet, Firewall, Router
from pathlib import Path

dir = Path(__file__).parent

with dir.joinpath("ruleset.json").open() as ruleset_fp:
    ruleset = json.load(ruleset_fp)

firewall = Firewall(ruleset)

with dir.joinpath("routes.json").open() as routes_fp:
    routes = json.load(routes_fp)

with dir.joinpath("interfaces.json").open() as interfaces_fp:
    interfaces = json.load(interfaces_fp)

with dir.joinpath("rules.json").open() as rules_fp:
    rules = json.load(rules_fp)

router = Router(interfaces, routes, rules)

simulator = Simulator(firewall, router)

packets = [
    Packet("10.0.50.11", "10.0.40.13"),
    Packet("10.0.40.13", "10.0.50.11"),
    Packet("10.0.50.11", "10.0.20.10"),
]

for packet in packets:
    assert simulator.simulate(packet) == "accept"
