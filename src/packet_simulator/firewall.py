import subprocess
import json
import ipaddress
from .packet import Packet


class _FirewallResult:
    def __init__(self):
        pass


class Firewall:
    def __init__(self, ruleset: dict = None):
        self.hooks = {}

        if ruleset is None:
            ruleset = self.get_system_ruleset()

        self.ruleset = self.parse_ruleset(ruleset)

    def get_system_ruleset(self):
        nft_list_ruleset = subprocess.run(
            ["nft", "-j", "list", "ruleset", "inet"],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed_ruleset = json.loads(nft_list_ruleset.stdout)
        return parsed_ruleset

    def parse_ruleset(self, raw_ruleset: dict):
        ruleset = {}

        for raw_element in raw_ruleset["nftables"]:
            for element_type, element in raw_element.items():
                if element_type == "metainfo":
                    # TODO: print this in verbose mode
                    pass

                elif element_type == "table":
                    # TODO: currently ignored
                    pass

                elif element_type == "chain":
                    # TODO: add ipv6 support
                    if not element["family"] in ("ip", "inet"):
                        continue
                    
                    ruleset[element["name"]] = {
                        "name": element["name"],
                        "rules": [],
                        "hook": element["hook"] if "hook" in element else None,
                        "policy": element["policy"] if "policy" in element else None,
                        "table": element["table"],
                    }

                elif element_type == "rule":
                    # TODO: add ipv6 support
                    if not element["family"] in ("ip", "inet"):
                        continue
                    
                    ruleset[element["chain"]]["rules"].append(element["expr"])

                else:
                    raise Exception(f"Unknown ruleset element_type: {element_type}")

        return ruleset

    # https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation#ct_status_-_conntrack_status
    # https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter/nf_conntrack_common.h#L65
    # TODO
    def _resolve_selector(self, raw_expression: dict, packet: Packet):
        if raw_expression == "dnat":
            return 1 << 5

        elif raw_expression == "invalid":
            return 1 << 0

        elif raw_expression == "established":
            return 1 << (0 + 1)

        elif raw_expression == "related":
            return 1 << (1 + 1)

        elif raw_expression == "new":
            return 1 << (2 + 1)

        else:
            raise Exception(f"Unknown selector: {raw_expression}")

    def _resolve_expression(self, raw_expression: dict, operator: str, packet: Packet):
        if isinstance(raw_expression, str):
            return (
                self._resolve_selector(raw_expression, packet)
                if operator == "in"
                else raw_expression
            )

        ((expression_type, expression),) = raw_expression.items()

        # TODO: add conntrack tool support
        # TODO
        if expression_type == "ct":
            ct_key = expression["key"]

            if ct_key == "state":
                state = packet.ct["state"]
                return (
                    self._resolve_selector(state, packet) if operator == "in" else state
                )

            elif ct_key == "status":
                status = packet.ct["status"]
                return status

            else:
                raise Exception(f"Unknown ct_key: {ct_key}")

        # https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
        # TODO
        elif expression_type == "meta":
            meta_key = expression["key"]

            if meta_key == "oifname":
                return packet.oiface

            elif meta_key == "iifname":
                return packet.iiface

            elif meta_key == "nfproto":
                return (
                    "ip4" if isinstance(packet.source, ipaddress.IPv4Address) else "ip6"
                )

            else:
                raise Exception(f"Unknown meta_key: {meta_key}")

        # TODO
        elif expression_type == "set":
            return [
                self._resolve_expression(set_expression, operator, packet)
                for set_expression in expression
            ]

        # TODO
        elif expression_type == "payload":
            if "protocol" in expression and "field" in expression:
                protocol = expression["protocol"]
                field = expression["field"]

                # TODO: refactor this so that not only daddr checks if packet is ipv6
                if protocol == "ip6":
                    if not isinstance(packet.source, ipaddress.IPv6Address):
                        return None

                    if field == "daddr":
                        return packet.source
                    else:
                        raise Exception(f"Unknown field {expression}")

                elif protocol == "icmpv6":
                    if not packet.proto == "icmpv6":
                        return None

                    # TODO:
                    return None

                elif protocol == "tcp":
                    if not packet.proto == "tcp":
                        return None

                    if field == "dport":
                        return packet.dport

                    elif field == "sport":
                        return packet.sport

                elif protocol == "udp":
                    if not packet.proto == "udp":
                        return None

                    if field == "dport":
                        return packet.dport

                    elif field == "sport":
                        return packet.sport

                else:
                    raise Exception(f"Unknown protocol {protocol}")

            else:
                raise Exception(f'Unknown payload {expression["payload"]}')

        elif expression_type == "prefix":
            return ipaddress.IPv6Network((expression["addr"], expression["len"]))

        elif expression_type == "range":
            return range(expression[0], expression[1] + 1)

        else:
            raise Exception(f"Unknown expression type {expression_type}")

    def _resolve_match(self, match: dict, packet: Packet):
        operator = match["op"]

        left = self._resolve_expression(match["left"], operator, packet)
        right = self._resolve_expression(match["right"], operator, packet)

        # print(f"[firewall] match {left} {operator} {right}")

        if isinstance(left, list):
            raise Exception(f"Unsupported expression on LHS {right}")

        elif isinstance(right, list) or isinstance(right, range):
            if operator == "==":
                result = left in right

            elif operator == "!=":
                result = not left in right

            else:
                raise Exception(f"Unknown operator {operator}")

        else:
            if operator == "==":
                result = right == left

            elif operator == "!=":
                result = right != left

            elif operator == "in":
                result = (right & left) == right

            else:
                raise Exception(f"Unknown operator: {operator}")

        print(f"[firewall] match {left} {operator} {right} -> {result}")
        return result

    def _resolve_rule(self, rule: dict, packet: Packet):
        for raw_expression in rule:
            for expression_type, expression in raw_expression.items():
                if expression_type == "jump":
                    print(f"[firewall] jump to chain {expression['target']}")

                    return self._resolve_chain(expression["target"], packet)
                    # self._resolve_chain()

                elif expression_type == "match":
                    if self._resolve_match(expression, packet) == True:
                        continue
                    else:
                        return None

                elif expression_type in ["accept", "reject", "drop"]:
                    print(f"[firewall] {expression_type}")

                    return expression_type

                elif expression_type == "return":
                    print(f"[firewall] return")
                    # print(f"[firewall] jump to chain {expression['target']}")
                    return None
                
                elif expression_type in ("counter", "xt"):
                    continue

                else:
                    raise Exception(f"Unknown rule expression_type {expression_type}")

    def _resolve_chain(self, chain: str, packet: Packet):
        print(f"[firewall] enter chain {chain}")
        for rule in self.ruleset[chain]["rules"]:
            value = self._resolve_rule(rule, packet)

            if value is not None:
                return value

    # https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
    def resolve_hook(self, hook: str, packet: Packet):
        print(f"[firewall] hook {hook}")
        
        result = None

        for chain in self.ruleset.values():
            if chain["hook"] == hook:
                result = self._resolve_chain(chain["name"], packet)

                if result is None:
                    result = chain["policy"]

                print(f'[firewall] {chain["name"]} -> {result}')

                if result in ("reject", "drop"):
                    return result

        return result
