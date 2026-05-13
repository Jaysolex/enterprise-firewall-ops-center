import xml.etree.ElementTree as ET
import json
from typing import List
from .models import FirewallRule


class FirewallConfigParser:
    """
    Base class for firewall configuration parsers.
    """
    def parse_rules(self) -> List[FirewallRule]:
        raise NotImplementedError


class PaloAltoParser(FirewallConfigParser):
    """
    Parses Palo Alto firewall XML configurations into normalized FirewallRule objects.
    
    Supports:
    - XML-based Palo Alto configurations
    - Multi-rule parsing with error handling
    - Rule validation and normalization
    """

    def __init__(self, xml_file):
        """
        Initialize PaloAltoParser.
        
        Args:
            xml_file (str): Path to Palo Alto XML configuration file
        """
        self.xml_file = xml_file
        self.rules = []
        self.errors = []

    def parse_rules(self) -> List[FirewallRule]:
        """
        Parse Palo Alto XML configuration and return normalized rules.
        
        Returns:
            List[FirewallRule]: List of parsed firewall rules
            
        Raises:
            FileNotFoundError: If XML file doesn't exist
            ET.ParseError: If XML is malformed
        """
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()

            # Support both <rules> wrapper and direct <rule> elements
            rule_elements = root.findall(".//rule")

            if not rule_elements:
                print(f"⚠️  Warning: No rules found in {self.xml_file}")
                return []

            for idx, rule in enumerate(rule_elements):
                try:
                    parsed_rule = self._parse_single_rule(rule, idx)
                    if parsed_rule:
                        self.rules.append(parsed_rule)
                except ValueError as e:
                    self.errors.append(f"Rule {idx}: {str(e)}")
                    print(f"⚠️  Skipping rule {idx}: {str(e)}")

            return self.rules

        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.xml_file}")
        except ET.ParseError as e:
            raise ET.ParseError(f"Invalid XML format: {str(e)}")

    def _parse_single_rule(self, rule_element, rule_index: int) -> FirewallRule:
        """
        Parse a single Palo Alto rule element.
        
        Args:
            rule_element: XML rule element
            rule_index (int): Rule index for identification
            
        Returns:
            FirewallRule: Parsed firewall rule object
        """
        name = rule_element.findtext("name", default=f"rule_{rule_index}")
        source = rule_element.findtext("source", default="any")
        destination = rule_element.findtext("destination", default="any")
        service = rule_element.findtext("service", default="any")
        action = rule_element.findtext("action", default="deny")
        description = rule_element.findtext("description", default="")

        # Optional fields
        rule_id = rule_element.findtext("rule_id", default=None)
        enabled_text = rule_element.findtext("enabled", default="true")
        enabled = enabled_text.lower() in ["true", "yes", "1"]

        return FirewallRule(
            name=name,
            source=source,
            destination=destination,
            service=service,
            action=action,
            description=description,
            rule_id=rule_id,
            enabled=enabled
        )

    def get_errors(self):
        """Return list of parsing errors."""
        return self.errors

    def print_summary(self):
        """Print parsing summary."""
        print(f"\n📊 Parsing Summary:")
        print(f"  ✅ Rules parsed: {len(self.rules)}")
        print(f"  ⚠️  Errors: {len(self.errors)}")
        if self.errors:
            for error in self.errors:
                print(f"     - {error}")


class JSONConfigParser(FirewallConfigParser):
    """
    Parses JSON-based firewall configurations into normalized FirewallRule objects.
    """

    def __init__(self, json_file):
        """
        Initialize JSONConfigParser.
        
        Args:
            json_file (str): Path to JSON configuration file
        """
        self.json_file = json_file
        self.rules = []
        self.errors = []

    def parse_rules(self) -> List[FirewallRule]:
        """
        Parse JSON configuration and return normalized rules.
        
        Returns:
            List[FirewallRule]: List of parsed firewall rules
        """
        try:
            with open(self.json_file, 'r') as f:
                data = json.load(f)

            # Support both {"rules": [...]} and direct [...] formats
            rule_list = data.get("rules", data) if isinstance(data, dict) else data

            if not isinstance(rule_list, list):
                raise ValueError("Expected list of rules in JSON")

            for idx, rule_data in enumerate(rule_list):
                try:
                    parsed_rule = FirewallRule(
                        name=rule_data.get("name", f"rule_{idx}"),
                        source=rule_data.get("source", "any"),
                        destination=rule_data.get("destination", "any"),
                        service=rule_data.get("service", "any"),
                        action=rule_data.get("action", "deny"),
                        description=rule_data.get("description", ""),
                        rule_id=rule_data.get("rule_id"),
                        enabled=rule_data.get("enabled", True)
                    )
                    self.rules.append(parsed_rule)
                except ValueError as e:
                    self.errors.append(f"Rule {idx}: {str(e)}")

            return self.rules

        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.json_file}")
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON format: {str(e)}", "", 0)
