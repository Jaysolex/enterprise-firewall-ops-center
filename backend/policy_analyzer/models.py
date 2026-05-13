class FirewallRule:
    """
    Represents a normalized enterprise firewall rule object.
    Supports multi-vendor firewall policy normalization (Palo Alto, Cisco ASA, Fortinet, Check Point).
    """

    VALID_ACTIONS = ["allow", "deny", "log", "drop", "reject", "alert"]

    def __init__(
        self,
        name,
        source,
        destination,
        service,
        action,
        description=None,
        rule_id=None,
        enabled=True
    ):
        """
        Initialize a FirewallRule object.
        
        Args:
            name (str): Rule name/identifier
            source (str): Source IP/network (e.g., "10.0.0.0/8", "any")
            destination (str): Destination IP/network (e.g., "192.168.1.0/24", "any")
            service (str): Service/port (e.g., "http", "ssh", "443", "any")
            action (str): Action to take (allow, deny, log, etc.)
            description (str, optional): Rule description/business justification
            rule_id (str, optional): Unique rule identifier
            enabled (bool, optional): Whether rule is active. Defaults to True.
        """
        self.name = name
        self.source = source
        self.destination = destination
        self.service = service
        self.action = action.lower() if action else "deny"
        self.description = description or ""
        self.rule_id = rule_id
        self.enabled = enabled

        # Validation
        if self.action not in self.VALID_ACTIONS:
            raise ValueError(
                f"Invalid action '{self.action}'. "
                f"Must be one of: {', '.join(self.VALID_ACTIONS)}"
            )

    def to_dict(self):
        """Convert rule to dictionary representation."""
        return {
            "name": self.name,
            "source": self.source,
            "destination": self.destination,
            "service": self.service,
            "action": self.action,
            "description": self.description,
            "rule_id": self.rule_id,
            "enabled": self.enabled
        }

    def to_json(self):
        """Convert rule to JSON-serializable format."""
        import json
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self):
        status = "ENABLED" if self.enabled else "DISABLED"
        return (
            f"FirewallRule("
            f"id={self.rule_id}, "
            f"name={self.name}, "
            f"{self.source} → {self.destination}:{self.service}, "
            f"action={self.action}, "
            f"status={status}"
            f")"
        )

    def __eq__(self, other):
        """Compare rules by core attributes."""
        if not isinstance(other, FirewallRule):
            return False
        return (
            self.name == other.name
            and self.source == other.source
            and self.destination == other.destination
            and self.service == other.service
            and self.action == other.action
        )

    def is_deny_rule(self):
        """Check if rule is a deny/block rule."""
        return self.action in ["deny", "drop", "reject"]

    def is_allow_rule(self):
        """Check if rule is an allow rule."""
        return self.action == "allow"
