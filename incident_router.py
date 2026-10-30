import ipaddress
from typing import Literal
from pydantic import BaseModel, Field, field_validator
from instructor_lite import extract_structured

class CompromisedHost(BaseModel):
    hostname: str = Field(description="Server hostname, e.g., auth-prod-01")
    ip_address: str = Field(description="Valid IPv4 address of the host")
    port: int = Field(description="Network port number between 1 and 65535")

    @field_validator("ip_address")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        ipaddress.IPv4Address(v)
        return v

    @field_validator("port")
    @classmethod
    def validate_port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v
    
class IncidentReport(BaseModel):
    summary: str = Field(description="One-sentence summary of the incident")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Strict severity classification"
    )
    compromised_hosts: list[CompromisedHost] = Field(
        description="List of all affected hosts extracted from the log"
    )
    requires_network_isolation: bool = Field(
        description="True if severity is CRITICAL or active data exfiltration is occurring"
    )

def dispatch_incident(report: IncidentReport) -> str:
    """Deterministically routes a validated IncidentReport object based on its typed attributes."""


if __name__ == "__main__":
    raw_soc_dump = """
        [SOC ALERT 2026-10-27 03:14 UTC]
        Anomalous outbound traffic spike detected from database cluster!
        Node db-replica-02 (IP: 10.24.88.14, listening on port 5432) and cache-node-01 
        (IP: 192.168.1.205, port 6379) are actively exfiltrating encrypted payloads to an unknown external ASN.
        Assess this as CRITICAL severity. Immediate network isolation is required.
        """

    print("🚀 Parsing nested IncidentReport from raw SOC telemetry...\n")
    incident = extract_structured(raw_soc_dump, IncidentReport)

    print("\n================ VALIDATED NESTED OBJECT ================")
    print(incident.model_dump_json(indent=2))

    print("\n================ DETERMINISTIC ROUTER ACTION ================")
    action = dispatch_incident(incident)
    print(action)