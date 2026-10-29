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