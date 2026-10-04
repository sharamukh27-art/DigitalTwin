"""Asset models: devices and services inside a network."""

import re
from ipaddress import AddressValueError, IPv4Address
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, model_validator

from app.models.common import Code, Name, PortNumber, StoredModel, reject_nulls
from app.models.enums import AssetType, DataClassification, Protocol, Zone

MAC_PATTERN = re.compile(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def _validate_mac(value: str) -> str:
    """Check the AA:BB:CC:DD:EE:FF format and normalise to upper case."""
    normalised = value.strip().upper()
    if not MAC_PATTERN.fullmatch(normalised):
        raise ValueError("MAC address must use the format AA:BB:CC:DD:EE:FF")
    return normalised


def _validate_ipv4(value: str) -> str:
    """Check that the value is a dotted-quad IPv4 address."""
    try:
        return str(IPv4Address(value.strip()))
    except AddressValueError as exc:
        raise ValueError("must be a valid IPv4 address") from exc


def _validate_cve_id(value: str) -> str:
    """Check the CVE-YYYY-NNNN+ format and normalise to upper case."""
    normalised = value.strip().upper()
    if not CVE_PATTERN.fullmatch(normalised):
        raise ValueError("CVE id must use the format CVE-YYYY-NNNN")
    return normalised


MacAddress = Annotated[str, AfterValidator(_validate_mac)]
IPv4Str = Annotated[str, AfterValidator(_validate_ipv4)]
CveId = Annotated[str, AfterValidator(_validate_cve_id)]
Vlan = Annotated[int, Field(ge=1, le=4094)]
CriticalityLevel = Annotated[int, Field(ge=1, le=5)]


class Port(BaseModel):
    """An open port on an asset."""

    port: PortNumber
    protocol: Protocol
    service: str
    version: str | None = None


class Cve(BaseModel):
    """A known vulnerability affecting an asset."""

    id: CveId
    cvss: float = Field(ge=0.0, le=10.0)
    description: str


class AssetBase(BaseModel):
    """Fields a client supplies for an asset."""

    code: Code
    name: Name
    type: AssetType
    ip: IPv4Str | None = None
    mac: MacAddress | None = None
    os: str = ""
    os_version: str = ""
    vlan: Vlan | None = None
    zone: Zone
    open_ports: list[Port] = Field(default_factory=list)
    criticality: CriticalityLevel = 3
    owner: str = ""
    tags: list[str] = Field(default_factory=list)
    known_cves: list[Cve] = Field(default_factory=list)
    data_classification: DataClassification = DataClassification.INTERNAL


class AssetCreate(AssetBase):
    """Request body for creating an asset."""


class AssetUpdate(BaseModel):
    """Request body for updating an asset. Only sent fields change."""

    code: Code | None = None
    name: Name | None = None
    type: AssetType | None = None
    ip: IPv4Str | None = None
    mac: MacAddress | None = None
    os: str | None = None
    os_version: str | None = None
    vlan: Vlan | None = None
    zone: Zone | None = None
    open_ports: list[Port] | None = None
    criticality: CriticalityLevel | None = None
    owner: str | None = None
    tags: list[str] | None = None
    known_cves: list[Cve] | None = None
    data_classification: DataClassification | None = None

    @model_validator(mode="after")
    def _no_nulls(self) -> "AssetUpdate":
        reject_nulls(self, frozenset({"ip", "mac", "vlan"}))
        return self


class Asset(AssetBase, StoredModel):
    """A stored asset."""

    network_id: str


class AssetRead(Asset):
    """Response model for an asset."""
