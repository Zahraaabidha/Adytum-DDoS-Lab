"""Provider connector package.

Importing this module has the side effect of populating
`app.provider.base.PROVIDER_REGISTRY`: each connector module below is
expected to define one `@register_provider`-decorated `ThreatProvider`
subclass. This file is intentionally the ONLY place that has to change to
add or remove a provider -- add the connector module, import it here (or
remove the import to retire a provider).

Stage A shipped the registry mechanism only. Stage B adds the connector
modules below -- this import list is the single place to touch to add or
remove a provider (plus the new/removed connector file itself).
"""
from app.provider import (  # noqa: F401  -- imported for @register_provider side effects
    abuseipdb,
    cisa_kev,
    emerging_threats,
    nvd_cve,
    otx,
    spamhaus_drop,
    threatfox,
)
