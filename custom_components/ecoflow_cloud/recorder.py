from homeassistant.core import callback, HomeAssistant

from . import (
    ATTR_KEEPALIVE_RECONNECTS,
    ATTR_KEEPALIVE_RESUBSCRIBES,
    ATTR_STATUS_UPDATES,
    ATTR_STATUS_DATA_LAST_UPDATE,
    ATTR_STATUS_LAST_UPDATE,
    ATTR_STATUS_PHASE,
    ATTR_QUOTA_REQUESTS,
)


@callback
def exclude_attributes(hass: HomeAssistant) -> set[str]:
    return {
        ATTR_KEEPALIVE_RECONNECTS,
        ATTR_KEEPALIVE_RESUBSCRIBES,
        ATTR_STATUS_UPDATES,
        ATTR_STATUS_DATA_LAST_UPDATE,
        ATTR_STATUS_LAST_UPDATE,
        ATTR_STATUS_PHASE,
        ATTR_QUOTA_REQUESTS,
    }
