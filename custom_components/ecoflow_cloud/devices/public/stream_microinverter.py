from typing import Any

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.components.number import NumberEntity
from homeassistant.components.select import SelectEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.components.switch import SwitchEntity

from custom_components.ecoflow_cloud.api import EcoflowApiClient
from custom_components.ecoflow_cloud.binary_sensor import MiscBinarySensorEntity
from custom_components.ecoflow_cloud.devices import BaseDevice, const
from custom_components.ecoflow_cloud.devices.public.data_bridge import to_plain
from custom_components.ecoflow_cloud.sensor import (
    CelsiusSensorEntity,
    FrequencySensorEntity,
    InAmpSensorEntity,
    MiscSensorEntity,
    StatusSensorEntity,
    VoltSensorEntity,
    WattsSensorEntity,
)
from custom_components.ecoflow_cloud.devices.public.stream_pv_helpers import (
    StreamPvWattsSensorEntity,
)


class StreamMicroinveter(BaseDevice):
    def sensors(self, client: EcoflowApiClient) -> list[SensorEntity]:
        return [
            WattsSensorEntity(client, self, "gridConnectionPower", const.STREAM_POWER_AC),
            # Per-PV mapping is firmware-dependent. See stream_ac.py comment
            # and issues #582/#584. Both variants are registered with
            # auto_enable=True so the integration stays firmware-agnostic.
            #
            # New-firmware path (computed amp x vol via StreamPvWattsSensorEntity)
            StreamPvWattsSensorEntity(client, self, "plugInInfoPvAmp", const.STREAM_POWER_PV_1, False, True),
            StreamPvWattsSensorEntity(client, self, "plugInInfoPv2Amp", const.STREAM_POWER_PV_2, False, True),
            # Legacy-firmware path (powGetPv* keys)
            WattsSensorEntity(client, self, "powGetPv", const.STREAM_POWER_PV_1, False, True),
            WattsSensorEntity(client, self, "powGetPv2", const.STREAM_POWER_PV_2, False, True),
            VoltSensorEntity(client, self, "gridConnectionVol", const.STREAM_POWER_VOL, False),
            VoltSensorEntity(client, self, "plugInInfoPvVol", const.STREAM_IN_VOL_PV_1, False, True),
            VoltSensorEntity(client, self, "plugInInfoPv2Vol", const.STREAM_IN_VOL_PV_2, False, True),
            InAmpSensorEntity(client, self, "gridConnectionAmp", const.STREAM_POWER_AMP, False),
            InAmpSensorEntity(client, self, "plugInInfoPvAmp", const.STREAM_IN_AMPS_PV_1, False, True),
            InAmpSensorEntity(client, self, "plugInInfoPv2Amp", const.STREAM_IN_AMPS_PV_2, False, True),
            CelsiusSensorEntity(client, self, "invNtcTemp3", "Inverter NTC Temperature"),
            FrequencySensorEntity(client, self, "gridConnectionFreq", "Grid Frequency"),
            # --- Additional diagnostics (disabled by default) ---
            # Configured export/feed-in power cap (e.g. 800 W in EU).
            WattsSensorEntity(client, self, "feedGridModePowLimit", "Feed-in Power Limit", False),
            # Live inverter target power setpoint.
            WattsSensorEntity(client, self, "invTargetPwr", "Inverter Target Power", False),
            # Grid quality / inverter health.
            MiscSensorEntity(client, self, "gridConnectionPowerFactor", "Grid Connection Power Factor", False),
            MiscSensorEntity(client, self, "gridConnectionReactivePower", "Grid Connection Reactive Power", False),
            MiscSensorEntity(client, self, "gridCodeSelection", "Grid Code", False),
            MiscSensorEntity(client, self, "moduleWifiRssi", "WiFi Signal Strength", False),
            StatusSensorEntity(client, self),
        ]

    def binary_sensors(self, client: EcoflowApiClient) -> list[BinarySensorEntity]:
        # Curtailment flags explain why the inverter is throttling output.
        # All disabled by default; enable per need. PV3/PV4 are present in the
        # protocol struct but unused on 2-string microinverters.
        return [
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isGridVol", "Curtailment - Grid Voltage", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isGridFreq", "Curtailment - Grid Frequency", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isTemp", "Curtailment - Temperature", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isPv1Oc", "Curtailment - PV1 Over-current", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isPv1Cl", "Curtailment - PV1 Current Limit", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isPv2Oc", "Curtailment - PV2 Over-current", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "gridCurtailmentSignal.isPv2Cl", "Curtailment - PV2 Current Limit", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "factoryModeEnable", "Factory Mode", False, diagnostic=True),
            MiscBinarySensorEntity(client, self, "debugModeEnable", "Debug Mode", False, diagnostic=True),
        ]

    def numbers(self, client: EcoflowApiClient) -> list[NumberEntity]:
        return []

    def switches(self, client: EcoflowApiClient) -> list[SwitchEntity]:
        return []

    def selects(self, client: EcoflowApiClient) -> list[SelectEntity]:
        return []

    def _prepare_data(self, raw_data) -> dict[str, Any]:
        res = super()._prepare_data(raw_data)
        res = to_plain(res)
        return res

    def _status_sensor(self, client: EcoflowApiClient) -> StatusSensorEntity:
        return StatusSensorEntity(client, self)
