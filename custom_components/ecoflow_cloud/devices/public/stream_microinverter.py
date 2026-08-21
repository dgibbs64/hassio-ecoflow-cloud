import asyncio
import logging
from collections.abc import Callable
from typing import Any

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.components.number import NumberEntity
from homeassistant.components.select import SelectEntity
from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant

from custom_components.ecoflow_cloud.api import EcoflowApiClient
from custom_components.ecoflow_cloud.binary_sensor import MiscBinarySensorEntity
from custom_components.ecoflow_cloud.devices import BaseDevice, const
from custom_components.ecoflow_cloud.devices.public.data_bridge import to_plain
from custom_components.ecoflow_cloud.entities import BaseSensorEntity
from custom_components.ecoflow_cloud.sensor import (
    AmpSensorEntity,
    CelsiusSensorEntity,
    EnergySensorEntity,
    FrequencySensorEntity,
    MiscSensorEntity,
    MqttKeepaliveStatusSensorEntity,
    StatusSensorEntity,
    VoltSensorEntity,
    WattsSensorEntity,
)
from custom_components.ecoflow_cloud.devices.public.stream_ac import (
    DEFAULT_STREAM_AC_HISTORY_PERIOD_SEC,
    StreamACHistoryUpdateCoordinator,
    StreamACMonetarySensorEntity,
)
from custom_components.ecoflow_cloud.devices.public.stream_pv_helpers import (
    StreamPvWattsSensorEntity,
)

_LOGGER = logging.getLogger(__name__)

# The Microinverter has no battery, so only the generation-side metrics from
# the shared Stream history coordinator apply. Unlike Stream AC/Battery,
# these codes are not confirmed against a real Microinverter account - the
# app's home-screen widget for this product may use different codes
# entirely, in which case these sensors will just stay unavailable. Disabled
# by default until someone can confirm they populate.
MICROINVERTER_HISTORY_METRICS: frozenset[str] = frozenset(
    {"environmental_impact", "savings", "solar_generated"}
)


class StreamMicroinveter(BaseDevice):
    history_coordinator: "StreamACHistoryUpdateCoordinator | None" = None
    _history_unsub: "Callable[[], None] | None" = None

    async def async_cleanup(self) -> None:
        """Cancel background tasks on device unload."""
        if self._history_unsub is not None:
            self._history_unsub()
            self._history_unsub = None
        tasks = getattr(self, "_background_tasks", None)
        if tasks:
            for task in list(tasks):
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            tasks.clear()

    def configure_history(self, hass: HomeAssistant, client: EcoflowApiClient) -> None:
        """Set up the periodic historical-data coordinator and trigger an initial refresh."""
        if not hasattr(self, "_background_tasks"):
            self._background_tasks: set[asyncio.Task[Any]] = set()
        try:
            if self.history_coordinator is None:
                self.history_coordinator = StreamACHistoryUpdateCoordinator(
                    hass,
                    client,
                    self,
                    DEFAULT_STREAM_AC_HISTORY_PERIOD_SEC,
                    metrics=MICROINVERTER_HISTORY_METRICS,
                )
            if self._history_unsub is None:
                # Keep the coordinator's periodic refresh scheduled - see the
                # matching comment in stream_ac.py for why this is needed.
                self._history_unsub = self.history_coordinator.async_add_listener(lambda: None)

            def _on_task_done(t: asyncio.Task) -> None:
                try:
                    t.result()
                except Exception as exc:
                    _LOGGER.error("Background historical fetch task failed: %s", exc)
                finally:
                    self._background_tasks.discard(t)

            task = hass.async_create_task(self.history_coordinator.async_request_refresh())
            self._background_tasks.add(task)
            task.add_done_callback(_on_task_done)
            _LOGGER.info("Scheduled initial historical refresh for StreamMicroinveter %s", self.device_info.sn)
        except Exception as exc:
            _LOGGER.error(
                "Failed to schedule historical refresh for StreamMicroinveter %s: %s",
                self.device_info.sn,
                exc,
                exc_info=True,
            )

    def sensors(self, client: EcoflowApiClient) -> list[SensorEntity]:
        return [
            WattsSensorEntity(client, self, "gridConnectionPower", const.STREAM_POWER_AC),
            # Per-PV mapping is firmware-dependent. See stream_ac.py comment
            # and issues #582/#584. Both variants are registered with
            # auto_enable=True so the integration stays firmware-agnostic, and
            # are given distinct "(Calculated)"/"(Reported)" titles so users can
            # tell them apart when a device reports both.
            #
            # "(Calculated)": power derived as plugInInfoPv*Amp x plugInInfoPv*Vol.
            # The amp/volt samples are not synchronised, so this can over-/under-
            # estimate (observed ~15% high vs AC output on some firmware).
            StreamPvWattsSensorEntity(client, self, "plugInInfoPvAmp", "Power PV 1 (Calculated)", False, True),
            StreamPvWattsSensorEntity(client, self, "plugInInfoPv2Amp", "Power PV 2 (Calculated)", False, True),
            # "(Reported)": the inverter's own powGetPv* PV-power figure, which
            # tracks AC output closely and is generally the more accurate source.
            WattsSensorEntity(client, self, "powGetPv", "Power PV 1 (Reported)", False, True),
            WattsSensorEntity(client, self, "powGetPv2", "Power PV 2 (Reported)", False, True),
            VoltSensorEntity(client, self, "gridConnectionVol", const.STREAM_POWER_VOL, False),
            VoltSensorEntity(client, self, "plugInInfoPvVol", const.STREAM_IN_VOL_PV_1, False, True),
            VoltSensorEntity(client, self, "plugInInfoPv2Vol", const.STREAM_IN_VOL_PV_2, False, True),
            # Plain AmpSensorEntity (neutral current icon) to match stream_ac.py -
            # InAmpSensorEntity would wrongly show a grid-import tower icon on a
            # solar PV current / the inverter's grid-export current.
            AmpSensorEntity(client, self, "gridConnectionAmp", const.STREAM_POWER_AMP, False),
            AmpSensorEntity(client, self, "plugInInfoPvAmp", const.STREAM_IN_AMPS_PV_1, False, True),
            AmpSensorEntity(client, self, "plugInInfoPv2Amp", const.STREAM_IN_AMPS_PV_2, False, True),
            CelsiusSensorEntity(client, self, "invNtcTemp3", "Inverter NTC Temperature"),
            FrequencySensorEntity(client, self, "gridConnectionFreq", "Grid Frequency"),
            # --- Additional diagnostics (disabled by default) ---
            # Configured export/feed-in power cap (e.g. 800 W in EU).
            WattsSensorEntity(client, self, "feedGridModePowLimit", "Feed-in Power Limit", False).with_icon("mdi:transmission-tower-export"),
            # Live inverter target power setpoint.
            WattsSensorEntity(client, self, "invTargetPwr", "Inverter Target Power", False).with_icon("mdi:target"),
            # Grid quality / inverter health.
            MiscSensorEntity(client, self, "gridConnectionPowerFactor", "Grid Connection Power Factor", False).with_icon("mdi:angle-acute"),
            MiscSensorEntity(client, self, "gridConnectionReactivePower", "Grid Connection Reactive Power", False).with_icon("mdi:flash-outline"),
            MiscSensorEntity(client, self, "gridCodeSelection", "Grid Code", False).with_icon("mdi:transmission-tower"),
            MiscSensorEntity(client, self, "moduleWifiRssi", "WiFi Signal Strength", False).with_icon("mdi:wifi"),
            self._status_sensor(client),
            # --- Historical data sensors (fetched via HTTP API every 15 minutes) ---
            # Speculative: reuses Stream AC/Battery's app-dashboard metric codes,
            # unconfirmed against a real Microinverter account. Disabled by
            # default; enable to test whether they populate for your device.
            EnergySensorEntity(client, self, "history.solarGeneratedToday", const.STREAM_HISTORY_SOLAR_GENERATED_TODAY, False)
            .with_icon("mdi:solar-power")
            .with_unit_of_measurement("Wh")
            .with_state_class(SensorStateClass.TOTAL)
            .attr("history.solarGeneratedToday.beginTime", "Begin Time", "")
            .attr("history.solarGeneratedToday.endTime", "End Time", "")
            .attr("history.mainSn", "Main Device SN", ""),
            EnergySensorEntity(client, self, "history.solarGeneratedCumulative", const.STREAM_HISTORY_SOLAR_GENERATED_CUMULATIVE, False)
            .with_icon("mdi:solar-power")
            .with_unit_of_measurement("Wh")
            .with_state_class(SensorStateClass.TOTAL_INCREASING)
            .attr("history.solarGeneratedCumulative.beginTime", "Begin Time", "")
            .attr("history.solarGeneratedCumulative.endTime", "End Time", "")
            .attr("history.mainSn", "Main Device SN", ""),
            BaseSensorEntity(client, self, "history.environmentalImpactToday", const.STREAM_HISTORY_ENVIRONMENTAL_IMPACT_TODAY, False)
            .with_icon("mdi:molecule-co2")
            .with_unit_of_measurement("kg")
            .with_state_class(SensorStateClass.TOTAL)
            .attr("history.environmentalImpactToday.beginTime", "Begin Time", "")
            .attr("history.environmentalImpactToday.endTime", "End Time", "")
            .attr("history.mainSn", "Main Device SN", ""),
            BaseSensorEntity(client, self, "history.environmentalImpactCumulative", const.STREAM_HISTORY_ENVIRONMENTAL_IMPACT_CUMULATIVE, False)
            .with_icon("mdi:molecule-co2")
            .with_unit_of_measurement("kg")
            .with_state_class(SensorStateClass.TOTAL_INCREASING)
            .attr("history.environmentalImpactCumulative.beginTime", "Begin Time", "")
            .attr("history.environmentalImpactCumulative.endTime", "End Time", "")
            .attr("history.mainSn", "Main Device SN", ""),
            StreamACMonetarySensorEntity(client, self, "history.solarEnergySavingsToday", const.STREAM_HISTORY_TOTAL_SOLAR_SAVINGS_TODAY, "history.solarEnergySavingsUnit", False)
            .with_icon("mdi:cash")
            .with_state_class(SensorStateClass.TOTAL)
            .attr("history.solarEnergySavingsToday.beginTime", "Begin Time", "")
            .attr("history.solarEnergySavingsToday.endTime", "End Time", "")
            .attr("history.solarEnergySavingsUnit", "Currency Unit", "")
            .attr("history.mainSn", "Main Device SN", ""),
            StreamACMonetarySensorEntity(client, self, "history.solarEnergySavingsCumulative", const.STREAM_HISTORY_TOTAL_SOLAR_SAVINGS_CUMULATIVE, "history.solarEnergySavingsUnit", False)
            .with_icon("mdi:cash")
            .with_state_class(SensorStateClass.TOTAL_INCREASING)
            .attr("history.solarEnergySavingsCumulative.beginTime", "Begin Time", "")
            .attr("history.solarEnergySavingsCumulative.endTime", "End Time", "")
            .attr("history.solarEnergySavingsUnit", "Currency Unit", "")
            .attr("history.mainSn", "Main Device SN", ""),
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
        # The cloud throttles the microinverter to a ~15-min heartbeat once the
        # streaming window after (re)connect expires, and /device/quota/all
        # returns no params for it, so quota-based fallbacks are useless here.
        # Keep the real-time stream alive at the MQTT level instead.
        return MqttKeepaliveStatusSensorEntity(client, self)
