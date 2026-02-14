import hashlib
import hmac
import logging
import random
import time
from typing import Any

import aiohttp

from custom_components.ecoflow_cloud.devices.data_holder import PreparedData
from ..devices import EcoflowDeviceInfo
from . import EcoflowApiClient

_LOGGER = logging.getLogger(__name__)


class EcoflowPublicApiClient(EcoflowApiClient):
    def __init__(self, api_domain: str, access_key: str, secret_key: str, group: str):
        super().__init__()
        self.api_domain = api_domain
        self.access_key = access_key
        self.secret_key = secret_key
        self.group = group
        self.nonce = str(random.randint(10000, 1000000))
        self.timestamp = str(int(time.time() * 1000))

    async def login(self):
        _LOGGER.info("Requesting IoT MQTT credentials")
        response = await self.call_api("GET", "/certification")
        self._accept_mqqt_certification(response)
        self.mqtt_info.client_id = f"Hassio-{self.mqtt_info.username}-{self.group.replace(' ', '-')}"

    async def fetch_all_available_devices(self) -> list[EcoflowDeviceInfo]:
        _LOGGER.info("Requesting all devices")
        response = await self.call_api("GET", "/device/list")
        result = []

        def _as_int(value) -> int | None:
            try:
                if value is None:
                    return None
                return int(value)
            except (TypeError, ValueError):
                return None

        def _as_nonempty_str(value) -> str | None:
            if value is None:
                return None
            text = str(value).strip()
            if not text:
                return None
            if text.casefold() in {"undefined", "null", "none"}:
                return None
            return text

        def _get_first_int(device: dict, keys: list[str]) -> int | None:
            for key in keys:
                if key in device:
                    candidate = _as_int(device.get(key))
                    if candidate is not None:
                        return candidate
            for container_key in ("productInfo", "product", "productInfoVo"):
                container = device.get(container_key)
                if isinstance(container, dict):
                    for key in keys:
                        if key in container:
                            candidate = _as_int(container.get(key))
                            if candidate is not None:
                                return candidate
            return None

        def _summarize_device(device: dict) -> dict:
            keys_of_interest = {
                "sn", "deviceName", "productName", "productType",
                "productTypeId", "productDetail", "productDetailId", "online",
            }
            summary: dict[str, object] = {k: device[k] for k in keys_of_interest if k in device}
            for key, value in device.items():
                if key in summary:
                    continue
                if any(t in str(key).casefold() for t in ("model", "type", "name", "detail", "series")):
                    summary[key] = value
            return summary

        for device in response["data"]:
            sn = device.get("sn")
            if not sn:
                _LOGGER.debug("API /device/list returned device without sn: %s", _summarize_device(device))
                continue

            raw_product_name = device.get("productName")
            product_name = _as_nonempty_str(raw_product_name)

            # Stable numeric identifiers: these tend to be more reliable than productName.
            product_type = _get_first_int(device, ["productType", "productTypeId"])
            product_detail = _get_first_int(device, ["productDetail", "productDetailId"])

            # Stream AC/Pro/Ultra batteries are observed as productType=58 in quota payloads.
            # Some payloads also carry productDetail=5.
            if product_type == 58 or (product_type is None and product_detail == 5):
                product_name = "Stream Battery"

            # If productName is missing/undefined, try to infer from deviceName.
            if product_name is None:
                from ..devices.registry import device_by_product

                device_list = list(device_by_product.keys())
                device_name_raw = _as_nonempty_str(device.get("deviceName")) or ""

                for devicetype in device_list:
                    if device_name_raw.casefold().startswith(devicetype.casefold()):
                        product_name = devicetype
                        break

                # Stream family fallback: deviceName often starts with a Stream variant.
                if product_name is None and device_name_raw.casefold().startswith("stream"):
                    product_name = "Stream Battery"

            # Last resort: keep something non-empty for the UI/logs.
            if product_name is None:
                product_name = "undefined"

            # Canonicalize to a known product key when EcoFlow varies naming
            # (e.g. "Stream AC Pro" / "Stream Max").
            from ..devices.registry import canonical_product_name

            product_name = canonical_product_name(product_name)
            device_name = device.get("deviceName", f"{product_name}-{sn}")
            status = int(device["online"])
            result.append(self._create_device_info(sn, device_name, product_name, status))

            if product_name == "undefined":
                _LOGGER.debug(
                    "API /device/list could not infer productName for sn=%s; summary=%s",
                    sn,
                    _summarize_device(device),
                )

        return result

    def _device_registry(self) -> dict[str, Any]:
        from custom_components.ecoflow_cloud.devices.registry import device_by_product

        return device_by_product

    async def quota_all(self, device_sn: str | None):
        target_devices = [device_sn] if device_sn else list(self.devices)

        for sn in target_devices:
            try:
                raw = await self.call_api("GET", "/device/quota/all", {"sn": sn})
                if "data" in raw:
                    self.devices[sn].data.add_data(PreparedData(None, {"params": raw["data"]}, raw, False))
            except Exception as exception:
                _LOGGER.error(exception, exc_info=True)
                _LOGGER.error("Error retrieving %s", sn)

    async def call_api(self, method: str, endpoint: str, params: dict[str, Any] | None = None) -> dict:
        self.nonce = str(random.randint(10000, 1000000))
        self.timestamp = str(int(time.time() * 1000))
        async with aiohttp.ClientSession() as session:
            params_str = ""
            if params is not None:
                params_str = self.__sort_and_concat_params(params)

            sign = self.__gen_sign(params_str)

            headers = {
                "accessKey": self.access_key,
                "nonce": self.nonce,
                "timestamp": self.timestamp,
                "sign": sign,
            }

            _LOGGER.debug("Request: %s %s.", str(endpoint), str(params_str))
            resp = await session.request(
                method,
                f"https://{self.api_domain}/iot-open/sign{endpoint}?{params_str}",
                headers=headers,
            )
            json_resp = await self._get_json_response(resp)
            _LOGGER.debug(
                "Request: %s %s. Response : %s",
                str(endpoint),
                str(params_str),
                str(json_resp),
            )
            return json_resp

    def _create_device_info(
        self, device_sn: str, device_name: str, device_type: str, status: int = -1
    ) -> EcoflowDeviceInfo:
        return EcoflowDeviceInfo(
            public_api=True,
            sn=device_sn,
            name=device_name,
            device_type=device_type,
            status=status,
            data_topic=f"/open/{self.mqtt_info.username}/{device_sn}/quota",
            set_topic=f"/open/{self.mqtt_info.username}/{device_sn}/set",
            set_reply_topic=f"/open/{self.mqtt_info.username}/{device_sn}/set_reply",
            get_topic=None,
            get_reply_topic=None,
            status_topic=f"/open/{self.mqtt_info.username}/{device_sn}/status",
        )

    def __gen_sign(self, query_params: str | None) -> str:
        target_str = f"accessKey={self.access_key}&nonce={self.nonce}&timestamp={self.timestamp}"
        if query_params:
            target_str = query_params + "&" + target_str

        return self.__encrypt_hmac_sha256(target_str, self.secret_key)

    def __flatten_params(self, data: dict[str, Any]) -> list[tuple[str, str]]:
        def _flatten(prefix: str, value: Any) -> list[tuple[str, str]]:
            items: list[tuple[str, str]] = []
            if isinstance(value, dict):
                for k, v in value.items():
                    key = f"{prefix}.{k}" if prefix else k
                    items.extend(_flatten(key, v))
            elif isinstance(value, list):
                for idx, v in enumerate(value):
                    key = f"{prefix}[{idx}]"
                    items.extend(_flatten(key, v))
            else:
                items.append((prefix, str(value)))
            return items

        return _flatten("", data)

    def __sort_and_concat_params(self, params: dict[str, Any]) -> str:
        flat_params = self.__flatten_params(params)
        sorted_items = sorted(flat_params, key=lambda x: x[0])
        return "&".join(f"{key}={value}" for key, value in sorted_items)

    def __encrypt_hmac_sha256(self, message: str, secret_key: str) -> str:
        return hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
