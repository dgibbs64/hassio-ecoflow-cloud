import hashlib
import hmac
import logging
import random
import time

import aiohttp

from ..device_data import DeviceData
from ..devices import DiagnosticDevice, EcoflowDeviceInfo
from . import EcoflowApiClient

_LOGGER = logging.getLogger(__name__)

# from FB
# client_id limits for MQTT connections
# If you are using MQTT to connect to the API be aware that only 10 unique client IDs are allowed per day.
# As such, it is suggested that you choose a static client_id for your application or integration to use consistently.
# If your code generates a unique client_id (as mine did) for each connection,
# you can exceed this limit very quickly when testing or debugging code.


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
        response = await self.call_api("/certification")
        self._accept_mqqt_certification(response)
        self.mqtt_info.client_id = (
            f"Hassio-{self.mqtt_info.username}-{self.group.replace(' ', '-')}"
        )

    async def fetch_all_available_devices(self) -> list[EcoflowDeviceInfo]:
        _LOGGER.info("Requesting all devices")
        response = await self.call_api("/device/list")
        result = list()
        for device in response["data"]:
            _LOGGER.debug(str(device))
            sn = device["sn"]
            product_name = device.get("productName", "undefined")
            if product_name == "undefined":
                from ..devices.registry import device_by_product

                device_list = list(device_by_product.keys())
                for devicetype in device_list:
                    if "deviceName" in device and device[
                        "deviceName"
                    ].lower().startswith(devicetype.lower()):
                        product_name = devicetype
            device_name = device.get("deviceName", f"{product_name}-{sn}")
            status = int(device["online"])
            result.append(
                self.__create_device_info(sn, device_name, product_name, status)
            )

        return result

    def configure_device(self, device_data: DeviceData):
        if device_data.parent is not None:
            info = self.__create_device_info(
                device_data.parent.sn, device_data.name, device_data.parent.device_type
            )
        else:
            info = self.__create_device_info(
                device_data.sn, device_data.name, device_data.device_type
            )

        from custom_components.ecoflow_cloud.devices.registry import device_by_product

        if device_data.device_type in device_by_product:
            device = device_by_product[device_data.device_type](info, device_data)
        elif (
            device_data.parent is not None
            and device_data.parent.device_type in device_by_product
        ):
            device = device_by_product[device_data.parent.device_type](
                info, device_data
            )
        else:
            device = DiagnosticDevice(info, device_data)

        self.add_device(device)
        return device

    async def quota_all(self, device_sn: str | None):
        if not device_sn:
            target_devices = self.devices.keys()
            # update all statuses
            devices = await self.fetch_all_available_devices()
            for device in devices:
                if device.sn in self.devices:
                    self.devices[device.sn].data.update_status(
                        {"params": {"status": device.status}}
                    )
        else:
            target_devices = [device_sn]

        for sn in target_devices:
            try:
                raw = await self.call_api("/device/quota/all", {"sn": sn})
                if "data" in raw:
                    self.devices[sn].data.update_data({"params": raw["data"]})
            except Exception as exception:
                _LOGGER.error(exception, exc_info=True)
                _LOGGER.error("Error retrieving %s", sn)

    async def call_api(self, endpoint: str, params: dict[str, str] = None) -> dict:
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
            resp = await session.get(
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

    def __create_device_info(
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
        target_str = (
            f"accessKey={self.access_key}&nonce={self.nonce}&timestamp={self.timestamp}"
        )
        if query_params:
            target_str = query_params + "&" + target_str

        return self.__encrypt_hmac_sha256(target_str, self.secret_key)

    def __sort_and_concat_params(self, params: dict[str, str]) -> str:
        # Sort the dictionary items by key
        sorted_items = sorted(params.items(), key=lambda x: x[0])

        # Create a list of "key=value" strings
        param_strings = [f"{key}={value}" for key, value in sorted_items]

        # Join the strings with '&'
        return "&".join(param_strings)

    def __encrypt_hmac_sha256(self, message: str, secret_key: str) -> str:
        # Convert the message and secret key to bytes
        message_bytes = message.encode("utf-8")
        secret_bytes = secret_key.encode("utf-8")

        # Create the HMAC
        hmac_obj = hmac.new(secret_bytes, message_bytes, hashlib.sha256)

        # Get the hexadecimal representation of the HMAC
        hmac_digest = hmac_obj.hexdigest()

        return hmac_digest

    async def call_api_post(
        self, endpoint: str, json_body: dict[str, any] = None
    ) -> dict:
        """Call the EcoFlow API with a POST request and JSON body."""
        self.nonce = str(random.randint(10000, 1000000))
        self.timestamp = str(int(time.time() * 1000))
        async with aiohttp.ClientSession() as session:
            sign = self.__gen_sign(None)

            headers = {
                "accessKey": self.access_key,
                "nonce": self.nonce,
                "timestamp": self.timestamp,
                "sign": sign,
                "Content-Type": "application/json",
            }

            _LOGGER.debug("POST Request: %s %s.", str(endpoint), str(json_body))
            resp = await session.post(
                f"https://{self.api_domain}/iot-open/sign{endpoint}",
                headers=headers,
                json=json_body,
            )
            json_resp = await self._get_json_response(resp)
            _LOGGER.debug(
                "POST Request: %s %s. Response : %s",
                str(endpoint),
                str(json_body),
                str(json_resp),
            )
            return json_resp

    async def fetch_daily_solar_energy(
        self, device_sn: str, date_str: str
    ) -> int | None:
        """Fetch daily solar energy for a device.

        Args:
            device_sn: The serial number of the device
            date_str: The date in YYYY-MM-DD format

        Returns:
            The solar energy in watt-hours or None if the request fails
        """
        try:
            json_body = {
                "sn": device_sn,
                "params": {
                    "beginTime": f"{date_str} 00:00:00",
                    "endTime": f"{date_str} 23:59:59",
                    "code": "BK621-App-HOME-SOLAR-ENERGY-FLOW-solor-line-NOTDISTINGUISH-MASTER_DATA",
                },
            }
            response = await self.call_api_post("/device/param/query/EnergyFlow", json_body)

            # Parse response: {"data": {"data": [{"unit": "wh", "indexName": "master_data", "indexValue": "9945"}]}}
            if (
                "data" in response
                and isinstance(response["data"], dict)
                and "data" in response["data"]
            ):
                data_list = response["data"]["data"]
                if isinstance(data_list, list):
                    for item in data_list:
                        if (
                            isinstance(item, dict)
                            and item.get("indexName") == "master_data"
                        ):
                            try:
                                return int(item.get("indexValue", 0))
                            except (TypeError, ValueError):
                                _LOGGER.warning(
                                    "Invalid indexValue in solar energy response: %s",
                                    item.get("indexValue"),
                                )
                                return None
            _LOGGER.debug("No solar energy data found in response: %s", response)
            return None
        except Exception as e:
            _LOGGER.error("Error fetching daily solar energy: %s", e)
            return None
