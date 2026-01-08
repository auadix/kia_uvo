"""Config flow for Hyundai / Kia Connect integration."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from hyundai_kia_connect_api import Token, VehicleManager
from hyundai_kia_connect_api.exceptions import AuthenticationError
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_PIN,
    CONF_REGION,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
    BRANDS,
    CONF_BRAND,
    CONF_FORCE_REFRESH_INTERVAL,
    CONF_NO_FORCE_REFRESH_HOUR_FINISH,
    CONF_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_FORCE_REFRESH_INTERVAL,
    DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
    DEFAULT_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_PIN,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    REGIONS,
    CONF_ENABLE_GEOLOCATION_ENTITY,
    CONF_USE_EMAIL_WITH_GEOCODE_API,
    DEFAULT_ENABLE_GEOLOCATION_ENTITY,
    DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
    REGION_EUROPE,
    REGION_USA,
    BRAND_HYUNDAI,
    BRAND_KIA,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_REGION_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_CREDENTIALS_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
    }
)

STEP_OTP_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("otp_code"): str
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=15, max=999)
        ),
        vol.Required(
            CONF_FORCE_REFRESH_INTERVAL,
            default=DEFAULT_FORCE_REFRESH_INTERVAL,
        ): vol.All(vol.Coerce(int), vol.Range(min=90, max=9999)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_START,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_START,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_FINISH,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Optional(
            CONF_ENABLE_GEOLOCATION_ENTITY,
            default=DEFAULT_ENABLE_GEOLOCATION_ENTITY,
        ): bool,
        vol.Optional(
            CONF_USE_EMAIL_WITH_GEOCODE_API,
            default=DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
        ): bool,
    }
)


class OtpRequiredException(Exception):
    """Raised when OTP verification is required."""
    
    def __init__(self, otp_context: dict, api=None):
        self.otp_context = otp_context
        self.api = api
        super().__init__("OTP verification required")


def _check_api_has_otp_support(api) -> bool:
    """Check if the API instance has OTP support methods."""
    return hasattr(api, 'start_login') and hasattr(api, 'verify_otp_and_complete_login')


async def validate_input(hass: HomeAssistant, user_input: dict[str, Any]) -> Token:
    """Validate the user input allows us to connect.
    
    For Kia USA with OTP support, uses start_login which may raise OtpRequiredException.
    Falls back to standard login() for other regions or if OTP methods unavailable.
    """
    try:
        is_kia_usa = (
            REGIONS[user_input[CONF_REGION]] == REGION_USA 
            and BRANDS[user_input[CONF_BRAND]] == BRAND_KIA
        )
        
        # Get the API implementation
        api = VehicleManager.get_implementation_by_region_brand(
            user_input[CONF_REGION],
            user_input[CONF_BRAND],
            language=hass.config.language,
        )
        
        if is_kia_usa and _check_api_has_otp_support(api):
            _LOGGER.debug(f"{DOMAIN} - Using OTP-enabled login flow for Kia USA")
            
            # Call start_login which returns (Token, None) or (None, otp_context)
            result = await hass.async_add_executor_job(
                api.start_login,
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
                None,  # No existing token
            )
            
            token, otp_context = result
            
            if otp_context is not None:
                # OTP is required - add device_id and api to context
                otp_context["device_id"] = api.device_id
                raise OtpRequiredException(otp_context, api=api)
            
            if token is None:
                raise InvalidAuth
            
            return token
        else:
            # Standard flow for other regions or if OTP not supported
            _LOGGER.debug(f"{DOMAIN} - Using standard login flow")
            
            token: Token = await hass.async_add_executor_job(
                api.login, user_input[CONF_USERNAME], user_input[CONF_PASSWORD]
            )

            if token is None:
                raise InvalidAuth

            return token
    except AuthenticationError as err:
        raise InvalidAuth from err


class HyundaiKiaConnectOptionFlowHandler(config_entries.OptionsFlow):
    """Handle an option flow for Hyundai / Kia Connect."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle options init setup."""

        if user_input is not None:
            return self.async_create_entry(
                title=self.config_entry.title, data=user_input
            )

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, self.config_entry.options
            ),
        )


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Hyundai / Kia Connect."""

    VERSION = 2
    reauth_entry: ConfigEntry | None = None

    def __init__(self):
        """Initialize the config flow."""
        self._region_data = None
        self._otp_context = None
        self._api = None  # Store the API instance for OTP verification

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry):
        """Initiate options flow instance."""
        return HyundaiKiaConnectOptionFlowHandler()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step for region/brand selection."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_REGION_DATA_SCHEMA
            )

        self._region_data = user_input
        if REGIONS[self._region_data[CONF_REGION]] == REGION_EUROPE and (
            BRANDS[self._region_data[CONF_BRAND]] == BRAND_KIA
            or BRANDS[self._region_data[CONF_BRAND]] == BRAND_HYUNDAI
        ):
            return await self.async_step_credentials_token()
        return await self.async_step_credentials_password()

    async def async_step_credentials_password(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step."""
        errors = {}

        if user_input is not None:
            # Combine region data with credentials
            full_config = {**self._region_data, **user_input}

            try:
                token = await validate_input(self.hass, full_config)
                
                # Store token data for persistence
                full_config["token_data"] = {
                    "access_token": token.access_token,
                    "refresh_token": getattr(token, "refresh_token", None),
                    "device_id": getattr(token, "device_id", None),
                    "valid_until": token.valid_until.isoformat() if token.valid_until else None,
                }
                
            except OtpRequiredException as otp_ex:
                # Store context for OTP step
                self._otp_context = otp_ex.otp_context
                self._otp_context["input"] = full_config
                self._api = otp_ex.api
                
                # Send OTP automatically
                if self._api and self._otp_context.get("otpKey"):
                    try:
                        await self.hass.async_add_executor_job(
                            self._api.send_otp,
                            self._otp_context["otpKey"],
                            "EMAIL",  # Default to email
                            self._otp_context.get("xid", ""),
                        )
                        _LOGGER.info(f"{DOMAIN} - OTP sent to email")
                    except Exception as e:
                        _LOGGER.error(f"{DOMAIN} - Failed to send OTP: {e}")
                        errors["base"] = "unknown"
                        return self.async_show_form(
                            step_id="credentials_password",
                            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
                            errors=errors,
                        )
                
                return await self.async_step_otp()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception as ex:  # pylint: disable=broad-except
                _LOGGER.exception(f"Unexpected exception: {ex}")
                errors["base"] = "unknown"
            else:
                if self.reauth_entry is None:
                    title = f"{BRANDS[self._region_data[CONF_BRAND]]} {REGIONS[self._region_data[CONF_REGION]]} {user_input[CONF_USERNAME]}"
                    await self.async_set_unique_id(
                        hashlib.sha256(title.encode("utf-8")).hexdigest()
                    )
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=title, data=full_config)
                else:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry, data=full_config
                    )
                    await self.hass.config_entries.async_reload(
                        self.reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="credentials_password",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_otp(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle OTP verification step."""
        errors = {}
        
        if user_input is not None:
            otp_code = user_input["otp_code"]
            full_config = self._otp_context["input"]
            
            try:
                if self._api is None:
                    # Recreate API if needed
                    self._api = VehicleManager.get_implementation_by_region_brand(
                        full_config[CONF_REGION],
                        full_config[CONF_BRAND],
                        language=self.hass.config.language,
                    )
                    # Restore device_id
                    if self._otp_context.get("device_id"):
                        self._api.device_id = self._otp_context["device_id"]
                
                # Verify OTP and complete login
                token = await self.hass.async_add_executor_job(
                    self._api.verify_otp_and_complete_login,
                    full_config[CONF_USERNAME],
                    full_config[CONF_PASSWORD],
                    self._otp_context["otpKey"],
                    self._otp_context.get("xid", ""),
                    otp_code,
                )
                
                # Store token data for persistence (including rmtoken)
                full_config["token_data"] = {
                    "access_token": token.access_token,
                    "refresh_token": getattr(token, "refresh_token", None),  # This is the rmtoken!
                    "device_id": getattr(token, "device_id", None),
                    "valid_until": token.valid_until.isoformat() if token.valid_until else None,
                }
                
                _LOGGER.info(f"{DOMAIN} - OTP verification successful, rmtoken stored for future logins")
                
                # If success
                if self.reauth_entry is None:
                    title = f"{BRANDS[full_config[CONF_BRAND]]} {REGIONS[full_config[CONF_REGION]]} {full_config[CONF_USERNAME]}"
                    await self.async_set_unique_id(
                        hashlib.sha256(title.encode("utf-8")).hexdigest()
                    )
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=title, data=full_config)
                else:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry, data=full_config
                    )
                    await self.hass.config_entries.async_reload(
                        self.reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

            except Exception as e:
                _LOGGER.exception(f"OTP Verification Failed: {e}")
                errors["base"] = "invalid_auth"

        email_hint = self._otp_context.get("email", self._otp_context["input"].get(CONF_USERNAME, "your email"))
        
        return self.async_show_form(
            step_id="otp",
            data_schema=STEP_OTP_DATA_SCHEMA,
            errors=errors,
            description_placeholders={"email": email_hint}
        )

    async def async_step_credentials_token(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step for EU (token-based)."""
        errors = {}

        if user_input is not None:
            # Combine region data with credentials
            full_config = {**self._region_data, **user_input}

            try:
                token = await validate_input(self.hass, full_config)
                
                # Store token data for persistence
                full_config["token_data"] = {
                    "access_token": token.access_token,
                    "refresh_token": getattr(token, "refresh_token", None),
                    "device_id": getattr(token, "device_id", None),
                    "valid_until": token.valid_until.isoformat() if token.valid_until else None,
                }
                
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                if self.reauth_entry is None:
                    title = f"{BRANDS[self._region_data[CONF_BRAND]]} {REGIONS[self._region_data[CONF_REGION]]} {user_input[CONF_USERNAME]}"
                    await self.async_set_unique_id(
                        hashlib.sha256(title.encode("utf-8")).hexdigest()
                    )
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=title, data=full_config)
                else:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry, data=full_config
                    )
                    await self.hass.config_entries.async_reload(
                        self.reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="credentials_token",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, user_input=None):
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({}),
            )
        self._reauth_config = True
        return await self.async_step_user()


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
