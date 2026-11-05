"""Tests for the Kia USA status entities carried over from the auadix fork."""

from collections.abc import Awaitable, Callable
from typing import Any

from hyundai_kia_connect_api import Vehicle
import pytest

from custom_components.kia_uvo.binary_sensor import (
    SENSOR_DESCRIPTIONS as BINARY_DESCRIPTIONS,
)

SENSOR_KEYS = {
    "_distance_to_empty",
    "_location_heading",
    "_location_speed",
    "weather_type",
    "valet_parking_mode",
    "car_battery_warning",
    "rsa_status",
    "link_status",
}
BINARY_KEYS = {
    "valet_parking_mode",
    "remote_control_available",
    "tail_lamp_status",
    "stop_lamp_status",
    "finance_registered",
}

Setup = Callable[..., Awaitable[dict[str, Any]]]


def _reporting_vehicle() -> Vehicle:
    vehicle = Vehicle(id="v1", name="test", model="test")
    vehicle.distance_to_empty = (195.0, "mi")
    vehicle.location_speed = (0, "mph")
    vehicle.location_heading = 162
    vehicle.weather_type = "Clear"
    vehicle.valet_parking_mode = False
    vehicle.car_battery_warning = 100
    vehicle.rsa_status = 0
    vehicle.link_status = 0
    vehicle.remote_control_available = True
    vehicle.tail_lamp_status = 0
    vehicle.stop_lamp_status = False
    vehicle.finance_registered = True
    return vehicle


@pytest.mark.asyncio
async def test_created_with_fork_keys_when_reported(
    setup_sensors: Setup, setup_binary_sensors: Setup
) -> None:
    assert SENSOR_KEYS <= set(await setup_sensors(_reporting_vehicle()))
    assert BINARY_KEYS <= set(await setup_binary_sensors(_reporting_vehicle()))


@pytest.mark.asyncio
async def test_not_created_when_not_reported(
    setup_sensors: Setup, setup_binary_sensors: Setup
) -> None:
    vehicle = Vehicle(id="v1", name="test", model="test")
    assert not SENSOR_KEYS & set(await setup_sensors(vehicle))
    assert not BINARY_KEYS & set(await setup_binary_sensors(vehicle))


@pytest.mark.asyncio
async def test_speed_and_distance_use_the_reported_unit(setup_sensors: Setup) -> None:
    sensors = await setup_sensors(_reporting_vehicle())
    assert sensors["_location_speed"].native_unit_of_measurement == "mph"
    assert sensors["_distance_to_empty"].native_unit_of_measurement == "mi"


@pytest.mark.parametrize(("code", "expected"), [(None, None), (0, False), (1, True)])
def test_tail_lamp_fault_follows_the_status_code(
    code: int | None, expected: bool | None
) -> None:
    vehicle = Vehicle(id="v1")
    vehicle.tail_lamp_status = code
    description = next(d for d in BINARY_DESCRIPTIONS if d.key == "tail_lamp_status")
    assert description.is_on is not None
    assert description.is_on(vehicle) is expected
