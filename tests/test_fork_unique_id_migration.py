"""Tests for moving the earlier fork's renamed entities onto upstream's keys."""

from collections.abc import Callable, Iterable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from custom_components.kia_uvo import _async_migrate_fork_unique_ids


def _entry(entity_id: str, unique_id: str) -> MagicMock:
    return MagicMock(
        entity_id=entity_id, unique_id=unique_id, domain=entity_id.split(".")[0]
    )


async def _migrate(
    entries: Iterable[MagicMock], existing: Iterable[str] = ()
) -> dict[str, Any]:
    """Run the migration over ``entries``; return each entity's update or None."""
    taken = set(existing)
    registry = MagicMock()
    registry.async_get_entity_id.side_effect = lambda _domain, _platform, uid: (
        "binary_sensor.taken" if uid in taken else None
    )
    results: dict[str, Any] = {}

    async def run_callback(
        _hass: Any, _entry_id: str, callback: Callable[[Any], Any]
    ) -> None:
        for entry in entries:
            results[entry.entity_id] = callback(entry)

    with (
        patch("custom_components.kia_uvo.er.async_get", return_value=registry),
        patch("custom_components.kia_uvo.er.async_migrate_entries", run_callback),
    ):
        await _async_migrate_fork_unique_ids(MagicMock(), MagicMock(entry_id="e1"))
    return results


@pytest.mark.asyncio
async def test_renamed_keys_move_to_upstream_unique_ids() -> None:
    results = await _migrate(
        [
            _entry("binary_sensor.car_hazard_lights", "kia_uvo_v1_hazard_status"),
            _entry(
                "binary_sensor.car_engine_oil_warning",
                "kia_uvo_v1_engine_oil_warning_is_on",
            ),
        ]
    )
    assert results == {
        "binary_sensor.car_hazard_lights": {
            "new_unique_id": "kia_uvo_v1_hazard_lights_on"
        },
        "binary_sensor.car_engine_oil_warning": {
            "new_unique_id": "kia_uvo_v1_oil_level_warning_is_on"
        },
    }


@pytest.mark.asyncio
async def test_other_entities_are_left_alone() -> None:
    results = await _migrate(
        [
            _entry("binary_sensor.car_tail_lamp_fault", "kia_uvo_v1_tail_lamp_status"),
            _entry("sensor.car_hazard_status", "kia_uvo_v1_hazard_status"),
        ]
    )
    assert results == {
        "binary_sensor.car_tail_lamp_fault": None,
        "sensor.car_hazard_status": None,
    }


@pytest.mark.asyncio
async def test_skips_when_upstream_entity_already_exists() -> None:
    results = await _migrate(
        [_entry("binary_sensor.car_hazard_lights", "kia_uvo_v1_hazard_status")],
        existing={"kia_uvo_v1_hazard_lights_on"},
    )
    assert results == {"binary_sensor.car_hazard_lights": None}
