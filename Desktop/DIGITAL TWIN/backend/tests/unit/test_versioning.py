"""Network version counter."""

from datetime import timedelta
from typing import Any

import pytest

from app.core import db
from app.core.errors import NotFound
from app.models.network import Network
from app.twin import repository
from app.twin.versioning import bump_version


async def test_bump_increments_version_and_updated_at(database: Any) -> None:
    network = await repository.insert_network(Network(name="n"))
    earlier = network.updated_at - timedelta(hours=1)
    await db.collection(db.NETWORKS).update_one({"id": network.id}, {"$set": {"updated_at": earlier}})

    assert await bump_version(network.id) == 2
    assert await bump_version(network.id) == 3

    stored = await repository.get_network(network.id)
    assert stored.version == 3
    assert stored.updated_at > earlier
    assert stored.created_at == network.created_at


async def test_bump_unknown_network_raises_not_found(database: Any) -> None:
    with pytest.raises(NotFound):
        await bump_version("missing")
