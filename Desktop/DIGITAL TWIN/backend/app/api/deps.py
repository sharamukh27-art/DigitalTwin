"""Shared FastAPI dependencies."""

from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel

from app.models.network import Network
from app.twin import repository


class Pagination(BaseModel):
    """Standard list paging parameters."""

    limit: int
    offset: int


def pagination(
    limit: Annotated[int, Query(ge=1, le=500, description="Maximum items to return")] = 50,
    offset: Annotated[int, Query(ge=0, description="Items to skip")] = 0,
) -> Pagination:
    """Read ?limit=&offset= from the query string."""
    return Pagination(limit=limit, offset=offset)


async def existing_network(network_id: str) -> Network:
    """Load the network named in the path. Raises NotFound when it does not exist."""
    return await repository.get_network(network_id)


PaginationDep = Annotated[Pagination, Depends(pagination)]
NetworkDep = Annotated[Network, Depends(existing_network)]
