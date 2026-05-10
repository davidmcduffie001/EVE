"""Small SQLAlchemy repository primitive for simple model persistence."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyRepository[ModelT]:
    """Minimal repository wrapper around an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession, model_type: type[ModelT]) -> None:
        """Initialize the repository for a specific ORM model type."""
        self.session = session
        self.model_type = model_type

    async def add(self, model: ModelT) -> ModelT:
        """Persist a model and flush generated defaults."""
        self.session.add(model)
        await self.session.flush()
        return model

    async def get(self, model_id: UUID | str) -> ModelT | None:
        """Fetch a model by primary key."""
        return await self.session.get(self.model_type, model_id)
