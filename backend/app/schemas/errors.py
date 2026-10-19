from uuid import UUID

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    field: str | None
    issue: str
    limit: int | None = None


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: UUID
    # Present only on 422 responses.
    details: list[ErrorDetail] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorBody
