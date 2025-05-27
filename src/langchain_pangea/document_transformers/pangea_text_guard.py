from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from langchain_core.documents import BaseDocumentTransformer, Document
from pangea.services import AIGuard
from pydantic import SecretStr

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pangea import PangeaConfig


class PangeaGuardTransformer(BaseDocumentTransformer):
    """Guard documents to monitor, sanitize, and protect sensitive data using Pangea's AI Guard service.

    Requirements:
        - Environment variable ``PANGEA_AI_GUARD_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    Example:
        .. code-block:: python

            from langchain_community.document_transformers.pangea_text_guard import PangeaGuardTransformer, PangeaConfig

            # Initialize parameters
            token = SecretStr(os.getenv("PANGEA_AI_GUARD_TOKEN"))
            config = PangeaConfig(domain="aws.us.pangea.cloud")
            recipe="pangea_ingestion_guard"

            pangea_guard_transformer = PangeaGuardTransformer(token=token, config_id="", config=config, recipe=recipe)
            guarded_documents = pangea_guard_transformer.transform_documents(docs)
    """

    _client: AIGuard
    _recipe: str

    def __init__(
        self,
        token: SecretStr | None = None,
        config: PangeaConfig | None = None,
        config_id: str | None = None,
        recipe: str = "pangea_ingestion_guard",
        token_env_key_name: str = "PANGEA_AI_GUARD_TOKEN",
    ) -> None:
        """
        Args:
            token: Pangea AI Guard API token.
            config_id: Pangea AI Guard configuration ID.
            config: PangeaConfig object.
            recipe: Pangea AI Guard recipe.
            token_env_key_name: Environment variable key name for Pangea AI Guard token.
        """

        if not token:
            token = SecretStr(os.getenv(token_env_key_name, ""))

        if not token or not token.get_secret_value() or token.get_secret_value() == "":
            raise ValueError(f"'{token_env_key_name}' must be set or passed")

        self._recipe = recipe
        self._client = AIGuard(token=token.get_secret_value(), config=config, config_id=config_id)

    async def atransform_documents(self, documents: Sequence[Document], **kwargs: Any) -> Sequence[Document]:
        raise NotImplementedError

    def transform_documents(self, documents: Sequence[Document], **kwargs: Any) -> Sequence[Document]:
        """
        Guard documents to monitor, sanitize, and protect sensitive data
        using Pangea's AI Guard service.
        """

        guarded_documents = []
        for document in documents:
            guarded = self._client.guard_text(document.page_content, recipe=self._recipe)

            if not guarded.result:
                raise AssertionError(f"Guard operation failed for document: {document}")

            guarded_content = guarded.result.prompt_text or document.page_content
            guarded_documents.append(document.model_copy(update={"page_content": guarded_content}))

        return guarded_documents
