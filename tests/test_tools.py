from __future__ import annotations

from typing import override

from langchain_tests.unit_tests import ToolsUnitTests
from pydantic import SecretStr

from langchain_pangea import (
    PangeaAIGuard,
    PangeaDomainIntelGuard,
    PangeaIpIntelGuard,
    PangeaRedactGuard,
    PangeaUrlIntelGuard,
)


class TestAIGuard(ToolsUnitTests):
    @override
    @property
    def tool_constructor(self) -> type[PangeaAIGuard]:
        return PangeaAIGuard

    @override
    @property
    def tool_constructor_params(self) -> dict:
        return {"token": SecretStr("my_api_token")}

    @override
    @property
    def tool_invoke_params_example(self) -> dict:
        return {"input_data": "foo"}


class TestDomainIntel(ToolsUnitTests):
    @override
    @property
    def tool_constructor(self) -> type[PangeaDomainIntelGuard]:
        return PangeaDomainIntelGuard

    @override
    @property
    def tool_constructor_params(self) -> dict:
        return {"token": SecretStr("my_api_token")}

    @override
    @property
    def tool_invoke_params_example(self) -> dict:
        return {"input_data": "foo"}


class TestIpIntel(ToolsUnitTests):
    @override
    @property
    def tool_constructor(self) -> type[PangeaIpIntelGuard]:
        return PangeaIpIntelGuard

    @override
    @property
    def tool_constructor_params(self) -> dict:
        return {"token": SecretStr("my_api_token")}

    @override
    @property
    def tool_invoke_params_example(self) -> dict:
        return {"input_data": "foo"}


class TestRedact(ToolsUnitTests):
    @override
    @property
    def tool_constructor(self) -> type[PangeaRedactGuard]:
        return PangeaRedactGuard

    @override
    @property
    def tool_constructor_params(self) -> dict:
        return {"token": SecretStr("my_api_token")}

    @override
    @property
    def tool_invoke_params_example(self) -> dict:
        return {"input_data": "foo"}


class TestUrlIntel(ToolsUnitTests):
    @override
    @property
    def tool_constructor(self) -> type[PangeaUrlIntelGuard]:
        return PangeaUrlIntelGuard

    @override
    @property
    def tool_constructor_params(self) -> dict:
        return {"token": SecretStr("my_api_token")}

    @override
    @property
    def tool_invoke_params_example(self) -> dict:
        return {"input_data": "foo"}
