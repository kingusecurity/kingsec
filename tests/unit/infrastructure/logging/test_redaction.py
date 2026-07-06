"""Secret redaction across all three strategies."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import SecretStr

from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.logging.redaction import REDACTED


class TestRedactByKey:
    def test_sensitive_keys_are_masked(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        get_logger("kingsec.test").info(
            "auth attempt",
            password="hunter2",
            api_key="sk-ABCDEFGHIJKLMNOP",
            authorization="Bearer xyz",
            username="alice",  # benign, must survive
        )

        (line,) = read_json()
        assert line["password"] == REDACTED
        assert line["api_key"] == REDACTED
        assert line["authorization"] == REDACTED
        assert line["username"] == "alice"

        # No raw secret anywhere in the serialised line.
        blob = str(line)
        assert "hunter2" not in blob
        assert "sk-ABCDEFGHIJKLMNOP" not in blob


class TestRedactSecretStr:
    def test_secretstr_value_is_masked_without_being_read(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        # Field key is NOT sensitive-looking, so only type-based redaction can
        # catch this. Proves the SecretStr duck-typing path works.
        get_logger("kingsec.test").info("payload", value=SecretStr("top-secret"))

        (line,) = read_json()
        assert line["value"] == REDACTED
        assert "top-secret" not in str(line)


class TestRedactNested:
    def test_nested_dicts_and_lists_are_walked(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        get_logger("kingsec.test").info(
            "config dump",
            data={"headers": [{"authorization": "Bearer deadbeef"}], "host": "127.0.0.1"},
        )

        (line,) = read_json()
        assert line["data"]["headers"][0]["authorization"] == REDACTED
        assert line["data"]["host"] == "127.0.0.1"
        assert "deadbeef" not in str(line)


class TestRedactFreeText:
    def test_token_shapes_in_message_are_masked(
        self, configure: Callable[..., object], read_json: Callable[[], list[dict]]
    ) -> None:
        configure(json_format=True)
        get_logger("kingsec.test").info(
            "raw dump: sk-ABCDEFGHIJKLMNOPQRST and Bearer aabbccddee and api_key=leaky"
        )

        (line,) = read_json()
        event = line["event"]
        assert "sk-ABCDEFGHIJKLMNOPQRST" not in event
        assert "aabbccddee" not in event
        assert "leaky" not in event
        # The label is preserved so the line is still readable.
        assert "api_key=" + REDACTED in event
