from __future__ import annotations

from kingsec.domain.notification import NotificationChannel, NotificationTemplate
from kingsec.infrastructure.notifications.templates import JinjaTemplateRenderer


class TestJinjaTemplateRenderer:
    def setup_method(self) -> None:
        self.renderer = JinjaTemplateRenderer()

    def test_render_simple(self) -> None:
        template = NotificationTemplate(
            event_type="test",
            channel=NotificationChannel.EMAIL,
            subject_template="Hello {{name}}",
            body_template="Welcome {{name}}!",
        )
        subject, body = self.renderer.render(template, {"name": "Alice"})
        assert subject == "Hello Alice"
        assert body == "Welcome Alice!"

    def test_render_missing_var_keeps_placeholder(self) -> None:
        template = NotificationTemplate(
            event_type="test",
            channel=NotificationChannel.EMAIL,
            subject_template="Hi {{name}}",
            body_template="Body",
        )
        subject, body = self.renderer.render(template, {})
        assert subject == "Hi {{name}}"
        assert body == "Body"

    def test_get_default_template_exists(self) -> None:
        template = self.renderer.get_template("scan_completed", "email")
        assert template is not None
        assert template.event_type == "scan_completed"

    def test_get_default_template_unknown(self) -> None:
        template = self.renderer.get_template("unknown_event", "email")
        assert template is None

    def test_register_custom_template(self) -> None:
        custom = NotificationTemplate(
            event_type="custom_event",
            channel=NotificationChannel.SLACK,
            subject_template="Custom: {{x}}",
            body_template="Body: {{x}}",
        )
        self.renderer.register_template(custom)
        retrieved = self.renderer.get_template("custom_event", "slack")
        assert retrieved is not None
        subj, body = self.renderer.render(retrieved, {"x": "val"})
        assert subj == "Custom: val"
        assert body == "Body: val"
