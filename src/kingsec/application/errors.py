from __future__ import annotations


class ApplicationError(Exception):
    """Base class for errors owned by the application layer."""


class InputValidationError(ApplicationError):
    """A request DTO carried invalid or malformed input."""


class LicenseRequiredError(ApplicationError):
    """The requested action is gated behind a license edition the caller doesn't have.

    Raised at the use-case layer (not just the route layer) so the check
    cannot be bypassed by anything that calls the use case directly.
    """

    def __init__(self, feature: str, current_edition: str, required: str = "a paid") -> None:
        self.feature = feature
        self.current_edition = current_edition
        super().__init__(
            f"{feature} requires {required} edition; the current license edition "
            f"({current_edition}) does not include it."
        )


class AssessmentNotFoundError(ApplicationError):
    """No assessment exists for the requested identifier."""


class ReportNotFoundError(ApplicationError):
    """No report exists for the requested assessment."""


class ScannerPluginError(ApplicationError):
    """Base class for all scanner plugin framework errors."""


class ExecutionPlanUnsatisfiedError(ApplicationError):
    """A required scanner in the assessment's profile is unavailable at run time.

    Raised by the server-side re-validation that runs immediately before
    scanning starts - it never trusts an earlier client-side ``/plan``
    preview, since scanner availability can change in the gap between
    preview and execution.
    """


class ScannerUnavailableError(ScannerPluginError):
    def __init__(
        self,
        message: str,
        *,
        scanner_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.scanner_id = scanner_id


class ScannerConfigError(ScannerPluginError):
    """A scanner plugin received invalid configuration."""


class ScannerVersionError(ScannerPluginError):
    """A scanner plugin targets an incompatible API version."""


class ScannerDuplicateError(ScannerPluginError):
    """A scanner plugin with the same id is already registered."""


class ScannerTimeoutError(ScannerPluginError):
    """A scanner plugin exceeded its execution time limit."""


class JobNotFoundError(ApplicationError):
    """No job exists for the requested identifier."""


class IllegalJobTransitionError(ApplicationError):
    """A job state transition is not allowed by the state machine."""


class NotificationNotFoundError(ApplicationError):
    """No notification exists for the requested identifier."""


class PluginNotFoundError(ApplicationError):
    """No plugin exists for the requested identifier."""


class PluginInstallError(ApplicationError):
    """Plugin installation failed."""


class PluginValidationError(ApplicationError):
    """Plugin validation failed."""


class PluginIncompatibleError(ApplicationError):
    """Plugin is incompatible with this system."""


class PluginDependencyError(ApplicationError):
    """Plugin has unmet dependencies."""


class PluginChecksumError(ApplicationError):
    """Plugin checksum verification failed."""


class PluginSignatureError(ApplicationError):
    """Plugin signature verification failed."""


class AgentNotFoundError(ApplicationError):
    """No agent exists for the requested identifier."""


class QueueEntryNotFoundError(ApplicationError):
    """No queue entry exists for the requested identifier."""


class PipelineNotFoundError(ApplicationError):
    """No pipeline exists for the requested identifier."""


class PipelineStateConflictError(ApplicationError):
    """The pipeline is in a state that does not allow the requested operation."""


class BackupNotFoundError(ApplicationError):
    """No backup exists for the requested identifier."""


class SnapshotNotFoundError(ApplicationError):
    """No snapshot exists for the requested identifier."""


class RestoreNotFoundError(ApplicationError):
    """No restore operation exists for the requested identifier."""


class AssetNotFoundError(ApplicationError):
    """No asset exists for the requested identifier."""


class ExposureNotFoundError(ApplicationError):
    """No exposure exists for the requested identifier."""


class MonitorEventNotFoundError(ApplicationError):
    """No monitoring event exists for the requested identifier."""


class AlertNotFoundError(ApplicationError):
    """No alert exists for the requested identifier."""


class RuleNotFoundError(ApplicationError):
    """No monitoring rule exists for the requested identifier."""


class CveNotFoundError(ApplicationError):
    """No CVE entry exists for the requested identifier."""


class ThreatFeedNotFoundError(ApplicationError):
    """No threat feed exists for the requested identifier."""


class CopilotConversationNotFoundError(ApplicationError):
    """No copilot conversation exists for the requested identifier."""


class InvestigationNoteNotFoundError(ApplicationError):
    """No investigation note exists for the requested identifier."""


class PlaybookNotFoundError(ApplicationError):
    """No playbook exists for the requested identifier."""


class ExecutionHistoryNotFoundError(ApplicationError):
    """No execution history exists for the requested identifier."""


class WorkerNotFoundError(ApplicationError):
    """No worker exists for the requested identifier."""


class WorkerOfflineError(ApplicationError):
    """The worker is offline and cannot accept jobs."""


class JobQueueEntryNotFoundError(ApplicationError):
    """No job queue entry exists for the requested identifier."""


class JobLeaseExpiredError(ApplicationError):
    """The job lease has expired."""


class JobLeaseNotFoundError(ApplicationError):
    """No job lease exists for the requested identifier."""


class DuplicateJobAssignmentError(ApplicationError):
    """The job is already assigned to another worker."""


class DeadLetterEntryNotFoundError(ApplicationError):
    """No dead letter entry exists for the requested identifier."""


class SchedulingStrategyNotAvailableError(ApplicationError):
    """The requested scheduling strategy is not available."""


class IdentityProviderNotFoundError(ApplicationError):
    """No identity provider exists for the requested identifier."""


class SSOSessionNotFoundError(ApplicationError):
    """No SSO session exists for the requested identifier."""


class ProtocolNotSupportedError(ApplicationError):
    """The requested SSO protocol is not supported."""


class AccountLinkNotFoundError(ApplicationError):
    """No account link exists for the requested identifier."""


class JITProvisioningError(ApplicationError):
    """Just-In-Time user provisioning failed."""


class ScheduleNotFoundError(ApplicationError):
    """No backup schedule exists for the requested identifier."""


class VerificationNotFoundError(ApplicationError):
    """No backup verification exists for the requested identifier."""


class RecoveryPlanNotFoundError(ApplicationError):
    """No disaster recovery plan exists for the requested identifier."""


class RecoveryTestNotFoundError(ApplicationError):
    """No recovery test exists for the requested identifier."""


class BackupCancellationError(ApplicationError):
    """The backup could not be cancelled."""


class RestoreRollbackError(ApplicationError):
    """Restore rollback failed."""


class StorageConnectionError(ApplicationError):
    """Could not connect to backup storage."""


class EncryptionKeyError(ApplicationError):
    """Encryption/decryption key error."""
