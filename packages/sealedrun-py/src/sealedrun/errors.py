"""Exception types raised by the package."""


class SealedRunError(Exception):
    """Base class for every error this package raises on purpose."""


class VerificationError(SealedRunError):
    """A verification check failed.

    `check` names the failed check; `run_id` and `seq` locate the record when the failure
    belongs to one.
    """

    def __init__(self, check: str, message: str, run_id: str | None = None, seq: int | None = None):
        self.check = check
        self.run_id = run_id
        self.seq = seq
        location = f" run={run_id} seq={seq}" if run_id is not None else ""
        super().__init__(f"{check}:{location} {message}")
