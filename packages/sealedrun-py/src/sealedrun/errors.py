class SealedRunError(Exception):
    pass


class VerificationError(SealedRunError):
    def __init__(self, check: str, message: str, run_id: str | None = None, seq: int | None = None):
        self.check = check
        self.run_id = run_id
        self.seq = seq
        location = f" run={run_id} seq={seq}" if run_id is not None else ""
        super().__init__(f"{check}:{location} {message}")
