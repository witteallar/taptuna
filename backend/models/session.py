from dataclasses import dataclass, asdict


@dataclass
class Session:
    session_id: str
    stream_index: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int
    start_ts: float
    end_ts: float

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = self.duration
        return d