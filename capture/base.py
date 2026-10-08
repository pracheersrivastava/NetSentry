"""FlowSource abstraction — script today, live NIC tomorrow. Both yield FlowIn dicts."""
from abc import ABC, abstractmethod
from typing import Iterator


class FlowSource(ABC):
    @abstractmethod
    def iter_flows(self) -> Iterator[dict]:
        raise NotImplementedError
