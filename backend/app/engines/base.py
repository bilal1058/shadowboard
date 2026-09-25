from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from app.schemas.policy import PolicyRule
from app.schemas.scan import ObservationRecord


class BaseEngine(ABC):
    def __init__(self, family_name: str):
        self.family_name = family_name

    @abstractmethod
    def get_strategies(self) -> List[str]:
        """Return ordered list of strategy IDs for this attack family."""
        pass

    @abstractmethod
    def build_prompt(
        self,
        rule: PolicyRule,
        strategy: str,
        history: List[Dict[str, Any]],
        observation: Optional[ObservationRecord] = None,
        **kwargs: Any,
    ) -> str:
        """Build an attack prompt for the given strategy.
        
        The observation parameter carries the previous turn's stance and
        the FSM's decision reason, allowing the prompt to be contextually
        adapted (not just cycling through a list).
        """
        pass

    def get_initial_strategy(self) -> str:
        """Return the first strategy to use."""
        strategies = self.get_strategies()
        return strategies[0] if strategies else ""
