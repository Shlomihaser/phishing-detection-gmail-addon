from abc import ABC, abstractmethod
from typing import Optional
from ...models.domain import Email
from ...models.risk import HeuristicDetail

class HeuristicRule(ABC):
    """
    Abstract Base Class for all heuristic checks.
    """
    @abstractmethod
    def evaluate(self, email: Email) -> Optional[HeuristicDetail]:
        """
        Evaluates the email against the rule.
        Returns a HeuristicDetail if the rule triggers, or None if it passes validation.
        """
        pass
