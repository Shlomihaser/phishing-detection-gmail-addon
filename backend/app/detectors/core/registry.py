from typing import List, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from app.detectors.core.base import BaseDetector


class DetectorRegistry:
    _detector_classes: List[Type["BaseDetector"]] = []

    @classmethod
    def register(cls, detector_class: Type["BaseDetector"]) -> Type["BaseDetector"]:
        if detector_class not in cls._detector_classes:
            cls._detector_classes.append(detector_class)
        return detector_class

    @classmethod
    def get_all_detectors(cls) -> List["BaseDetector"]:
        return [detector_class() for detector_class in cls._detector_classes]

    @classmethod
    def clear(cls) -> None:
        cls._detector_classes = []

    @classmethod
    def get_registered_count(cls) -> int:
        return len(cls._detector_classes)
