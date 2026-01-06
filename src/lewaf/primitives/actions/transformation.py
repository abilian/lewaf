"""Transformation action (t:)."""

from __future__ import annotations

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("t")
class TransformationAction(Action):
    """Transformation action specifies the transformation pipeline for rule variables.

    The 't' action is used to specify the transformation pipeline to use to transform
    the value of each variable used in the rule before matching. Any transformation
    functions specified in a SecRule will be added to previous ones specified in
    SecDefaultAction.

    Special case: t:none removes all previous transformations, preventing rules from
    depending on the default configuration.

    Example:
        SecRule ARGS "attack" "id:1,t:none,t:lowercase,t:removeNulls"
    """

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Add or clear transformations in the rule."""
        from lewaf.primitives.transformations import (  # noqa: PLC0415
            TRANSFORMATIONS,
        )

        if not data:
            msg = "Transformation action requires a transformation name"
            raise ValueError(msg)

        transformation_name = data.strip().lower()

        # Initialize transformations list if not present
        if "transformations" not in rule_metadata:
            rule_metadata["transformations"] = []

        # Special case: "none" clears all previous transformations
        if transformation_name == "none":
            rule_metadata["transformations"] = []
            return

        # Validate transformation exists
        if transformation_name not in TRANSFORMATIONS:
            msg = (
                f"Unknown transformation '{transformation_name}'. "
                f"Available: {', '.join(sorted(TRANSFORMATIONS.keys()))}"
            )
            raise ValueError(msg)

        # Add transformation to the list
        rule_metadata["transformations"].append(transformation_name)

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Transformation is applied during rule evaluation, not as an action."""
