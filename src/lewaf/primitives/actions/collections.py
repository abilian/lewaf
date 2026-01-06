"""Collection actions (initcol, setsid)."""

from __future__ import annotations

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("initcol")
class InitColAction(Action):
    """
    Initialize a persistent collection.

    Loads a persistent collection from storage and associates it with a
    transaction variable. Used for cross-request tracking like:
    - Rate limiting per IP
    - Session-based anomaly scores
    - User behavior tracking

    Syntax:
        initcol:collection=key
        initcol:ip=%{REMOTE_ADDR}
        initcol:session=%{TX.session_id}
        initcol:user=%{ARGS.username},ttl=3600

    Examples:
        # Track per-IP data
        SecAction "id:1,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"

        # Track per-session with custom TTL
        SecAction "id:2,phase:1,nolog,pass,initcol:session=%{TX.sessionid},ttl=1800"

        # After initcol, you can use the collection:
        SecAction "id:3,phase:1,pass,setvar:ip.request_count=+1"
        SecRule IP:request_count "@gt 100" "id:4,deny,msg:'Rate limit exceeded'"
    """

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse initcol specification."""
        if not data or "=" not in data:
            msg = "InitCol action requires format: collection=key or collection=key,ttl=seconds"
            raise ValueError(msg)

        # Parse collection=key,ttl=seconds
        parts = data.split(",")
        collection_spec = parts[0]

        # Extract collection name and key expression
        if "=" not in collection_spec:
            msg = "InitCol requires collection=key format"
            raise ValueError(msg)

        collection_name, key_expression = collection_spec.split("=", 1)
        self.collection_name = collection_name.strip()
        self.key_expression = key_expression.strip()

        # Parse optional TTL
        self.ttl = 0  # 0 = use default
        for part in parts[1:]:
            if "=" in part:
                param_name, param_value = part.split("=", 1)
                if param_name.strip().lower() == "ttl":
                    try:
                        self.ttl = int(param_value.strip())
                    except ValueError:
                        msg = f"Invalid TTL value: {param_value}"
                        raise ValueError(msg)

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Load persistent collection for this transaction."""
        # Import here to avoid circular dependencies
        from lewaf.primitives.collections import (  # noqa: PLC0415
            MapCollection,
        )
        from lewaf.primitives.variable_expansion import (  # noqa: PLC0415
            VariableExpander,
        )
        from lewaf.storage import (  # noqa: PLC0415
            get_storage_backend,
        )
        from lewaf.storage.collections import (  # noqa: PLC0415
            PersistentCollectionManager,
        )

        # Expand key expression to get actual key
        key = VariableExpander.expand(self.key_expression, transaction.variables)

        if not key:
            # Empty key, cannot initialize collection
            return

        # Ensure transaction has collection manager
        if not hasattr(transaction, "collection_manager") or not isinstance(
            getattr(transaction, "collection_manager", None),
            PersistentCollectionManager,
        ):
            storage_backend = get_storage_backend()
            transaction.collection_manager = PersistentCollectionManager(
                storage_backend
            )

        # Create or get collection for this type
        # Collections are added as attributes to transaction.variables
        # e.g., initcol:ip=... creates transaction.variables.ip
        collection_attr = self.collection_name.lower()

        # Create collection if it doesn't exist
        if not hasattr(transaction.variables, collection_attr):
            collection = MapCollection(self.collection_name.upper())
            setattr(transaction.variables, collection_attr, collection)
        else:
            collection = getattr(transaction.variables, collection_attr)

        # Load persistent data into collection
        transaction.collection_manager.init_collection(
            self.collection_name,
            key,
            collection,
            self.ttl,
        )


@register_action("setsid")
class SetSidAction(Action):
    """
    Set session ID for session-based collections.

    Sets the session identifier that will be used for session-based
    persistent collections. Typically used before initcol:session.

    Syntax:
        setsid:expression

    Examples:
        # Set session ID from cookie
        SecAction "id:10,phase:1,nolog,pass,setsid:%{REQUEST_COOKIES.PHPSESSID}"

        # Set session ID from custom header
        SecAction "id:11,phase:1,nolog,pass,setsid:%{REQUEST_HEADERS.X-Session-ID}"

        # Then use session collection
        SecAction "id:12,phase:1,nolog,pass,initcol:session=%{TX.sessionid}"
    """

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse setsid expression."""
        if not data:
            msg = "SetSid action requires an expression"
            raise ValueError(msg)

        self.session_id_expression = data.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Set session ID in transaction."""
        # Import here to avoid circular dependencies
        from lewaf.primitives.variable_expansion import (  # noqa: PLC0415
            VariableExpander,
        )

        # Expand expression to get session ID
        session_id = VariableExpander.expand(
            self.session_id_expression, transaction.variables
        )

        # Store in TX.sessionid for use with initcol
        transaction.variables.tx.remove("sessionid")
        if session_id:
            transaction.variables.tx.add("sessionid", session_id)
