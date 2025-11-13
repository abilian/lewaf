# LeWAF API Reference

**Version**: 1.0.0
**Last Updated**: 2025-11-13

This document provides comprehensive API reference for LeWAF, a Python Web Application Firewall implementation with ModSecurity SecLang compatibility.

---

## Table of Contents

1. [Core API](#core-api)
   - [WAF Class](#waf-class)
   - [Transaction Class](#transaction-class)
   - [Rule Class](#rule-class)
2. [Configuration](#configuration)
   - [WAFConfig](#wafconfig)
   - [Configuration Loading](#configuration-loading)
   - [Configuration Management](#configuration-management)
3. [Operators](#operators)
4. [Actions](#actions)
5. [Transformations](#transformations)
6. [Collections & Variables](#collections--variables)
7. [Middleware & Integration](#middleware--integration)
8. [Body Processors](#body-processors)
9. [Storage Backends](#storage-backends)
10. [Logging & Audit](#logging--audit)
11. [Exceptions](#exceptions)
12. [CLI Tools](#cli-tools)

---

## Core API

### WAF Class

**Module**: `lewaf.integration`

The main entry point for creating and managing a WAF instance.

#### Constructor

```python
from lewaf.integration import WAF

waf = WAF(config: dict[str, list[Any] | list[str]])
```

**Parameters**:
- `config` (dict): Configuration dictionary with keys:
  - `"rules"` (list[str]): Inline SecLang rules
  - `"rule_files"` (list[str]): Paths to rule files

**Attributes**:
- `rule_group` (RuleGroup): Container for rules organized by phase (1-5)
- `parser` (SecLangParser): Parser for SecLang rule syntax
- `component_signature` (str): WAF version identifier

#### Methods

##### `new_transaction() -> Transaction`

Create a new transaction for processing an HTTP request/response.

```python
waf = WAF(config={"rules": [], "rule_files": []})
transaction = waf.new_transaction()
```

**Returns**: Transaction instance

**Usage**: Call this for each HTTP request to create an isolated transaction context.

---

### Transaction Class

**Module**: `lewaf.transaction`

Represents a single HTTP request/response transaction through the WAF.

#### Constructor

```python
from lewaf.transaction import Transaction

tx = Transaction(waf: WAF, id: str)
```

**Parameters**:
- `waf` (WAF): Parent WAF instance
- `id` (str): Unique transaction identifier

**Note**: Typically created via `waf.new_transaction()` rather than directly.

#### Request Processing Methods

##### `process_uri(uri: str, method: str) -> None`

Set the request URI and HTTP method.

```python
tx.process_uri("/api/users", "GET")
```

**Parameters**:
- `uri` (str): Request URI (e.g., "/path?query=value")
- `method` (str): HTTP method (GET, POST, PUT, DELETE, etc.)

**Side Effects**: Populates `REQUEST_URI`, `REQUEST_METHOD`, `QUERY_STRING` collections.

##### `add_request_header(name: str, value: str) -> None`

Add a request header.

```python
tx.add_request_header("Content-Type", "application/json")
tx.add_request_header("Authorization", "Bearer token")
```

**Parameters**:
- `name` (str): Header name
- `value` (str): Header value

##### `add_request_body(body: bytes, content_type: str = "") -> None`

Add request body content.

```python
body = b'{"username": "admin"}'
tx.add_request_body(body, "application/json")
```

**Parameters**:
- `body` (bytes): Raw request body
- `content_type` (str, optional): Content-Type header value

**Side Effects**: Triggers body processor based on content type, populates `REQUEST_BODY`, `ARGS_POST`, `JSON`, `XML` collections.

##### `process_request_headers() -> dict[str, str | int] | None`

Evaluate Phase 1 rules (request headers phase).

```python
result = tx.process_request_headers()
if result:
    # Request was blocked
    status = result["status"]  # HTTP status code
    message = result["message"]  # Block message
```

**Returns**:
- `dict` if request should be blocked (contains "status", "message", "rule_id")
- `None` if request should continue

**Phase**: Executes rules with `phase:1`

##### `process_request_body() -> dict[str, str | int] | None`

Evaluate Phase 2 rules (request body phase).

```python
result = tx.process_request_body()
if result:
    # Request was blocked
    return blocking_response(result["status"], result["message"])
```

**Returns**: Block dict or None
**Phase**: Executes rules with `phase:2`

#### Response Processing Methods

##### `add_response_header(name: str, value: str) -> None`

Add a response header.

```python
tx.add_response_header("Content-Type", "text/html")
```

##### `add_response_status(status: int, protocol: str = "HTTP/1.1") -> None`

Set the response status code.

```python
tx.add_response_status(200, "HTTP/1.1")
```

##### `process_response_headers() -> dict[str, str | int] | None`

Evaluate Phase 3 rules (response headers phase).

```python
result = tx.process_response_headers()
```

**Phase**: Executes rules with `phase:3`

##### `add_response_body(body: bytes, content_type: str = "") -> None`

Add response body content.

```python
tx.add_response_body(b"<html>...</html>", "text/html")
```

##### `process_response_body() -> dict[str, str | int] | None`

Evaluate Phase 4 rules (response body phase).

```python
result = tx.process_response_body()
```

**Phase**: Executes rules with `phase:4`

#### Control Flow Methods

##### `interrupt(rule: Rule) -> None`

Interrupt the transaction with a blocking rule.

```python
tx.interrupt(rule)
```

**Parameters**:
- `rule` (Rule): The rule that triggered the block

**Side Effects**: Sets `tx.interruption` dict with block details.

##### `capturing() -> bool`

Check if transaction is in capture mode.

```python
if tx.capturing():
    tx.capture_field(0, "captured_value")
```

**Returns**: True if capture action is active

##### `capture_field(index: int, value: str) -> None`

Capture a field value (e.g., from regex groups).

```python
# After regex match with groups
tx.capture_field(0, matched_group)
```

**Parameters**:
- `index` (int): Capture group index (0-9)
- `value` (str): Value to capture

**Side Effects**: Sets `TX:0` through `TX:9` variables.

#### Attributes

- `variables` (TransactionVariables): All transaction variables (see [Collections](#collections--variables))
- `interruption` (dict | None): Interruption details if blocked
- `current_phase` (int): Current processing phase (1-5)
- `id` (str): Unique transaction ID
- `matched_var` (str): Name of last matched variable
- `matched_var_value` (str): Value of last matched variable
- `chain_state` (bool): Chain rule state
- `skip_state` (int): Number of rules to skip
- `multimatch_state` (bool): Multi-match mode active

---

### Rule Class

**Module**: `lewaf.rules`

Represents a single WAF rule for evaluation.

#### Constructor

```python
from lewaf.rules import Rule

rule = Rule(
    variables: list[tuple[str, str | None]],
    operator: ParsedOperator,
    transformations: list[Any | str],
    actions: dict[str, Action],
    metadata: dict[str, int | str],
    tags: list[str]
)
```

**Parameters**:
- `variables`: List of (variable_name, key_pattern) tuples
- `operator`: Parsed operator instance
- `transformations`: Transformation pipeline
- `actions`: Dictionary of action instances
- `metadata`: Rule metadata (id, phase, severity, etc.)
- `tags`: List of rule tags

**Note**: Rules are typically created by SecLangParser, not constructed manually.

#### Properties

##### `id -> int | str`

Get the rule ID.

```python
rule_id = rule.id  # From metadata["id"]
```

##### `phase -> int`

Get the rule phase (1-5).

```python
phase = rule.phase  # From metadata["phase"]
```

#### Methods

##### `evaluate(transaction: Transaction) -> bool`

Evaluate the rule against a transaction.

```python
matched = rule.evaluate(tx)
if matched:
    # Rule matched, actions executed
```

**Parameters**:
- `transaction` (Transaction): Transaction to evaluate

**Returns**: True if rule matched, False otherwise

**Side Effects**: Executes rule actions if matched (block, log, setvar, etc.)

---

## Configuration

### WAFConfig

**Module**: `lewaf.config.models`

Complete WAF configuration model.

#### Constructor

```python
from lewaf.config.models import WAFConfig, StorageConfig, RequestLimits

config = WAFConfig(
    engine="On",
    rules=[],
    rule_files=["rules/crs-setup.conf", "rules/*.conf"],
    request_limits=RequestLimits(
        body_limit=13107200,  # 12.5 MB
        header_limit=8192,
        request_line_limit=8192
    ),
    storage=StorageConfig(
        backend="memory"  # or "file", "redis"
    )
)
```

#### Attributes

- `engine` (str): WAF mode - "On", "DetectionOnly", "Off"
- `rules` (list[str]): Inline SecLang rules
- `rule_files` (list[str]): Rule file paths (supports wildcards)
- `request_limits` (RequestLimits): Request size limits
- `storage` (StorageConfig): Persistent storage configuration
- `audit_logging` (AuditLoggingConfig): Audit logging configuration
- `performance` (PerformanceConfig): Performance tuning
- `component_signature` (str): Server signature

#### Methods

##### `to_dict() -> dict`

Convert configuration to dictionary.

```python
config_dict = config.to_dict()
```

##### `from_dict(data: dict) -> WAFConfig` (classmethod)

Create configuration from dictionary.

```python
config = WAFConfig.from_dict({
    "engine": "On",
    "rules": [],
    "rule_files": ["rules/*.conf"]
})
```

---

### RequestLimits

**Module**: `lewaf.config.models`

Request size limits configuration.

```python
from lewaf.config.models import RequestLimits

limits = RequestLimits(
    body_limit=13107200,      # 12.5 MB (bytes)
    header_limit=8192,        # 8 KB (bytes)
    request_line_limit=8192   # 8 KB (bytes)
)
```

**Attributes**:
- `body_limit` (int): Maximum request body size in bytes (default: 13107200)
- `header_limit` (int): Maximum header size in bytes (default: 8192)
- `request_line_limit` (int): Maximum request line size (default: 8192)

---

### StorageConfig

**Module**: `lewaf.config.models`

Persistent storage backend configuration.

```python
from lewaf.config.models import StorageConfig

# Memory storage (default)
storage = StorageConfig(backend="memory")

# File storage
storage = StorageConfig(
    backend="file",
    file_path="/var/lib/lewaf/storage.db"
)

# Redis storage
storage = StorageConfig(
    backend="redis",
    redis_host="localhost",
    redis_port=6379,
    redis_db=0,
    ttl=3600  # 1 hour
)
```

**Attributes**:
- `backend` (str): Storage backend - "memory", "file", or "redis"
- `file_path` (str | None): Path for file backend
- `redis_host` (str): Redis host (default: "localhost")
- `redis_port` (int): Redis port (default: 6379)
- `redis_db` (int): Redis database number (default: 0)
- `ttl` (int): Time-to-live for entries in seconds (default: 3600)

---

### AuditLoggingConfig

**Module**: `lewaf.config.models`

Audit logging configuration.

```python
from lewaf.config.models import AuditLoggingConfig

audit = AuditLoggingConfig(
    enabled=True,
    format="json",  # or "text"
    mask_sensitive=True,
    output="/var/log/lewaf/audit.log",
    level="INFO",
    additional_fields={
        "environment": "production",
        "service": "api-gateway"
    }
)
```

**Attributes**:
- `enabled` (bool): Enable audit logging
- `format` (str): Log format - "json" or "text"
- `mask_sensitive` (bool): Mask sensitive data (passwords, tokens)
- `output` (str): Log output path or "stdout"
- `level` (str): Log level - "DEBUG", "INFO", "WARNING", "ERROR"
- `additional_fields` (dict): Extra fields to include in logs

---

### Configuration Loading

**Module**: `lewaf.config.loader`

#### ConfigLoader

Load configuration from YAML/JSON files with environment variable substitution.

```python
from lewaf.config.loader import ConfigLoader

loader = ConfigLoader()
config = loader.load_from_file("config/lewaf.yaml")
```

##### `load_from_file(file_path: str | Path) -> WAFConfig`

Load configuration from a YAML or JSON file.

```python
config = loader.load_from_file("/etc/lewaf/config.yaml")
```

**Supports Environment Variables**:
```yaml
# config.yaml
storage:
  backend: redis
  redis_host: ${REDIS_HOST:-localhost}
  redis_port: ${REDIS_PORT:-6379}
```

##### `load_from_dict(data: dict) -> WAFConfig`

Load configuration from a dictionary.

```python
config = loader.load_from_dict({
    "engine": "On",
    "rules": ["SecRuleEngine On"]
})
```

#### Helper Function

##### `load_config(file_path: str | Path) -> WAFConfig`

Convenience function to load configuration.

```python
from lewaf.config import load_config

config = load_config("config/lewaf.yaml")
```

---

### Configuration Management

**Module**: `lewaf.config.manager`

#### ConfigManager

Configuration manager with hot-reload support.

```python
from lewaf.config.manager import ConfigManager

manager = ConfigManager(
    config_file="config/lewaf.yaml",
    environment="production",
    auto_reload_on_signal=True  # Reload on SIGHUP
)

# Get current config
config = manager.get_config()

# Manually reload
new_config = manager.reload()

# Register callback for config changes
def on_config_reload(new_config, old_config):
    print(f"Config updated to version {manager.get_version()}")

manager.register_reload_callback(on_config_reload)
```

**Features**:
- Thread-safe configuration access
- Hot-reload on SIGHUP signal
- Configuration versioning
- Reload callbacks
- Configuration history

##### `get_config() -> WAFConfig`

Get the current configuration.

##### `reload(overrides: dict | None = None) -> WAFConfig`

Reload configuration from file with optional overrides.

##### `register_reload_callback(callback: Callable) -> None`

Register a callback to be called when configuration is reloaded.

##### `get_version() -> int`

Get the current configuration version number.

##### `get_history() -> list[ConfigVersion]`

Get configuration change history.

---

## Operators

**Module**: `lewaf.primitives.operators`

Operators perform pattern matching and validation in WAF rules.

### Using Operators

Operators are typically used in SecLang rules:

```
SecRule ARGS "@rx (?i)union.*select" "id:1,phase:2,deny"
```

### Custom Operator Registration

```python
from lewaf.primitives.operators import register_operator, Operator, OperatorFactory

@register_operator("custom")
class CustomOperatorFactory(OperatorFactory):
    @staticmethod
    def create(options):
        return CustomOperator(options.arguments)

class CustomOperator(Operator):
    def __init__(self, pattern):
        self.pattern = pattern

    def evaluate(self, tx, value):
        return self.pattern in value
```

### Operator Registry

#### String Matching Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `rx` | Regular expression matching | `@rx "(?i)admin"` |
| `eq` | Exact equality | `@eq "admin"` |
| `contains` | Substring matching | `@contains "script"` |
| `beginswith` | Prefix matching | `@beginsWith "/admin"` |
| `endswith` | Suffix matching | `@endsWith ".php"` |
| `pm` | Phrase match (multiple patterns) | `@pm "admin user root"` |
| `pmfromfile` | Phrase match from file | `@pmFromFile "badwords.txt"` |
| `strmatch` | Wildcard pattern matching | `@strMatch "*.php"` |
| `streq` | Case-sensitive string equality | `@streq "Admin"` |

#### Numeric Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `gt` | Greater than | `@gt 100` |
| `ge` | Greater than or equal | `@ge 100` |
| `lt` | Less than | `@lt 10` |
| `le` | Less than or equal | `@le 10` |
| `within` | Value within set | `@within "1 2 3 4 5"` |

#### Security Detection Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `detectsqli` | SQL injection detection | `@detectSQLi` |
| `detectxss` | XSS detection | `@detectXSS` |

#### Validation Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `validatebyterange` | Byte range validation | `@validateByteRange "32-126"` |
| `validateutf8encoding` | UTF-8 validation | `@validateUtf8Encoding` |
| `validateurlencoding` | URL encoding validation | `@validateUrlEncoding` |
| `validateschema` | JSON/XML schema validation | `@validateSchema "schema.json"` |
| `validatenid` | National ID validation | `@validateNid "rut"` |

#### Network Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `ipmatch` | IP/CIDR matching | `@ipMatch "192.168.1.0/24"` |
| `ipmatchfromfile` | IP match from file | `@ipMatchFromFile "blocked_ips.txt"` |
| `geolookup` | Geographic IP lookup | `@geoLookup` |
| `rbl` | Real-time blacklist check | `@rbl "dnsbl.example.com"` |

#### Control Flow Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `unconditional` | Always matches | `@unconditionalMatch` |
| `nomatch` | Never matches | `@noMatch` |

---

## Actions

**Module**: `lewaf.primitives.actions`

Actions define what happens when a rule matches.

### Action Types

Actions are classified into 5 types:

1. **METADATA** - Rule metadata (id, phase, msg, severity)
2. **DISRUPTIVE** - Block/allow/redirect requests
3. **DATA** - Data manipulation
4. **NONDISRUPTIVE** - Logging, variable setting
5. **FLOW** - Control rule execution flow

### Using Actions

Actions are specified in SecLang rules:

```
SecRule ARGS "@rx attack" \
    "id:1,phase:2,deny,status:403,msg:'Attack detected',log,severity:CRITICAL"
```

### Custom Action Registration

```python
from lewaf.primitives.actions import register_action, Action, ActionType

@register_action("custom")
class CustomAction(Action):
    def action_type(self):
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule, transaction):
        # Custom action logic
        print(f"Rule {rule.id} matched!")
```

### Action Registry

#### Disruptive Actions

| Action | Type | Description | Example |
|--------|------|-------------|---------|
| `deny` | DISRUPTIVE | Block request | `deny` |
| `allow` | DISRUPTIVE | Allow request | `allow` |
| `block` | DISRUPTIVE | Block request | `block` |
| `drop` | DISRUPTIVE | Drop connection | `drop` |
| `redirect` | DISRUPTIVE | Redirect to URL | `redirect:http://example.com` |

#### Metadata Actions

| Action | Type | Description | Example |
|--------|------|-------------|---------|
| `id` | METADATA | Rule ID | `id:100001` |
| `phase` | METADATA | Rule phase (1-5) | `phase:2` |
| `msg` | METADATA | Rule message | `msg:'SQL injection detected'` |
| `severity` | METADATA | Severity level | `severity:CRITICAL` |
| `tag` | METADATA | Rule tags | `tag:'OWASP_CRS'` |
| `status` | METADATA | HTTP status code | `status:403` |
| `logdata` | METADATA | Data to log | `logdata:'User: %{ARGS.user}'` |
| `rev` | METADATA | Rule revision | `rev:2` |
| `ver` | METADATA | Version requirement | `ver:'OWASP_CRS/3.3.0'` |

#### Non-Disruptive Actions

| Action | Type | Description | Example |
|--------|------|-------------|---------|
| `log` | NONDISRUPTIVE | Log rule match | `log` |
| `nolog` | NONDISRUPTIVE | Don't log | `nolog` |
| `pass` | NONDISRUPTIVE | Continue processing | `pass` |
| `capture` | NONDISRUPTIVE | Capture regex groups | `capture` |
| `auditlog` | NONDISRUPTIVE | Enable audit logging | `auditlog` |
| `noauditlog` | NONDISRUPTIVE | Disable audit logging | `noauditlog` |
| `setvar` | NONDISRUPTIVE | Set variable | `setvar:tx.score=+5` |
| `setenv` | NONDISRUPTIVE | Set environment var | `setenv:BLOCKED=1` |
| `multimatch` | NONDISRUPTIVE | Multi-match mode | `multiMatch` |

#### Flow Control Actions

| Action | Type | Description | Example |
|--------|------|-------------|---------|
| `chain` | FLOW | Chain rules (AND) | `chain` |
| `skip` | FLOW | Skip rules | `skip:2` |
| `skipafter` | FLOW | Skip to marker | `skipAfter:END_CHECKS` |
| `ctl` | FLOW | Runtime control | `ctl:ruleEngine=Off` |

#### Persistent Storage Actions

| Action | Type | Description | Example |
|--------|------|-------------|---------|
| `initcol` | NONDISRUPTIVE | Init persistent collection | `initcol:IP=%{REMOTE_ADDR}` |
| `setsid` | NONDISRUPTIVE | Set session ID | `setsid:%{ARGS.sessionid}` |

### Macro Expansion

The `msg` and `logdata` actions support macro expansion:

```
SecRule ARGS "@rx attack" \
    "id:1,msg:'Attack from %{REMOTE_ADDR} on %{REQUEST_URI}'"
```

**Supported Macros**:
- `%{VARIABLE_NAME}` - Simple variable
- `%{COLLECTION.key}` - Collection member
- `%{TX.score}` - Transaction variable
- `%{MATCHED_VAR}` - Last matched variable value
- `%{MATCHED_VAR_NAME}` - Last matched variable name

---

## Transformations

**Module**: `lewaf.primitives.transformations`

Transformations modify values before operator matching.

### Using Transformations

Transformations are applied via the `t:` action:

```
SecRule ARGS "@rx attack" "id:1,t:lowercase,t:removeWhitespace"
```

Multiple transformations are applied in order (pipeline).

### Transformation Registry

#### Basic Text Transformations

| Transformation | Description | Example Input | Example Output |
|----------------|-------------|---------------|----------------|
| `none` | No transformation | `"Test"` | `"Test"` |
| `lowercase` | Convert to lowercase | `"TeSt"` | `"test"` |
| `uppercase` | Convert to uppercase | `"test"` | `"TEST"` |
| `length` | Return string length | `"hello"` | `"5"` |
| `trim` | Remove leading/trailing whitespace | `" test "` | `"test"` |
| `trimleft` | Remove left whitespace | `" test"` | `"test"` |
| `trimright` | Remove right whitespace | `"test "` | `"test"` |

#### Whitespace Transformations

| Transformation | Description |
|----------------|-------------|
| `compresswhitespace` | Replace multiple spaces with single space |
| `removewhitespace` | Remove all whitespace |
| `replacewhitespace` | Replace all whitespace with spaces |

#### Encoding/Decoding Transformations

| Transformation | Description |
|----------------|-------------|
| `urldecode` | URL decode (`%20` → space) |
| `urldecodeuni` | URL decode with Unicode |
| `urlencode` | URL encode (space → `%20`) |
| `htmlentitydecode` | Decode HTML entities (`&lt;` → `<`) |
| `jsdecode` | Decode JavaScript escapes |
| `cssdecode` | Decode CSS escapes |
| `base64decode` | Base64 decode |
| `base64decodeext` | Extended Base64 decode (forgiving) |
| `base64encode` | Base64 encode |
| `hexdecode` | Hexadecimal decode |
| `hexencode` | Hexadecimal encode |
| `utf8tounicode` | UTF-8 to Unicode |
| `sqlhexdecode` | SQL hex decode (`0x41` → `A`) |

#### Hashing Transformations

| Transformation | Description | Output |
|----------------|-------------|--------|
| `md5` | MD5 hash | 32-character hex |
| `sha1` | SHA-1 hash | 40-character hex |
| `sha256` | SHA-256 hash | 64-character hex |

#### Cleanup Transformations

| Transformation | Description |
|----------------|-------------|
| `removenulls` | Remove null bytes |
| `removenullbytes` | Remove null and control characters |
| `removecomments` | Remove comment patterns |
| `replacecomments` | Replace comments with spaces |
| `replacenulls` | Replace nulls with spaces |

#### Path Normalization

| Transformation | Description |
|----------------|-------------|
| `normalizepath` | Normalize file paths (`/./` → `/`, `/../` handling) |
| `normalizepathwin` | Normalize Windows paths |

#### Advanced Transformations

| Transformation | Description |
|----------------|-------------|
| `cmdline` | Command line normalization |
| `parityeven7bit` | Set even parity on 7-bit chars |
| `parityodd7bit` | Set odd parity on 7-bit chars |

### Transformation Pipelines

Example of stacked transformations:

```python
# In SecLang:
SecRule ARGS "@rx <script" "id:1,t:lowercase,t:htmlEntityDecode,t:removeWhitespace"

# Processing:
# Input: " &lt;SCRIPT&gt; "
# After lowercase: " &lt;script&gt; "
# After htmlEntityDecode: " <script> "
# After removeWhitespace: "<script>"
# Matches: @rx <script
```

---

## Collections & Variables

**Module**: `lewaf.primitives.collections`

Collections provide structured access to request/response data.

### Collection Types

#### MapCollection

Key-value pair collections (headers, arguments).

```python
from lewaf.primitives.collections import MapCollection

headers = MapCollection("REQUEST_HEADERS", case_insensitive=True)
headers.add("Content-Type", "application/json")
headers.add("Authorization", "Bearer token")

# Get all values for a key
values = headers.get("content-type")  # Case-insensitive

# Find by regex
matches = headers.find_regex(re.compile("^auth", re.I))

# Find all
all_headers = headers.find_all()  # List of MatchData
```

#### SingleValueCollection

Single value collections (REQUEST_URI, REQUEST_METHOD).

```python
from lewaf.primitives.collections import SingleValueCollection

uri = SingleValueCollection("REQUEST_URI")
uri.set("/api/users")

value = uri.get()  # "/api/users"
```

#### BodyCollection

Request/response body content.

```python
from lewaf.primitives.collections import BodyCollection

body = BodyCollection("REQUEST_BODY")
body.set_content(b'{"user": "admin"}', "application/json")

raw_bytes = body.get_raw()
content_type = body.get_content_type()
is_json = body.is_json()  # True
```

#### FilesCollection

Uploaded file collections.

```python
from lewaf.primitives.collections import FilesCollection

files = FilesCollection("FILES")
files.add_file(
    name="avatar",
    filename="photo.jpg",
    content=b"\xff\xd8\xff...",
    content_type="image/jpeg"
)

# Get files for a field
avatar_files = files.get_files("avatar")
```

### Transaction Variables

All available variables in `TransactionVariables`:

#### Request Variables

| Variable | Type | Description |
|----------|------|-------------|
| `ARGS` | MapCollection | All arguments (GET + POST) |
| `ARGS_GET` | MapCollection | Query string arguments |
| `ARGS_POST` | MapCollection | POST body arguments |
| `REQUEST_HEADERS` | MapCollection | Request headers |
| `REQUEST_COOKIES` | MapCollection | Request cookies |
| `REQUEST_URI` | SingleValueCollection | Request URI with query string |
| `REQUEST_METHOD` | SingleValueCollection | HTTP method (GET, POST, etc.) |
| `REQUEST_PROTOCOL` | SingleValueCollection | HTTP protocol (HTTP/1.1, etc.) |
| `REQUEST_BODY` | BodyCollection | Raw request body |
| `QUERY_STRING` | SingleValueCollection | Raw query string |
| `REQUEST_BASENAME` | SingleValueCollection | URI without query |
| `REQUEST_LINE` | SingleValueCollection | Full HTTP request line |

#### Response Variables

| Variable | Type | Description |
|----------|------|-------------|
| `RESPONSE_HEADERS` | MapCollection | Response headers |
| `RESPONSE_BODY` | BodyCollection | Response body |
| `RESPONSE_STATUS` | SingleValueCollection | HTTP status code |
| `RESPONSE_PROTOCOL` | SingleValueCollection | Response protocol |
| `RESPONSE_CONTENT_TYPE` | SingleValueCollection | Response Content-Type |

#### File Variables

| Variable | Type | Description |
|----------|------|-------------|
| `FILES` | FilesCollection | Uploaded files |
| `FILES_NAMES` | MapCollection | File field names |
| `FILES_SIZES` | MapCollection | Individual file sizes |
| `FILES_COMBINED_SIZE` | SingleValueCollection | Total upload size |

#### Server Variables

| Variable | Type | Description |
|----------|------|-------------|
| `REMOTE_ADDR` | SingleValueCollection | Client IP address |
| `REMOTE_HOST` | SingleValueCollection | Client hostname |
| `REMOTE_PORT` | SingleValueCollection | Client port |
| `SERVER_ADDR` | SingleValueCollection | Server IP |
| `SERVER_NAME` | SingleValueCollection | Server hostname |
| `SERVER_PORT` | SingleValueCollection | Server port |

#### Content Variables

| Variable | Type | Description |
|----------|------|-------------|
| `JSON` | MapCollection | Parsed JSON data |
| `XML` | MapCollection | Parsed XML data |

#### Metadata Variables

| Variable | Type | Description |
|----------|------|-------------|
| `TX` | MapCollection | Transaction variables |
| `ENV` | MapCollection | Environment variables |
| `MATCHED_VAR` | SingleValueCollection | Last matched value |
| `MATCHED_VAR_NAME` | SingleValueCollection | Last matched variable name |
| `UNIQUE_ID` | SingleValueCollection | Unique transaction ID |
| `DURATION` | SingleValueCollection | Transaction duration (ms) |
| `HIGHEST_SEVERITY` | SingleValueCollection | Highest rule severity |

### Using Variables in Rules

```
# Match on specific argument
SecRule ARGS:username "@rx admin" "id:1"

# Match on all arguments
SecRule ARGS "@rx <script" "id:2"

# Match on request header
SecRule REQUEST_HEADERS:User-Agent "@rx bot" "id:3"

# Match on transaction variable
SecRule TX:score "@gt 10" "id:4"
```

---

## Middleware & Integration

### ASGI Middleware

**Module**: `lewaf.integration.asgi`

ASGI middleware for integrating LeWAF with modern Python web frameworks.

#### ASGIMiddleware

```python
from lewaf.integration.asgi import ASGIMiddleware
from starlette.applications import Starlette

app = Starlette()

# Wrap with LeWAF middleware
app = ASGIMiddleware(
    app,
    config_file="config/lewaf.yaml",
    enable_hot_reload=True
)
```

**Constructor Parameters**:
- `app` (ASGIApp): The ASGI application to wrap
- `config_file` (str | None): Path to configuration file
- `config_dict` (dict | None): Configuration dictionary
- `waf_instance` (WAF | None): Existing WAF instance
- `enable_hot_reload` (bool): Enable config hot-reload (default: False)

**Features**:
- Automatic request/response filtering
- Phase-based rule evaluation
- Blocking responses with custom status/message
- Configuration hot-reload support

#### ASGIMiddlewareFactory

Factory for creating middleware with shared WAF instance.

```python
from lewaf.integration.asgi import ASGIMiddlewareFactory

# Create factory
factory = ASGIMiddlewareFactory(config_file="config/lewaf.yaml")

# Wrap multiple apps with same WAF instance
app1 = factory.wrap(starlette_app)
app2 = factory.wrap(fastapi_app)
```

### Starlette Integration

**Module**: `lewaf.integrations.starlette`

```python
from starlette.applications import Starlette
from lewaf.integrations.starlette import CorazaMiddleware

app = Starlette()
app.add_middleware(
    CorazaMiddleware,
    rules=["rules/crs-setup.conf"],
    block_response_status=403,
    block_response_body=b"Forbidden"
)
```

---

## Body Processors

**Module**: `lewaf.bodyprocessors`

Body processors parse request/response bodies and populate collections.

### Built-in Processors

| Content-Type | Processor | Populates |
|--------------|-----------|-----------|
| `application/x-www-form-urlencoded` | URLEncodedProcessor | `ARGS_POST` |
| `application/json` | JSONProcessor | `JSON` |
| `application/xml`, `text/xml` | XMLProcessor | `XML` |
| `multipart/form-data` | MultipartProcessor | `ARGS_POST`, `FILES` |

### Custom Body Processor

```python
from lewaf.bodyprocessors import register_body_processor, BodyProcessorProtocol

@register_body_processor("application/custom")
class CustomProcessor:
    def read(self, body: bytes, content_type: str):
        # Parse body
        parsed_data = custom_parse(body)
        return parsed_data

    def get_collections(self) -> dict:
        # Return populated collections
        return {
            "ARGS_POST": parsed_args,
            "CUSTOM_DATA": custom_collection
        }
```

---

## Storage Backends

**Module**: `lewaf.storage`

Storage backends provide persistence for collections (IP reputation, rate limiting, etc.).

### Storage Protocol

```python
from lewaf.storage import StorageBackend

class StorageBackend(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int | None = None) -> None: ...
    def delete(self, key: str) -> None: ...
    def exists(self, key: str) -> bool: ...
    def expire(self, key: str, ttl: int) -> None: ...
```

### Built-in Backends

#### MemoryStorage

In-memory storage (default).

```python
from lewaf.storage import MemoryStorage, set_storage_backend

storage = MemoryStorage()
set_storage_backend(storage)
```

**Pros**: Fast, no dependencies
**Cons**: Not persistent, not shared across processes

#### FileStorage

File-based storage.

```python
from lewaf.storage import FileStorage, set_storage_backend

storage = FileStorage(file_path="/var/lib/lewaf/storage.db")
set_storage_backend(storage)
```

**Pros**: Persistent
**Cons**: Slower than memory, not suitable for high concurrency

#### RedisStorage

Redis backend (production recommended).

```python
from lewaf.storage import RedisStorage, set_storage_backend

storage = RedisStorage(
    host="localhost",
    port=6379,
    db=0
)
set_storage_backend(storage)
```

**Pros**: Fast, persistent, distributed
**Cons**: Requires Redis server

### Using Storage in Rules

```
# Initialize persistent collection based on IP
SecAction "id:1,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"

# Track failed login attempts
SecRule ARGS:login_failed "@eq 1" \
    "id:2,phase:2,setvar:IP.failed_logins=+1"

# Block after 5 failures
SecRule IP:failed_logins "@gt 5" \
    "id:3,phase:2,deny,status:429,msg:'Rate limit exceeded'"
```

---

## Logging & Audit

**Module**: `lewaf.logging`

### Audit Logger

```python
from lewaf.logging import configure_audit_logging, get_audit_logger

# Configure audit logging
configure_audit_logging(
    format="json",
    mask_sensitive=True,
    output="/var/log/lewaf/audit.log",
    level="INFO"
)

# Get logger instance
logger = get_audit_logger()

# Log transaction
logger.info("rule_matched", extra={
    "rule_id": 100001,
    "matched_var": "ARGS:username",
    "matched_value": "admin",
    "severity": "WARNING"
})
```

### Error Logging

```python
from lewaf.logging import log_error, log_operator_error

# Log general error
log_error("WAF-0001", "Configuration file not found", {
    "file_path": "/etc/lewaf/config.yaml"
})

# Log operator error
log_operator_error("rx", "Invalid regex pattern", {
    "pattern": "(?P<invalid",
    "rule_id": 100001
})
```

### Data Masking

```python
from lewaf.logging import mask_sensitive_data, set_masking_config

# Configure masking
set_masking_config({
    "patterns": [
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Credit cards
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Emails
    ],
    "fields": ["password", "token", "api_key", "secret"]
})

# Mask data
data = {"password": "secret123", "user": "admin"}
masked = mask_sensitive_data(data)
# {"password": "***MASKED***", "user": "admin"}
```

---

## Exceptions

**Module**: `lewaf.exceptions`

All LeWAF exceptions follow a structured error code format: `CATEGORY-NNNN`

### Exception Hierarchy

```python
WAFError (base)
├── ConfigurationError (WAF-0001)
├── ConfigFileNotFoundError (WAF-0002)
├── ParseError (PARSE-1000)
│   ├── SecRuleParseError (PARSE-1001)
│   ├── IncludeRecursionError (PARSE-1002)
│   └── UnknownOperatorError (PARSE-1003)
├── RuleEvaluationError (RULE-2000)
│   ├── OperatorEvaluationError (RULE-2001)
│   └── TransformationError (RULE-2003)
├── BodyProcessorError (BODY-3000)
│   ├── InvalidJSONError (BODY-3001)
│   └── BodySizeLimitError (BODY-3003)
├── StorageError (STORE-6000)
└── ProxyError (PROXY-7000)
```

### Using Exceptions

```python
from lewaf.exceptions import (
    WAFError,
    ConfigurationError,
    SecRuleParseError
)

try:
    config = load_config("config.yaml")
except ConfigFileNotFoundError as e:
    print(f"Error code: {e.code}")  # WAF-0002
    print(f"Message: {e.message}")
    print(f"Context: {e.context}")

    # Convert to dict for logging
    error_dict = e.to_dict()
```

### Error Codes Reference

See [Error Codes Documentation](../troubleshooting/error-codes.md) for complete error code reference.

---

## CLI Tools

### Configuration Validator

**Command**: `lewaf-validate`

Validate LeWAF configuration before deployment.

```bash
# Basic validation
lewaf-validate config/lewaf.yaml

# Strict validation with rule checking
lewaf-validate config/lewaf.yaml --strict --check-rules

# Quiet mode (exit code only)
lewaf-validate config/lewaf.yaml --quiet
```

**Options**:
- `--check-rules`: Validate all rule files
- `--check-variables`: Check for undefined variables
- `--strict`: Fail on warnings
- `--quiet`: Suppress output (exit code only)

**Exit Codes**:
- `0`: Valid configuration
- `1`: Validation errors
- `2`: Warnings (in strict mode)

### Reverse Proxy Server

**Command**: `coraza-proxy`

Run LeWAF as a standalone reverse proxy.

```bash
# Start proxy
coraza-proxy \
    --upstream http://backend:8080 \
    --host 0.0.0.0 \
    --port 8000 \
    --rules-file config/rules.conf

# With custom configuration
coraza-proxy \
    --upstream http://backend:8080 \
    --config config/lewaf.yaml
```

**Options**:
- `--upstream`: Backend server URL (required)
- `--host`: Listen host (default: 0.0.0.0)
- `--port`: Listen port (default: 8000)
- `--rules-file`: SecLang rules file
- `--config`: Configuration file path
- `--timeout`: Upstream request timeout

---

## Examples

### Complete Usage Example

```python
from lewaf.integration import WAF
from lewaf.config import load_config

# Load configuration
config = load_config("config/lewaf.yaml")

# Create WAF instance
waf = WAF(config={
    "rules": [],
    "rule_files": ["rules/crs-setup.conf", "rules/REQUEST-*.conf"]
})

# Process a request
tx = waf.new_transaction()

# Set request data
tx.process_uri("/api/login", "POST")
tx.add_request_header("Content-Type", "application/json")
tx.add_request_header("User-Agent", "curl/7.68.0")

# Add request body
body = b'{"username": "admin", "password": "secret"}'
tx.add_request_body(body, "application/json")

# Evaluate request headers (Phase 1)
result = tx.process_request_headers()
if result:
    # Request blocked
    print(f"Blocked: {result['message']}")
    print(f"Rule ID: {result['rule_id']}")
    print(f"Status: {result['status']}")
else:
    # Continue processing
    result = tx.process_request_body()  # Phase 2

    if result:
        print(f"Blocked at Phase 2: {result['message']}")
    else:
        # Request allowed, process response
        tx.add_response_status(200)
        tx.add_response_header("Content-Type", "application/json")

        response_body = b'{"status": "success"}'
        tx.add_response_body(response_body, "application/json")

        # Evaluate response
        tx.process_response_headers()  # Phase 3
        tx.process_response_body()     # Phase 4
```

---

## Related Documentation

- [Quickstart Guide](../guides/quickstart.md) - Get started quickly
- [FastAPI Integration](../guides/integration-fastapi.md) - FastAPI examples
- [Flask Integration](../guides/integration-flask.md) - Flask examples
- [Starlette Integration](../guides/integration-starlette.md) - Starlette examples
- [Custom Rules Guide](../guides/custom-rules.md) - Writing custom rules
- [Error Codes Reference](../troubleshooting/error-codes.md) - Complete error codes
- [Troubleshooting Runbook](../troubleshooting/runbook.md) - Common issues
- [Performance Tuning](../performance/tuning.md) - Optimization guide

---

**Last Updated**: 2025-11-13
**Version**: 1.0.0
**Phase**: 16 - Production Documentation
