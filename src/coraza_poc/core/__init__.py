from __future__ import annotations

import logging
import re
from functools import lru_cache

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


@lru_cache(maxsize=128)
def compile_regex(pattern):
    logging.debug(f"Compiling regex: {pattern}")
    return re.compile(pattern)
