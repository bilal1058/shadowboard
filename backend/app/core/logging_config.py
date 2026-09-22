import logging
import sys
from loguru import logger
import structlog
from structlog import configure, processors
from structlog.stdlib import add_log_level, add_logger_name, filter_by_level
from structlog.processors import TimeStamper, JSONRenderer
from typing import Optional

_log_level = "INFO"
_log_format = "json"
_log_destination = "stdout"


def setup_logging(level: str = "INFO", format: str = "json", destination: str = "stdout"):
    global _log_level, _log_format, _log_destination
    _log_level = level.upper()
    _log_format = format
    _log_destination = destination

    logging.getLogger().setLevel(getattr(logging, _log_level, logging.INFO))

    if _log_format == "json":
        configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                add_log_level,
                add_logger_name,
                structlog.stdlib.filter_by_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
                processors.JSONRenderer()
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(structlog.stdlib.ProcessorFormatter(
            processor=processors.JSONRenderer()
        ))
        logging.getLogger().handlers = [handler]
    else:
        logging.basicConfig(
            level=getattr(logging, _log_level, logging.INFO),
            format=f"%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            stream=sys.stdout,
        )

    logger.remove()
    for lvl in ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
        try:
            logger.level(lvl, icon="")
        except Exception:
            pass
    logger.add(
        sys.stdout if _log_destination == "stdout" else _log_destination,
        level=_log_level,
        format=_log_format,
        colorize=False,
        serialize=_log_format == "json",
        backtrace=True,
        diagnose=True,
        enqueue=True,
    )

    logger.info("Logging initialized", level=_log_level, format=_log_format, destination=_log_destination)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
