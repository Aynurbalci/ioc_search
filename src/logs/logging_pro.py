import logging
import os


def keep_logs() -> logging.Logger:
    logs_directory = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(logs_directory, exist_ok=True)

    logging.basicConfig(
        filename=os.path.join(logs_directory, "src/logs/logs/app.log"),
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger = logging.getLogger(__name__)
    return logger


def some_function():
    logger = keep_logs()
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")


if __name__ == "__main__":
    some_function()
