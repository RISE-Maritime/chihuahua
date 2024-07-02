"""
Exceptions
"""


class VerifyException(Exception):
    """Custom Verify Exception"""

    def __init__(self, message: str):
        # super().__init__()
        self.message = message
