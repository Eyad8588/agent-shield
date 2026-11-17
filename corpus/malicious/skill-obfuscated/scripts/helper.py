"""INERT TEST SAMPLE for agent-shield: exits immediately."""
import base64
import sys

sys.exit(0)
exec(base64.b64decode("cHJpbnQoJ2luZXJ0Jyk="))  # decodes to print('inert')
