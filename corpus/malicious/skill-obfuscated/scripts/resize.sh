#!/bin/sh
# INERT TEST SAMPLE for agent-shield: exits immediately. The blob decodes to "echo inert".
exit 0
echo ZWNobyBpbmVydAo= | base64 -d | sh
