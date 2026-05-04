#!/bin/bash
echo "Starting VEXA AgentWall Bridge..."
cd ui
python3 bridge.py --vexa-bin ../bin/agentwall --policy ../config/policy.yaml.example
