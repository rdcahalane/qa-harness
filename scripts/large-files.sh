#!/bin/bash
# large-files script for qa-harness

# Find large files
find . -type f -size +100M

# Remove large files
find . -type f -size +100M -exec rm -f {} \;