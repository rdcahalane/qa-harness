#!/bin/bash
# integrate script for qa-harness

# Run setup script
./setup.sh

# Run update script
./update.sh

# Run docs script
./docs.sh

# Run large files script
./large-files.sh

# Run missing tests script
./missing-tests.sh