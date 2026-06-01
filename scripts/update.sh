#!/bin/bash
# update script for qa-harness

# Update dependencies
npm update

# Run tests
npm test

# Run typecheck
npm run typecheck