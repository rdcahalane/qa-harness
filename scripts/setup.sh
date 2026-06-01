#!/bin/bash
# setup script for qa-harness

# Install dependencies
npm install

# Run tests
npm test

# Run typecheck
npm run typecheck