#!/bin/bash
# docs script for qa-harness

# Generate docs
npm run docs:generate

# Check for drift
npm run docs:check