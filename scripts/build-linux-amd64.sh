#!/bin/bash
go build -ldflags "-X secretify-cli/internal/config.Version=$VERSION -X secretify-cli/internal/config.Date=$(date +%Y-%m-%d)" -o secretify