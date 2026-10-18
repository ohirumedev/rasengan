#!/usr/bin/env bash

go run . &
GO_PID=$!

(
    cd frontend
    bun next dev
) &
NEXT_PID=$!

trap 'kill $GO_PID $NEXT_PID 2>/dev/null' EXIT

wait
