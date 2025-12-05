#!/usr/bin/env bash
cd /workspaces/tty-clipboard
meson test -C .build -v bridge-mock
