#!/bin/sh
export LC_ALL=C
head -c 200 /dev/random | tr -cd '[:graph:]' | head -c 16