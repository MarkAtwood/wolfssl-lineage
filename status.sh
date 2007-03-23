#!/bin/sh

# Filter cvs status to find modified files
cvs status | grep "File:" | grep -v "Up-to-date"

