#!/bin/bash

if [ $1 == "format" ]
then
    uv run python -m isort --profile black --multi-line 3 --trailing-comma --line-length 120 mon2pcap
    uv run python -m ruff --line-length=120 mon2pcap
    uv run python -m black --line-length=120 mon2pcap
elif [ $1 == "test" ]
then
    uv run python -m coverage run --source ./mon2pcap -m pytest --disable-warnings
    uv run python -m coverage xml -o .coverage.xml
elif [ $1 == "run" ]
then
    uv run mon2pcap "${@:2}"
else
   echo "unknown command $1"
fi
