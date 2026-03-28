#!/bin/bash

find -name "*.so" -not -path "./lib/x86/*" -not -path "./lib/armeabi/*" -not -path "./lib/x86_64/*" -not -path "./lib/arm64-v8a/*" -not -path "./lib/mips/*" | wc -l