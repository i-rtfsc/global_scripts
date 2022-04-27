#!/bin/bash

function gs_system_cpu_men() {
    cpu_mem=$(ps -A -o %cpu,%mem | awk '{ cpu += $1; mem += $2} END {print "cpu="cpu"%\nmem="mem"%"}')
    echo "${cpu_mem}"
}
