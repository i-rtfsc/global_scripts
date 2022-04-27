#!/bin/bash

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# ls & grep colored
if $isMac ; then
    alias ls='ls -G'
    alias ll='ls -G -la'
    alias lh='ls -G -lh'
    alias  l='ls -G'
else
    alias ls='ls --color=auto'
    alias ll='ls --color=auto -la'
    alias lh='ls --color=auto -lh'
    alias  l='ls --color=auto'
    alias grep='grep --color=auto'
fi
