#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2022 anqi.huang@outlook.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# ls & grep colored
if $isMac ; then
    alias ls='ls -G'
    alias ll='ls -G -lah'
    alias lh='ls -G -lh'
    alias  l='ls -G'
    alias sl='ls -G'
else
    alias ls='ls --color=auto'
    alias ll='ls --color=auto -lah'
    alias lh='ls --color=auto -lh'
    alias  l='ls --color=auto'
    alias  sl='ls --color=auto'
    alias grep='grep --color=auto'

    alias meminfo='free -m -l -t'

    ## get top process eating memory
    alias psmem='ps auxf | sort -nr -k 4'
    alias psmem10='ps auxf | sort -nr -k 4 | head -10'

    ## get top process eating cpu ##
    alias pscpu='ps auxf | sort -nr -k 3'
    alias pscpu10='ps auxf | sort -nr -k 3 | head -10'

    ## Get server cpu info ##
    alias cpuinfo='lscpu'

    #------------
    # Disk
    #------------
    alias dfree='df -HPT'
fi

#alias python=/usr/bin/python3