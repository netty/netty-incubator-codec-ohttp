#!/bin/bash
# ----------------------------------------------------------------------------
# Copyright 2023 The Netty Project
#
# The Netty Project licenses this file to you under the Apache License,
# version 2.0 (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------
set -e

if [ "$#" -ne 1 ]; then
    echo "Expected build log as argument"
    exit 1
fi

if grep -q 'BUILD FAILURE' $1 ; then
    echo "Build failure detected, please inspect build log"
    exit 1
else
    echo "Build successful"
    exit 0
fi
