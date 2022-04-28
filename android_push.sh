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

function android_push_bx-framework {
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.art /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.oat /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.vdex /system/framework/arm/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.art /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.oat /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.vdex /system/framework/arm64/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/bx-framework.jar /system/framework/
}

function android_push_framework {
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.art /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.oat /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.vdex /system/framework/arm/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.art /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.oat /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.vdex /system/framework/arm64/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/framework.jar /system/framework/
}