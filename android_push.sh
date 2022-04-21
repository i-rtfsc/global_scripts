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