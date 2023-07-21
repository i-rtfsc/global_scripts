function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

/**
 * 获取对象，并用来主动调用 静态方法/变量
 * @param targetClass 类名
 * @returns {*} 对象
 */
function useClass(targetClass) {
    return Java.use(targetClass);
}

/**
 * 通过 Java.choose 来寻找堆上实例化的对象
 * 拿到instance后可以主动调用 动态方法/变量，静态方法/变量不适用
 * @param targetClass 类名
 * @returns {*} 实例化的对象
 */
function chooseClass(targetClass) {
    let instanceClass;
    Java.choose(targetClass, {
        onMatch: function (instance) {
            instanceClass = instance;
        },
        onComplete: function () {
            console.warn('get', targetClass, 'completed')
        },
    });
    return instanceClass;
}

/**
 * 可以打印函数入参，返回值。
 * 【也可以改代码，改变返回值，入参等。】
 * @param targetClass 类名
 * @param targetMethod 方法名
 * @param showStack 打印出调用栈，默认打印
 */
function hookFunc(targetClass, targetMethod, showStack = true) {
    var clazz = Java.use(targetClass);
    var overloads = clazz[targetMethod].overloads;
    for (var i in overloads) {
        if (overloads[i].hasOwnProperty('argumentTypes') || overloads[i]['argumentTypes'] != undefined) {
            clazz[targetMethod].implementation = function () {
                //打印方法
                console.warn(overloads[i]);

                //打印出调用栈
                if (showStack) {
                    var throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                    console.log(throwable);
                }

                //打印入参
                for (var a = 0; a < arguments.length; a++) {
                    console.log('args', a, '=', arguments[a]);
                }

                //调用原方法
                //可以改传入的参数
                var retval = this[targetMethod].apply(this, arguments);
                console.warn("old retval =", retval, '\n');

                //改变返回值
                return retval;
            }
        }
    }
}

function main() {
    // hookFunc('com.android.server.policy.PhoneWindowManager', 'interceptKeyBeforeQueueing');
    // hookFunc('com.android.internal.widget.PointerLocationView', 'onPointerEvent');
    // hookFunc('com.android.server.policy.PhoneWindowManager', 'isLongPressToAssistantEnabled', false);


    // //获取TelephonyManager实例化的对象
    // let telephonyManager = chooseClass('android.telephony.TelephonyManager');
    // //主动调用getDeviceId()查询imei
    // let imei = telephonyManager.getImei();//telephonyManager.getDeviceId();
    // console.log(telephonyManager,"getImei =", imei);


    // let phoneWindowManager = chooseClass('com.android.server.policy.PhoneWindowManager');
    // console.log("before hook mLongPressOnPowerBehavior =", phoneWindowManager.mLongPressOnPowerBehavior.value);
    // //非static变量
    // phoneWindowManager.mLongPressOnPowerBehavior.value = 0;
    // console.log("before hook mLongPressOnPowerBehavior =", phoneWindowManager.mLongPressOnPowerBehavior.value);


    let staticPhoneWindowManager = useClass('com.android.server.policy.PhoneWindowManager');
    console.log("before hook DEBUG_INPUT =", staticPhoneWindowManager.DEBUG_INPUT.value);
    //static变量 但不能是final（aosp中PhoneWindowManager.DEBUG_INPUT是static 、final，需要在源码中改成非final才可以这么用）
    staticPhoneWindowManager.DEBUG_INPUT.value = true;
    console.log("before hook DEBUG_INPUT =", staticPhoneWindowManager.DEBUG_INPUT.value);

    //主动调static函数
    let isLongPressToAssistantEnabled = staticPhoneWindowManager.isLongPressToAssistantEnabled(getContext());
    console.log("isLongPressToAssistantEnabled =", isLongPressToAssistantEnabled);

}

setImmediate(function () {
    Java.perform(function () {
        main();
    });
});