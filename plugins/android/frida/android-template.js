function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

function stackTrace() {
    return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
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
 * @param inject 为map，可以设置
 * targetClass 类名
 * targetMethod 方法名
 * retval 返回值
 * showStack 打印出调用栈
 */
function hookFunc(inject) {
    // Logging map object to console
    inject.forEach((value, key) => {
        console.log(key + " = " + value)
    })

    var targetClass = inject.get('targetClass');
    var targetMethod = inject.get('targetMethod');

    var clazz = Java.use(targetClass);
    var overloads = clazz[targetMethod].overloads;
    for (var i in overloads) {
        if (overloads[i].hasOwnProperty('argumentTypes') || overloads[i]['argumentTypes'] != undefined) {
            clazz[targetMethod].implementation = function () {
                var output = "";

                //画个横线
                for (var n = 0; n < 150; n++) {
                    output = output.concat("-");
                }
                output = output.concat("\n")

                //打印方法
                output = output.concat(clazz);
                output = output.concat("\n");
                output = output.concat(overloads[i]);
                output = output.concat("\n");

                //打印入参
                for (var j = 0; j < arguments.length; j++) {
                    output = output.concat("arg[" + j + "]: " + arguments[j]);
                    output = output.concat("\n")
                }

                //调用原方法
                //可以改传入的参数
                var retval = this[targetMethod].apply(this, arguments);

                //返回值
                output = output.concat("retval: " + retval);
                output = output.concat("\n")

                //打印出调用栈
                if (inject.has('retval')) {
                    retval = inject.get('retval');
                    output = output.concat("update retval: " + retval);
                    output = output.concat("\n")
                }

                console.log(output);

                //打印出调用栈
                if (inject.has('showStack')) {
                    if (inject.get('showStack')) {
                        console.log(stackTrace());
                    }
                }

                //改变返回值
                return retval;
            }
        }
    }
}


function main() {
    let inject = new Map();

    // inject.set('targetClass', 'com.android.server.policy.PhoneWindowManager');
    // inject.set('targetMethod', 'interceptKeyBeforeQueueing');
    // inject.set('retval', 0);
    // inject.set('showStack', true);

    // inject.set('targetClass', 'com.android.server.policy.PhoneWindowManager');
    // inject.set('targetMethod', 'getMaxMultiPressPowerCount');

    // inject.set('targetClass', 'com.android.server.policy.PhoneWindowManager');
    // inject.set('targetMethod', 'interceptKeyBeforeQueueing');

    // inject.set('targetClass', 'com.android.server.policy.PhoneWindowManager');
    // inject.set('targetMethod', 'isLongPressToAssistantEnabled');

    // inject.set('targetClass', 'com.android.server.policy.PhoneWindowManager');
    // inject.set('targetMethod', 'hasVeryLongPressOnPowerBehavior');

    // inject.set('targetClass', 'com.android.internal.widget.PointerLocationView');
    // inject.set('targetMethod', 'onPointerEvent');

    // inject.set('targetClass', 'com.android.internal.widget.PointerLocationView');
    // inject.set('targetMethod', 'onTouchEvent');

    // inject.set('targetClass', 'com.android.internal.widget.PointerLocationView');
    // inject.set('targetMethod', 'onGenericMotionEvent');

    // inject.set('targetClass', 'android.view.InputEventReceiver');
    // inject.set('targetMethod', 'dispatchInputEvent');

    // inject.set('targetClass', 'com.android.server.wm.PointerEventDispatcher');
    // inject.set('targetMethod', 'onInputEvent');

    // inject.set('targetClass', 'android.view.View');
    // inject.set('targetMethod', 'onTouchEvent');

    // inject.set('targetClass', 'android.view.View');
    // inject.set('targetMethod', 'onLongClick');

    // inject.set('targetClass', 'android.app.Activity');
    // inject.set('targetMethod', 'onKeyDown');
    // inject.set('showStack', true);

    // inject.set('targetClass', 'android.app.Activity');
    // inject.set('targetMethod', 'onKeyUp');

    // inject.set('targetClass', 'android.app.Activity');
    // inject.set('targetMethod', 'onKeyLongPress');

    // inject.set('targetClass', 'com.android.internal.widget.RecyclerView');
    // inject.set('targetMethod', 'onTouchEvent');

    // inject.set('targetClass', 'android.view.GestureDetector');
    // inject.set('targetMethod', 'onLongPress');

    // inject.set('targetClass', 'android.view.ViewRootImpl$NativePreImeInputStage');
    // inject.set('targetMethod', 'onProcess');
    // inject.set('showStack', true);

    // hookFunc(inject);


    //获取TelephonyManager实例化的对象
    let telephonyManager = chooseClass('android.telephony.TelephonyManager');
    //主动调用getDeviceId()查询imei
    let imei = telephonyManager.getImei();//telephonyManager.getDeviceId();
    console.log(telephonyManager,"getImei =", imei);


    // let phoneWindowManager = chooseClass('com.android.server.policy.PhoneWindowManager');
    // console.log("before hook mLongPressOnPowerBehavior =", phoneWindowManager.mLongPressOnPowerBehavior.value);
    // //非static变量
    // phoneWindowManager.mLongPressOnPowerBehavior.value = 0;
    // console.log("before hook mLongPressOnPowerBehavior =", phoneWindowManager.mLongPressOnPowerBehavior.value);


    // let staticPhoneWindowManager = useClass('com.android.server.policy.PhoneWindowManager');
    // console.log("before hook DEBUG_INPUT =", staticPhoneWindowManager.DEBUG_INPUT.value);
    // //static变量 但不能是final（aosp中PhoneWindowManager.DEBUG_INPUT是static 、final，需要在源码中改成非final才可以这么用）
    // staticPhoneWindowManager.DEBUG_INPUT.value = true;
    // console.log("before hook DEBUG_INPUT =", staticPhoneWindowManager.DEBUG_INPUT.value);
    //
    // //主动调static函数
    // let isLongPressToAssistantEnabled = staticPhoneWindowManager.isLongPressToAssistantEnabled(getContext());
    // console.log("isLongPressToAssistantEnabled =", isLongPressToAssistantEnabled);
}

setImmediate(function () {
    Java.perform(function () {
        main();
    });
});