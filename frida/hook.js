/**
 * 获取Context
 */
function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

/**
 * 获取SettingsProvider数据
 */
function getSettingsProvider(table, col) {
    var result = Java.use('android.provider.Settings$' + table).getString(getContext().getContentResolver(), col);
    console.log(col, '=', result);
}

/**
 * 弹一个Toast
 */
function makeToast(toast_text) {
    Java.scheduleOnMainThread(() => {
        Java.use("android.widget.Toast").makeText(getContext(), Java.use("java.lang.StringBuilder").$new(toast_text), 0).show();
    });
}

/**
 * hook __system_property_get 接口，打印系统属性key, value
 */
function hook_system_property() {
    Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
        onEnter: function (args) {
            this._name = args[0].readCString();
            this._value = args[1];
        },
        onLeave: function (retval) {
            console.log(JSON.stringify({
                result_length: retval,
                name: this._name,
                val: this._value.readCString()
            }));
        }
    });
}

/**
 * 接收广播
 */
function registerBroadcastReceiver(action) {
    const MyBroadcastReceiver = Java.registerClass({
        name: 'MyBroadcastReceiver',
        superClass: Java.use('android.content.BroadcastReceiver'),
        methods: {
            onReceive: [{
                returnType: 'void',
                argumentTypes: ['android.content.Context', 'android.content.Intent'],
                implementation: function (context, intent) {
                    console.log(intent)
                }
            }]
        },
    });
    getContext().registerReceiver(MyBroadcastReceiver.$new(), Java.use('android.content.IntentFilter').$new(action));
}

/**
 * 改变java类的变量
 */
function hook_java_class_val() {
    //class name
    var className = 'com.android.server.policy.PhoneWindowManager';

    var aClass = Java.use(className);
    console.log(aClass.DEBUG_INPUT.value);
    //static变量 但不能是final
    aClass.DEBUG_INPUT.value = true;
    console.log(aClass.DEBUG_INPUT.value);

    //非static变量
    Java.choose(className, {
        onMatch: function (instance) {
            instance.mLongPressOnPowerBehavior.value = 0;
            console.log(instance.mLongPressOnPowerBehavior.value);
        },
        onComplete: function () {

        }
    });
}

/**
 * 打印函数入参
 * 需要自己改掉：
 * 1. className
 * 2. func name
 * 3. 入参类型
 * 4. 入参个数
 */
function hook_func_args() {
    // var className = 'com.android.server.policy.PhoneWindowManager';
    // var aClass = Java.use(className);
    // aClass.interceptKeyBeforeQueueing.overload("android.view.KeyEvent", "int").implementation = function (args1, args2) {
    //     console.log(args1)
    //     console.log("policyFlags=", args2)
    //     var retval = this.interceptKeyBeforeQueueing(args1, args2)
    //     console.log("result=", retval)
    //     return retval
    // }

    var className = 'com.android.internal.widget.PointerLocationView';
    var aClass = Java.use(className);
    aClass.onPointerEvent.overload("android.view.MotionEvent").implementation = function (args) {
        console.log(args)
        var retval = this.onPointerEvent(args)
        console.log("retval", retval)
        return retval
    }
}

/**
 * hook 改变函数返回值
 */
function hook_func_retval(className, funcName, hookval) {
    //class
    var aClass = Java.use(className);
    //func name
    aClass[funcName].overload().implementation = function () {
        console.log("info: entered target method");

        //打印原本的返回值
        var retval = aClass[funcName].apply(this);
        //var retval = this.FUNCNAME.apply(this);
        console.log("old ret value = " + retval);

        //改变返回值
        console.log("hook ret value = " + hookval);
        return hookval;
    }
}

setTimeout(function () {
    Java.perform(function () {
        // hook_system_property();
        // getSettingsProvider("Secure", "android_id");
        // makeToast("弹出内容");
        registerBroadcastReceiver('android.intent.action.SCREEN_ON');

        // hook_java_class_val();
        // hook_func_args();
        // hook_func_retval('com.android.server.policy.PhoneWindowManager', 'isUserSetupComplete', false);
    });
}, 0);