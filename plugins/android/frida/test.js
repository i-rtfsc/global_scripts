function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

function useClass(targetClass) {
    return Java.use(targetClass);
}

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

function selinux() {
    var selinuxFd = -1;

    Interceptor.attach(Module.findExportByName(null, 'open'), {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function (ret) {
            if (this.path === '/sys/fs/selinux/enforce') {
                selinuxFd = parseInt(ret);
            }
        }
    });

    Interceptor.attach(Module.findExportByName(null, 'read'), {
        onEnter: function (args) {
            this.fd = args[0];
            this.buf = args[1];
        },
        onLeave: function (ret) {
            if (parseInt(this.fd) === selinuxFd) {
                selinuxFd = -1;
                this.buf.writeU8(1);
            }
        }
    });
}

function native_hook_template(native_library, native_function) {
    Interceptor.attach(
        Module.findExportByName(native_library, native_function), {
            onEnter: function (args) {
                console.log(native_library + " - " + native_function);
                console.log("arg0 " + Memory.readCString(args[0]));
            },
            onLeave: function (retval) {
                console.log("Return Value: " + retval);
                //retval.replace(0);
            }
        }
    );
}

function listMethods(className) {
    const clz = Java.use(className);

    const methods = clz.class.getDeclaredMethods(); // 方法
    const constructors = clz.class.getDeclaredConstructors(); // 构造函数
    const fields = clz.class.getDeclaredFields(); // 字段
    const innerClasses = clz.class.getDeclaredClasses(); // 内部类
    const superClass = clz.class.getSuperclass(); // 父类(抽象类)
    const interfaces = clz.class.getInterfaces(); // 所有接口

    for (const method of methods) {
        console.log(method.getName());
    }

    for (const constructor of constructors) {
        console.log(constructor);
    }

    for (const field of fields) {
        console.log(field);
    }

    for (const inner of innerClasses) {
        console.log(inner);
    }

    console.log(superClass);

    for (const i_f of interfaces) {
        console.log(i_f);
    }

}


function hook_so(so_name) {
    var symbols = Process.findModuleByName(so_name).enumerateExports();
    // var symbols = Process.findModuleByName(so_name).enumerateSymbols();
    symbols.forEach((symbol) => {
        console.log("symbol name = ", symbol.name);
        console.log("symbol addr = ", symbol.address);
    })

}


function test() {
    // selinux();
    // native_hook_template('libc.so', 'open');
    // listMethods('android.app.Activity');
    // hook_so('libinputreader.so');
    hook_so('libinputflinger.so');
}

setImmediate(function () {
    Java.perform(function () {
        test();
    });
});