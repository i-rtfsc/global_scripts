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

function test() {
    // selinux();
    native_hook_template('libc.so', 'open');
}

setImmediate(function () {
    Java.perform(function () {
        test();
    });
});