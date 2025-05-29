/**
 * hook __system_property_xxx 接口，打印系统属性key, value等
 */
function hookSystemProperty(func_name) {
    // bionic/libc/bionic/system_property_api.cpp
    Interceptor.attach(Module.findExportByName(null, func_name), {
        onEnter: function (args) {
            this._name = args[0].readCString();
            this._value = args[1];
        },
        onLeave: function (retval) {
            console.log(JSON.stringify({
                func_name: func_name,
                name: this._name,
                val: this._value.readCString(),
                result_length: retval
            }));
        }
    });
}

setImmediate(function () {
    Java.perform(function () {
        // hookSystemProperty('__system_property_get');
        hookSystemProperty('__system_property_find');
    });
});