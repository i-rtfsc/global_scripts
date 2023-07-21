/**
 * hook __system_property_get 接口，打印系统属性key, value
 */
function hookSystemProperty() {
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

setImmediate(function () {
    Java.perform(function () {
        hookSystemProperty();
    });
});