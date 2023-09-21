function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

function getSettingsProvider(table, col) {
    var result = Java.use('android.provider.Settings$' + table).getString(getContext().getContentResolver(), col);
    console.log(col, '=', result);
}

setImmediate(function () {
    Java.perform(function () {
        getSettingsProvider("Secure", "android_id");
    });
});