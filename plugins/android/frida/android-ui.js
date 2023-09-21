/**
 * 获取Context
 */
function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}


/**
 * 弹一个Toast
 */
function makeToast(toast_text) {
    Java.scheduleOnMainThread(() => {
        Java.use("android.widget.Toast").makeText(getContext(), Java.use("java.lang.StringBuilder").$new(toast_text), 0).show();
    });
}

setImmediate(function () {
    Java.perform(function () {
        makeToast("弹出内容");
    });
});