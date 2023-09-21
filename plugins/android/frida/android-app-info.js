function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

function getInfo() {
    let context = getContext();

    let env = {
        mainDirectory: context.getFilesDir().getParent(),
        filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
        cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
        externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
        codeCacheDirectory:
            'getCodeCacheDir' in context ?
                context.getCodeCacheDir().getAbsolutePath().toString() : 'N/A',
        obbDir: context.getObbDir().getAbsolutePath().toString(),
        packageCodePath: context.getPackageCodePath().toString(),
    };

    console.log("******************* App Environment Info *******************")
    console.log("mainDirectory: " + env.mainDirectory);
    console.log("filesDirectory: " + env.filesDirectory);
    console.log("cacheDirectory: " + env.cacheDirectory);
    console.log("externalCacheDirectory: " + env.externalCacheDirectory);
    console.log("codeCacheDirectory: " + env.codeCacheDirectory);
    console.log("obbDir: " + env.obbDir);
    console.log("packageCodePath: " + env.packageCodePath);
    console.log("************************************************************")
}

setImmediate(function () {
    Java.perform(function () {
        getInfo();
    });
});