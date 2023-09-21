function trace(pattern) {
    var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

    if (type === "module") {
        // trace Module
        var res = new ApiResolver("module");
        var matches = res.enumerateMatchesSync(pattern);
        var targets = uniqBy(matches, JSON.stringify);
        targets.forEach(function (target) {
            traceModule(target.address, target.name);
        });
    } else if (type === "java") {
        // trace Java Class
        var found = false;
        Java.enumerateLoadedClasses({
            onMatch: function (aClass) {
                if (aClass.match(pattern)) {
                    found = true;
                    var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
                    traceClass(className);
                }
            },
            onComplete: function () {
            }
        });

        // trace Java Method
        if (!found) {
            try {
                traceMethod(pattern);
            } catch (err) { // catch non existing classes/methods
                console.error(err);
            }
        }
    }
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass) {
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose;

    var parsedMethods = [];
    methods.forEach(function (method) {
        parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
    });

    var targets = uniqBy(parsedMethods, JSON.stringify);
    targets.forEach(function (targetMethod) {
        traceMethod(targetClass + "." + targetMethod);
    });
}

function showStacks() {
    var stackTrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    console.log(stackTrace);
}

function getCurrentTime() {
    var date = new Date();
    var month = zeroFill(date.getMonth() + 1);
    var day = zeroFill(date.getDate());
    var hour = zeroFill(date.getHours());
    var minute = zeroFill(date.getMinutes());
    var second = zeroFill((date.getSeconds() * 1000 + date.getMilliseconds()) / 1000.0);
    if (second.length < 6) {
        var count = 6 - second.length;
        second = second + "0".repeat(count);
    }

    var curTime = date.getFullYear() + "-" + month + "-" + day
        + " " + hour + ":" + minute + ":" + second;

    return curTime;
}

function zeroFill(i) {
    if (i >= 0 && i < 10) {
        return "0" + i;
    } else {
        return "" + i;
    }
}

// trace a specific Java Method
function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;

    var targetClass = targetClassMethod.slice(0, delim)
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

    for (var i = 0; i < overloadCount; i++) {

        hook[targetMethod].overloads[i].implementation = function () {
            console.warn("\n*** entered " + targetClassMethod);

            // print args
            if (arguments.length) {
                console.log();
            }

            var args = [];
            for (var j = 0; j < arguments.length; j++) {
                args[j] = arguments[j] + ""
                console.log("arg[" + j + "]: " + arguments[j]);
            }

            var c = randomLightColor();
            var logFunctionName = "[" + getTid() + "]" + targetClassMethod;
            console.log(c + " " + "[" + getCurrentTime() + "]" + " " + logFunctionName + "(" + args + ")");
            showStacks(targetClassMethod);


            // print retval
            var retval = this[targetMethod].apply(this, arguments);
            console.log(c + " " + "[" + getCurrentTime() + "]" + " " + logFunctionName + " ==> " + retval);
            console.warn("\n*** exiting " + targetClassMethod);
            return retval;
        }
    }
}

function getTid() {
    var Thread = Java.use("android.os.Process");
    return Thread.myTid();
}

function randomLightColor() {
    var color = "";
    for (var i = 0; i < 6; i++) {
        color += '5678956789defdef' [Math.floor(Math.random() * 16)]
    }
    return "#" + color;
}

// trace Module functions
function traceModule(impl, name) {
    console.log("Tracing " + name);

    Interceptor.attach(impl, {

        onEnter: function (args) {

            // debug only the intended calls
            this.flag = false;
            // var filename = Memory.readCString(ptr(args[0]));
            // if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
            // if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
            this.flag = true;

            if (this.flag) {
                console.warn("\n*** entered " + name);

                // print backtrace
                console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
            }
        },

        onLeave: function (retval) {

            if (this.flag) {
                // print retval
                console.log("\nretval: " + retval);
                console.warn("\n*** exiting " + name);
            }
        }

    });
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

// usage examples
setImmediate(function () {
    // var name ="com.android.server.accessibility.AccessibilityInputFilter.onMotionEvent";
    var name = "com.android.server.wm.SystemGesturesPointerEventListener.captureDown"

    Java.perform(function () {
        trace(name);
    });
});


