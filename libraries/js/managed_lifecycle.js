// medusa-managed-lifecycle:v1
// Explicit resource ownership for scripts loaded by Medusa's interactive CLI.
// Uses messages rather than rpc.exports, which individual modules may replace.
(function () {
    'use strict';
    const channel = 'medusa:lifecycle';
    const resources = new Map();
    let nextId = 0;
    let closing = false;
    let pending = null;

    function assertOpen() {
        if (closing) throw new Error('Medusa cleanup has started; new resources cannot be registered');
    }

    function addCleanup(name, callback) {
        assertOpen();
        if (typeof callback !== 'function') throw new TypeError('cleanup must be a function');
        const id = ++nextId;
        resources.set(id, {name: String(name), callback: callback});
        return id;
    }

    async function clean() {
        closing = true;
        const errors = [];
        const cleaned = [];
        // Reverse registration order mirrors acquisition/dependency order.
        for (const [id, resource] of Array.from(resources.entries()).reverse()) {
            try {
                await resource.callback();
                resources.delete(id);
                cleaned.push(resource.name);
            } catch (error) {
                errors.push({name: resource.name, error: String(error && error.stack || error)});
            }
        }
        return {ok: errors.length === 0, cleaned: cleaned, errors: errors, remaining: resources.size};
    }

    function cleanup() {
        if (pending !== null) return pending;
        pending = clean().finally(function () { pending = null; });
        return pending;
    }

    function receive() {
        recv(channel, function (message) {
            receive();
            cleanup().then(function (result) {
                send(Object.assign({type: channel, request: message.request}, result));
            });
        });
    }

    function registerActivityLifecycleCallbacks(application, observer) {
        assertOpen();
        // Called from Java.perform, like the equivalent Android registration.
        const retainedApp = Java.retain(application);
        let retainedObserver;
        try {
            retainedObserver = Java.retain(observer);
            retainedApp.registerActivityLifecycleCallbacks(retainedObserver);
        } catch (error) {
            retainedApp.$dispose();
            if (retainedObserver) retainedObserver.$dispose();
            throw error;
        }
        addCleanup('ActivityLifecycleCallbacks', function () {
            Java.performNow(function () {
                retainedApp.unregisterActivityLifecycleCallbacks(retainedObserver);
            });
        });
        return observer;
    }

    function managedInterval(callback, delay) {
        assertOpen();
        const timer = setInterval(function () { if (!closing) callback(); }, delay);
        addCleanup('interval', function () { clearInterval(timer); });
        return timer;
    }

    function managedTimeout(callback, delay) {
        assertOpen();
        let resource;
        const timer = setTimeout(function () {
            resources.delete(resource);
            if (!closing) callback();
        }, delay);
        resource = addCleanup('timeout', function () { clearTimeout(timer); });
        return timer;
    }

    globalThis.MedusaLifecycle = Object.freeze({
        addCleanup: addCleanup,
        registerActivityLifecycleCallbacks: registerActivityLifecycleCallbacks,
        setInterval: managedInterval,
        setTimeout: managedTimeout,
        get closing() { return closing; }
    });
    receive();
})();
