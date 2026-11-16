/* Exercise the actual agent helper without a phone or Frida session. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../libraries/js/managed_lifecycle.js'), 'utf8');

function fixture() {
    let receiver;
    const replies = new Map();
    const timers = new Map();
    let nextTimer = 0;
    const context = {
        recv(type, callback) { assert.equal(type, 'medusa:lifecycle'); receiver = callback; },
        send(message) { replies.get(message.request)(message); },
        setInterval(fn) { const id = ++nextTimer; timers.set(id, fn); return id; },
        setTimeout(fn) { const id = ++nextTimer; timers.set(id, fn); return id; },
        clearInterval(id) { timers.delete(id); },
        clearTimeout(id) { timers.delete(id); },
        Java: {retain: value => value, performNow: fn => fn()},
        rpc: {exports: {userFunction: () => 42}}
    };
    vm.runInNewContext(source, context);
    return {
        api: context.MedusaLifecycle, context, timers,
        cleanup(id) {
            return new Promise(resolve => {
                replies.set(id, resolve);
                receiver({type: 'medusa:lifecycle', request: id});
            });
        }
    };
}

(async () => {
    // Actual lifecycle observer registration/unregistration, including retry.
    const f = fixture();
    const registered = new Set();
    let fail = true;
    const observer = {};
    const application = {
        registerActivityLifecycleCallbacks(value) { registered.add(value); },
        unregisterActivityLifecycleCallbacks(value) {
            if (fail) throw new Error('fixture unregister failure');
            registered.delete(value);
        }
    };
    f.api.registerActivityLifecycleCallbacks(application, observer);
    assert.equal(registered.size, 1);
    const first = await f.cleanup('first');
    assert.equal(first.ok, false);
    assert.equal(first.remaining, 1);
    assert.match(first.errors[0].error, /fixture unregister failure/);
    assert.equal(registered.size, 1);
    fail = false;
    assert.equal((await f.cleanup('retry')).ok, true);
    assert.equal(registered.size, 0);
    assert.equal((await f.cleanup('again')).cleaned.length, 0);
    assert.throws(() => f.api.addCleanup('late', () => {}), /cleanup has started/);
    assert.equal(f.context.rpc.exports.userFunction(), 42);

    // Cleanup reverses acquisition order and retains only failed actions.
    const g = fixture();
    const order = [];
    g.api.addCleanup('one', () => order.push(1));
    g.api.addCleanup('two', () => order.push(2));
    let timersFired = 0;
    g.api.setTimeout(() => { timersFired++; }, 10);
    g.api.setInterval(() => { timersFired++; }, 10);
    const callbacks = Array.from(g.timers.values());
    assert.equal((await g.cleanup('timers')).ok, true);
    assert.deepEqual(order, [2, 1]);
    assert.equal(g.timers.size, 0);
    callbacks.forEach(fn => fn());
    assert.equal(timersFired, 0);

    // A pending async cleanup is shared by concurrent requests, not repeated.
    const h = fixture();
    let resolveCleanup;
    let calls = 0;
    h.api.addCleanup('async', () => {
        calls++;
        return new Promise(resolve => { resolveCleanup = resolve; });
    });
    const a = h.cleanup('a');
    const b = h.cleanup('b');
    resolveCleanup();
    assert.equal((await a).ok, true);
    assert.equal((await b).ok, true);
    assert.equal(calls, 1);
    console.log('Managed lifecycle JavaScript checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
