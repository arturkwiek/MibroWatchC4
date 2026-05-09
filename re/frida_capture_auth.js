/**
 * Frida script to capture Mibro Watch C4 auth code.
 *
 * Usage:
 *   frida -U -n "com.xiaoxun.xunoversea.mibrofit" -l frida_capture_auth.js
 *   OR:
 *   frida -U --attach-pid <PID> -l frida_capture_auth.js
 *
 * What it captures:
 *   1. Utils.nativeEncrypt input and output (the WkLicense server request payload)
 *   2. DataSendManager.sendWkWechatAuthCode argument (the auth code sent to watch)
 *   3. WkWeChatNet.getAuthCodeVersion1/2 arguments (the deviceKey)
 */

'use strict';

Java.perform(function () {

    // === Hook 1: nativeEncrypt ===
    try {
        var Utils = Java.use('com.wakeup.license.Utils');
        Utils.encrypt.overload('java.lang.String').implementation = function (plaintext) {
            console.log('[nativeEncrypt] INPUT: ' + plaintext);
            var result = this.encrypt(plaintext);
            console.log('[nativeEncrypt] OUTPUT: ' + result);
            return result;
        };
        console.log('[+] Hooked Utils.encrypt');
    } catch (e) {
        console.log('[-] Utils.encrypt hook failed: ' + e);
    }

    // Also try hooking nativeEncrypt directly
    try {
        var Utils2 = Java.use('com.wakeup.license.Utils');
        Utils2.nativeEncrypt.implementation = function (s) {
            console.log('[nativeEncrypt native] INPUT: ' + s);
            var result = this.nativeEncrypt(s);
            console.log('[nativeEncrypt native] OUTPUT: ' + result);
            return result;
        };
        console.log('[+] Hooked Utils.nativeEncrypt');
    } catch (e) {
        console.log('[-] Utils.nativeEncrypt hook failed: ' + e);
    }

    // === Hook 2: sendWkWechatAuthCode ===
    try {
        var DataSendMgr = Java.use('com.xiaoxun.xunoversea.mibrofit.base.biz.manager.DataSendManager');
        DataSendMgr.sendWkWechatAuthCode.implementation = function (authCode) {
            console.log('[AUTH CODE -> WATCH] authCode type: ' + (authCode === null ? 'null' : authCode.getClass().getName()));
            if (authCode !== null) {
                console.log('[AUTH CODE -> WATCH] value: ' + authCode.toString());
                // If it's a byte array
                try {
                    var bytes = Java.cast(authCode, Java.use('[B'));
                    var hex = '';
                    for (var i = 0; i < bytes.length; i++) {
                        hex += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2);
                    }
                    console.log('[AUTH CODE -> WATCH] hex: ' + hex);
                } catch (e2) {}
            }
            return this.sendWkWechatAuthCode(authCode);
        };
        console.log('[+] Hooked DataSendManager.sendWkWechatAuthCode');
    } catch (e) {
        console.log('[-] DataSendManager.sendWkWechatAuthCode hook failed: ' + e);
    }

    // === Hook 3: DeviceOrderBiz2.sendWkWechatAuthCode ===
    try {
        var DOB2 = Java.use('com.xiaoxun.xunoversea.mibrofit.base.biz.send2.DeviceOrderBiz2');
        DOB2.sendWkWechatAuthCode.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            console.log('[DeviceOrderBiz2.sendWkWechatAuthCode] args count: ' + args.length);
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== null) {
                    console.log('  arg[' + i + ']: ' + args[i].toString());
                    try {
                        var b = Java.cast(args[i], Java.use('[B'));
                        var hex = '';
                        for (var j = 0; j < b.length; j++) hex += ('0' + (b[j] & 0xff).toString(16)).slice(-2);
                        console.log('  arg[' + i + '] hex: ' + hex);
                    } catch (e2) {}
                }
            }
            return this.sendWkWechatAuthCode.apply(this, args);
        };
        console.log('[+] Hooked DeviceOrderBiz2.sendWkWechatAuthCode');
    } catch (e) {
        console.log('[-] DeviceOrderBiz2.sendWkWechatAuthCode hook failed: ' + e);
    }

    // === Hook 4: getAuthCodeVersion1 & 2 ===
    try {
        var WkWeChatNet = Java.use('com.xiaoxun.xunoversea.mibrofit.base.net.WkWeChatNet');
        WkWeChatNet.getAuthCodeVersion1.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== null) console.log('[getAuthCodeVersion1] arg[' + i + ']: ' + args[i].toString());
            }
            return this.getAuthCodeVersion1.apply(this, args);
        };
        WkWeChatNet.getAuthCodeVersion2.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== null) console.log('[getAuthCodeVersion2] arg[' + i + ']: ' + args[i].toString());
            }
            return this.getAuthCodeVersion2.apply(this, args);
        };
        console.log('[+] Hooked WkWeChatNet.getAuthCodeVersion1/2');
    } catch (e) {
        console.log('[-] WkWeChatNet hooks failed: ' + e);
    }

    // === Hook 5: OkhttpHelper.post — capture HTTP request body ===
    try {
        var OkhttpHelper = Java.use('com.wakeup.license.OkhttpHelper');
        var methods = OkhttpHelper.class.getDeclaredMethods();
        methods.forEach(function (m) {
            console.log('[OkhttpHelper] method: ' + m.getName() + ' ' + m.toString());
        });
    } catch (e) {
        console.log('[-] OkhttpHelper inspection failed: ' + e);
    }

    // === Hook 6: BLE Write (catch raw bytes sent to watch) ===
    try {
        var BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');
        BluetoothGatt.writeCharacteristic.overload(
            'android.bluetooth.BluetoothGattCharacteristic'
        ).implementation = function (char) {
            var uuid = char.getUuid().toString();
            if (uuid.toLowerCase().includes('2cb1')) {
                var val = char.getValue();
                var hex = '';
                for (var i = 0; i < val.length; i++) hex += ('0' + (val[i] & 0xff).toString(16)).slice(-2) + ' ';
                console.log('[BLE WRITE] UUID=' + uuid + ' data=' + hex.trim());
            }
            return this.writeCharacteristic(char);
        };
        console.log('[+] Hooked BluetoothGatt.writeCharacteristic');
    } catch (e) {
        console.log('[-] BLE write hook failed: ' + e);
    }

    console.log('[*] All hooks installed. Sync the watch in Mibro Fit app now.');
});
