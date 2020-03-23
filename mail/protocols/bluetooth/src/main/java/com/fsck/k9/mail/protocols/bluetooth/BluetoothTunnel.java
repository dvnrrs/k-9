package com.fsck.k9.mail.protocols.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class BluetoothTunnel {

    public static BluetoothSocket open(String deviceAddress) throws IOException {

        if (deviceAddress == null) {
            throw new IllegalArgumentException("Bluetooth: device address is null");
        } else if (!deviceAddress.matches("^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")) {
            throw new IllegalArgumentException("Bluetooth: badly formatted device address");
        }

        BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
        BluetoothDevice device = adapter.getRemoteDevice(deviceAddress);
        BluetoothSocket socket;

        try {
            Method createRfcommSocket = device.getClass().getMethod("createRfcommSocket", new Class[] { int.class });
            socket = (BluetoothSocket) createRfcommSocket.invoke(device,1);
        } catch (NoSuchMethodException e) {
            throw new IOException("Bluetooth: can't find createRfcommSocket()");
        } catch (InvocationTargetException e) {
            throw new IOException("Bluetooth: can't invoke createRfcommSocket()");
        } catch (IllegalAccessException e) {
            throw new IOException("Bluetooth: can't access createRfcommSocket()");
        }

        socket.connect();
        return socket;

    }

}
