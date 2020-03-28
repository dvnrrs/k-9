package com.fsck.k9.activity;

import android.app.Activity;
import android.app.ListActivity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

import androidx.annotation.Nullable;

import com.fsck.k9.ui.R;

import java.util.ArrayList;

public class ChooseBluetoothDeviceActivity extends ListActivity implements View.OnClickListener {

    private static class Device {
        public String name;
        public String address;
        @Override public String toString() {
            return name + " : " + address;
        }
    }

    private ArrayList<Device> deviceListItems = new ArrayList<Device>();
    private ArrayAdapter<Device> deviceListAdapter;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.choose_bluetooth_device);

        Button cancelButton = findViewById(R.id.cancel_button);
        TextView statusText = findViewById(R.id.status_text);

        cancelButton.setOnClickListener(this);

        deviceListAdapter = new ArrayAdapter<Device>(this, android.R.layout.simple_list_item_1, deviceListItems);
        setListAdapter(deviceListAdapter);

        try {
            BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
            if (adapter != null) {
                for (BluetoothDevice device : adapter.getBondedDevices()) {
                    Device d = new Device();
                    d.address = device.getAddress();
                    d.name = device.getName();
                    deviceListItems.add(d);
                }
                deviceListAdapter.notifyDataSetChanged();
            }
            ((ViewManager) statusText.getParent()).removeView(statusText);
        } catch (Exception ex) {
            statusText.setText("Error: " + ex.getMessage());
        }

    }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        Object o = l.getItemAtPosition(position);
        if (o != null) {
            Intent data = new Intent();
            Device device = (Device) o;
            data.putExtra("address", device.address);
            setResult(RESULT_OK, data);
            finish();
        }
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.cancel_button) {
            setResult(RESULT_CANCELED);
            finish();
        }
    }
}