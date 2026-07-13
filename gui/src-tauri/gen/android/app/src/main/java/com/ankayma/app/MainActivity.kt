package com.ankayma.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        // Store JVM + Application context for Rust→Java calls in vpn_android.rs.
        initAndroidVpn(applicationContext)

        // Request VPN permission once — shows the system consent dialog if needed.
        // After the user grants it, VpnService.Builder.establish() succeeds on
        // every subsequent vpn_connect without another prompt.
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
        }
    }

    // Called with the result of the VPN consent dialog. No action needed here —
    // the next vpn_connect attempt will call establish() and succeed if granted.
    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        // VPN permission granted/denied — AnkaymaVpnService.establish() will reflect it.
    }

    // Implemented in Rust (vpn_android.rs). Stores JavaVM + Application context
    // so start_service / stop_service can call Java from Rust async threads.
    private external fun initAndroidVpn(appContext: android.content.Context)

    companion object {
        private const val VPN_PERMISSION_REQUEST = 1001
    }
}
