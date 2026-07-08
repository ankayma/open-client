package com.ankayma.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.net.InetAddress

class AnkaymaVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private var nativeHandle: Long = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }

        val configJson = intent?.getStringExtra(EXTRA_CONFIG) ?: run {
            stopSelf()
            return START_NOT_STICKY
        }

        // Required on Android 8+: call startForeground within 5 seconds.
        startForeground(NOTIFICATION_ID, buildNotification())

        try {
            val obj = JSONObject(configJson)
            val overlayIp = obj.getString("overlay_ip")
            val isV6 = overlayIp.contains(":")

            // Magic DNS IP: fd00:a11a::53 — reserved Ankayma ULA address for the
            // in-process DNS interceptor (F-3 private domain). Routes through TUN so
            // DNS queries to this IP are caught by spawn_tx_with_dns in the pump.
            val magicDnsIp = "fd00:a11a::53"

            val builder = Builder()
                .setSession("Ankayma")
                .setMtu(1420)
                .setBlocking(false)

            if (isV6) {
                // IPv6 overlay: /128 host address for this device.
                builder.addAddress(overlayIp, 128)
                // Add /128 routes for each peer's overlay IP so their traffic goes
                // through the TUN to the WireGuard pump. [T:A.1.9]
                val peers = obj.optJSONArray("peers")
                if (peers != null) {
                    for (i in 0 until peers.length()) {
                        val peerIp = peers.getJSONObject(i).optString("overlay_ip", "")
                        if (peerIp.isNotEmpty()) builder.addRoute(peerIp, 128)
                    }
                }
                // Route the magic DNS IP so DNS queries to it enter the TUN.
                builder.addRoute(magicDnsIp, 128)
            } else {
                // IPv4 overlay (legacy; current control plane issues IPv6).
                builder.addAddress(overlayIp, 32)
                builder.addRoute("10.0.0.0", 8)
            }

            // F-3 DNS: primary = in-process interceptor (answers *.int.ankayma.com),
            // secondary = 8.8.8.8 (fallback for non-Ankayma domains via SERVFAIL).
            builder.addDnsServer(InetAddress.getByName(magicDnsIp))
            builder.addDnsServer(InetAddress.getByName("8.8.8.8"))

            val pfd = builder.establish() ?: run {
                    // VPN permission not yet granted — establish() returns null.
                    stopSelf()
                    return START_NOT_STICKY
                }

            tunInterface = pfd
            // Pass fd to Rust (borrowed, not detached — Kotlin keeps ownership for close).
            nativeHandle = nativeStart(pfd.fd, configJson)

            if (nativeHandle == 0L) {
                pfd.close()
                tunInterface = null
                stopSelf()
                return START_NOT_STICKY
            }
        } catch (e: Exception) {
            android.util.Log.e("AnkaymaVPN", "start failed", e)
            stopSelf()
            return START_NOT_STICKY
        }

        return START_STICKY
    }

    private fun stopVpn() {
        val h = nativeHandle
        if (h != 0L) {
            nativeStop(h)
            nativeHandle = 0L
        }
        // Close TUN fd after Rust pump threads have exited.
        tunInterface?.close()
        tunInterface = null
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val channelId = "ankayma_vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Ankayma VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Ankayma mesh network active" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Ankayma VPN")
            .setContentText("Mesh network is active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    // Implemented in Rust (app_lib via JNI). Service instance is the implicit receiver
    // so Rust can call VpnService.protect(udpFd) to bypass tunnel routing.
    private external fun nativeStart(tunFd: Int, configJson: String): Long
    private external fun nativeStop(handle: Long)

    companion object {
        const val ACTION_STOP = "com.ankayma.app.VPN_STOP"
        const val EXTRA_CONFIG = "config_json"
        private const val NOTIFICATION_ID = 1001
    }
}
