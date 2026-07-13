package com.ankayma.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

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
            // Capture the upstream DNS BEFORE establishing the VPN tunnel. Once the
            // VPN is up with a default route (0.0.0.0/0), the active network becomes
            // the VPN itself, so we'd lose access to the underlying WiFi DNS. [T:F-3]
            val upstreamDns = getUpstreamDns()
            android.util.Log.i("AnkaymaVPN", "upstream DNS: $upstreamDns")

            val obj = JSONObject(configJson)
            // Inject upstream_dns (as a JSON array — matches build_config's shape) so
            // Rust forwards non-Ankayma DNS queries to it via a bindSocket()'d socket
            // (bypasses the TUN). The device's own WiFi DNS is preferred (handles local
            // names); public resolvers follow as fallbacks. [T:F-3]
            val upstreams = org.json.JSONArray()
            if (upstreamDns != null) upstreams.put(upstreamDns)
            upstreams.put("1.1.1.1")
            upstreams.put("8.8.8.8")
            obj.put("upstream_dns", upstreams)

            val overlayIp = obj.getString("overlay_ip")
            val isV6 = overlayIp.contains(":")

            // Magic DNS IP: fd00:a11a::53 — reserved Ankayma ULA address for the
            // in-process DNS interceptor (F-3 private domain). Routes through TUN so
            // DNS queries to this IP are caught by spawn_tx_with_dns in the pump.
            val magicDnsIp = "fd00:a11a::53"

            val builder = Builder()
                .setSession("Ankayma")
                .setMtu(1420)
                .setBlocking(true)

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
                // Add a dummy IPv4 address + default route so Android makes this VPN the
                // default network — required for the system DNS resolver to use our
                // addDnsServer() instead of the underlying WiFi DNS. Non-Ankayma IPv4
                // traffic entering TUN is silently dropped in the pump (no matching peer).
                builder.addAddress("10.0.0.1", 32)
                builder.addRoute("0.0.0.0", 0)
                // IPv6 default route: without this Android assumes no IPv6 internet and
                // the stub resolver only sends A (qtype=1) queries, never AAAA (qtype=28).
                // We need AAAA queries to answer with the peer overlay IPv6 address.
                // Non-Ankayma IPv6 traffic entering TUN is silently dropped (same as IPv4).
                // [T:4a597ca — re-applied; dropped during c8a5c97 re-implementation]
                builder.addRoute("::", 0)
            } else {
                // IPv4 overlay (legacy; current control plane issues IPv6).
                builder.addAddress(overlayIp, 32)
                builder.addRoute("10.0.0.0", 8)
            }

            // F-3 DNS: only the magic IP — non-Ankayma queries are forwarded in-process
            // to the upstream WiFi DNS via a protect()ed socket (Tailscale pattern).
            // 8.8.8.8 removed: with 0.0.0.0/0 default route it's unreachable via TUN.
            builder.addDnsServer(InetAddress.getByName(magicDnsIp))

            val pfd = builder.establish() ?: run {
                    // VPN permission not yet granted — establish() returns null.
                    stopSelf()
                    return START_NOT_STICKY
                }

            tunInterface = pfd
            // Pass updated config (with upstream_dns injected) to Rust.
            nativeHandle = nativeStart(pfd.fd, obj.toString())

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

    /// Get the first non-loopback DNS server from the underlying (non-VPN) network.
    /// Called BEFORE builder.establish() so the active network is still WiFi/cellular.
    /// Returns null on any error so the caller can proceed without upstream DNS.
    private fun getUpstreamDns(): String? {
        return try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return null
            // Walk all networks to find one with internet that is NOT the VPN.
            // activeNetwork can be the VPN itself on reconnect, so we check all networks.
            cm.allNetworks
                .mapNotNull { net ->
                    val caps = cm.getNetworkCapabilities(net) ?: return@mapNotNull null
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
                    cm.getLinkProperties(net)
                }
                .flatMap { it.dnsServers }
                // Skip loopback and link-local (fe80::) addresses: link-local addresses
                // carry a zone ID suffix (%wlan0) that Rust's SocketAddr parser rejects.
                // Prefer a routable unicast DNS server (typically 192.168.x.x or 8.8.8.8).
                .firstOrNull { !it.isLoopbackAddress && !it.isLinkLocalAddress }
                ?.hostAddress
        } catch (e: Exception) {
            android.util.Log.w("AnkaymaVPN", "getUpstreamDns failed: ${e.message}")
            null
        }
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

    /// Forward a raw DNS UDP payload to `upstreamIp:53` on the non-VPN network.
    /// Uses `network.bindSocket()` to bypass TUN routing — more reliable than
    /// protect()+socket on OEM firmware that ignores protect(). [T:F-3]
    /// Called from Rust via JNI (dns_forward_fn in pump::DnsInterceptor).
    fun forwardDns(payload: ByteArray, upstreamIp: String): ByteArray? {
        return try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return null
            val net = cm.allNetworks.firstOrNull { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            } ?: return null

            val sock = DatagramSocket()
            // Bind to the non-VPN network — this is what makes DNS bypass the TUN.
            net.bindSocket(sock)
            sock.soTimeout = 2000
            val addr = InetAddress.getByName(upstreamIp)
            sock.send(DatagramPacket(payload, payload.size, addr, 53))
            val buf = ByteArray(512)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            sock.close()
            buf.copyOf(resp.length)
        } catch (e: Exception) {
            android.util.Log.w("AnkaymaVPN", "forwardDns failed: ${e.message}")
            null
        }
    }

    /// Bind an existing socket fd (created in Rust) to the non-VPN network so its
    /// traffic bypasses the TUN — same mechanism as forwardDns(), reliable on OEM
    /// firmware where protect() is silently ignored. Used by the control-plane HTTP
    /// proxy so the app can reach cp.ankayma.com while the full-tunnel VPN is up.
    /// Must be called BEFORE connect(). Returns true if bound. [T:F-3 bindSocket pattern]
    fun bindSocketToUnderlyingNetwork(fd: Int): Boolean {
        return try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return false
            val net = cm.allNetworks.firstOrNull { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            } ?: return false
            // fromFd dups the fd; binding the dup marks the shared underlying socket,
            // then we close the dup — the original Rust fd stays open and bound.
            val pfd = android.os.ParcelFileDescriptor.fromFd(fd)
            net.bindSocket(pfd.fileDescriptor)
            pfd.close()
            true
        } catch (e: Exception) {
            android.util.Log.w("AnkaymaVPN", "bindSocket failed: ${e.message}")
            false
        }
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
