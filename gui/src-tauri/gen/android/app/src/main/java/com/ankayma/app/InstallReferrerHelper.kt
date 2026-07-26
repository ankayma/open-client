package com.ankayma.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.android.installreferrer.api.InstallReferrerClient
import com.android.installreferrer.api.InstallReferrerStateListener
import com.android.installreferrer.api.ReferrerDetails

/**
 * Captures Play Install Referrer once at cold start and hands it to Rust for
 * deferred email-invite redeem. Sideload / no Play → empty string (clipboard
 * / short-code fallbacks still work).
 */
object InstallReferrerHelper {
    @JvmStatic
    external fun nativeSetReferrer(referrer: String)

    @JvmStatic
    fun fetch(context: Context) {
        val client = InstallReferrerClient.newBuilder(context).build()
        try {
            client.startConnection(object : InstallReferrerStateListener {
                override fun onInstallReferrerSetupFinished(responseCode: Int) {
                    var referrer = ""
                    if (responseCode == InstallReferrerClient.InstallReferrerResponse.OK) {
                        try {
                            val details: ReferrerDetails = client.installReferrer
                            referrer = details.installReferrer ?: ""
                        } catch (_: Exception) {
                            // Play services quirk — treat as empty.
                        }
                    }
                    try {
                        nativeSetReferrer(referrer)
                    } catch (_: UnsatisfiedLinkError) {
                        // Native lib not loaded yet; retry once shortly.
                        Handler(Looper.getMainLooper()).postDelayed({
                            try {
                                nativeSetReferrer(referrer)
                            } catch (_: UnsatisfiedLinkError) {
                            }
                        }, 500)
                    }
                    try {
                        client.endConnection()
                    } catch (_: Exception) {
                    }
                }

                override fun onInstallReferrerServiceDisconnected() {
                    // No retry loop — InviteResolver also has clipboard/short-code.
                }
            })
        } catch (_: Exception) {
            try {
                nativeSetReferrer("")
            } catch (_: UnsatisfiedLinkError) {
            }
        }
    }
}
