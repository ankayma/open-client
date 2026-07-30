# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# ─── JNI callbacks: Rust → Java ──────────────────────────────────────────────
# R8 cannot see a call that originates in native code, so anything only reached
# from Rust looks like dead code and gets removed. That is not a theoretical
# risk: shipped release builds crashed the moment the tunnel started, with
#
#   java.lang.NoSuchMethodError: no non-static method
#     "Lcom/ankayma/app/AnkaymaVpnService;.bindSocketToUnderlyingNetwork(I)Z"
#       at AnkaymaVpnService.nativeStart(Native Method)
#
# followed by the same for forwardDns on the DNS threads. The main thread hung
# inside nativeStart first, so the user saw the app freeze and got the system's
# "Close app / Wait" dialog before it died. Debug builds were unaffected because
# isMinifyEnabled is false there — which is exactly why this reached users.
# [T — reproduced on a moto g06 / Android 15 with 1.1.28, adb logcat 2026-07-30]
#
# Keep the whole service: it is a small class, the two entry points Rust calls
# (forwardDns, bindSocketToUnderlyingNetwork) are not obviously special to a
# future reader, and a partial rule would only invite the same bug back.
-keep class com.ankayma.app.AnkaymaVpnService { *; }

# Native method declarations and the classes holding them, so JNI name lookup
# still resolves after shrinking. Standard rule, kept here for the same reason.
-keepclasseswithmembernames class * {
    native <methods>;
}
