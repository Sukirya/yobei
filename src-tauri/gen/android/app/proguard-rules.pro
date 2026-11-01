# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# R8 runs on release builds (isMinifyEnabled). These keeps are load-bearing:
# the Tauri runtime is reached from Rust over JNI and from the manifest,
# and the app's own activities/services are launched by explicit intents.
# Without them R8 can rename or strip entry points the Rust side calls
# by name, which crashes at runtime instead of at build time.
-keep class app.tauri.** { *; }
-keep class com.sukirya.yobei.** { *; }

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