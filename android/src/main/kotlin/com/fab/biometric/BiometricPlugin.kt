package com.fab.biometric

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.util.Log
import androidx.annotation.NonNull
import androidx.biometric.BiometricManager
import com.fab.biometric.utils.SecureLocalManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import io.flutter.embedding.engine.plugins.lifecycle.FlutterLifecycleAdapter

/** BiometricPlugin */
class BiometricPlugin: FlutterPlugin,
        MethodCallHandler,
        ActivityAware {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private lateinit var activity: Activity
  private lateinit var mPluginHelper: PluginHelper
//  private lateinit var mSecureLocalManager: SecureLocalManager

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "biometric")
    channel.setMethodCallHandler(this)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    when (call.method) {
      PluginHelper.CREATE_KEYS -> mPluginHelper.createKeys(call, result)
      PluginHelper.AVAILABLE_BIOMETRICS -> mPluginHelper.getAvailableBiometrics(result)
      PluginHelper.METHOD_AUTHENTICATE -> mPluginHelper.authenticate(call, result)
      PluginHelper.METHOD_DEVICE_SUPPORTED -> mPluginHelper.isDeviceSupported(result)
      PluginHelper.METHOD_STOP_AUTH -> mPluginHelper.stopAuthentication(result)
      else -> result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
//    mSecureLocalManager = SecureLocalManager(activity.applicationContext)
    mPluginHelper = PluginHelper(activity)
    binding.addActivityResultListener(resultListener)
    setServicesFromActivity(binding.activity)
    mPluginHelper.lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(binding)
    channel.setMethodCallHandler(this)
  }

  override fun onDetachedFromActivity() {
    mPluginHelper.lifecycle = null
    channel.setMethodCallHandler(null)
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    Log.d("====", "onReattachedToActivityForConfigChanges")
    binding.addActivityResultListener(resultListener)
    setServicesFromActivity(binding.activity)
    mPluginHelper.lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(binding)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    Log.d("====", "onDetachedFromActivityForConfigChanges")
    mPluginHelper.lifecycle = null
  }

  private fun setServicesFromActivity(activity: Activity?) {
    if (activity == null) return
    this.activity = activity
    val context = activity.baseContext
    mPluginHelper.biometricManager = BiometricManager.from(activity)
    mPluginHelper.keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      mPluginHelper.fingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as? FingerprintManager
    }
  }

  private val resultListener = ActivityResultListener { requestCode, resultCode, data ->
    if (requestCode == PluginHelper.LOCK_REQUEST_CODE) {
      if (resultCode == Activity.RESULT_OK && mPluginHelper.lockRequestResult != null) {
        mPluginHelper.authenticateSuccess(mPluginHelper.lockRequestResult)
      } else {
        mPluginHelper.authenticateFail(mPluginHelper.lockRequestResult)
      }
      mPluginHelper.lockRequestResult = null
    }
    false
  }
}
