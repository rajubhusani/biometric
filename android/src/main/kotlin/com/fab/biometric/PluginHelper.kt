package com.fab.biometric

import android.app.Activity
import android.app.KeyguardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class PluginHelper(private val activity: Activity) {

    var biometricManager: BiometricManager? = null
    var fingerprintManager: FingerprintManager? = null
    var keyguardManager: KeyguardManager? = null
    private var authHelper: AuthenticationHelper? = null
    var lockRequestResult: MethodChannel.Result? = null
    private val authInProgress = AtomicBoolean(false)
    var lifecycle: Lifecycle? = null

    fun createKeys(call: MethodCall, result: MethodChannel.Result) {
        if (!authInProgress.compareAndSet(false, true)) {
            result.error("auth_in_progress", "Authentication in progress", null)
            return
        }

        if (activity.isFinishing) {
            if (authInProgress.compareAndSet(true, false)) {
                result.error("no_activity", "local_auth plugin requires a foreground activity", null)
            }
            return
        }

        if (activity !is FragmentActivity) {
            if (authInProgress.compareAndSet(true, false)) {
                result.error("no_fragment_activity", "local_auth plugin requires activity to be a FragmentActivity.", null)
            }
            return
        }
        val completionHandler: AuthenticationHelper.AuthCompletionHandler = object : AuthenticationHelper.AuthCompletionHandler {

            override fun onSuccess(cryptoObject: BiometricPrompt.CryptoObject?) {
                   if (authInProgress.compareAndSet(true, false)) {
                            try {
                                deleteBiometricKey()
                                val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
                                val keyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
                                        KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256)
                                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                        .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                                        .setUserAuthenticationRequired(true).build()
                                keyPairGenerator.initialize(keyGenParameterSpec)
                                keyPairGenerator.generateKeyPair()
                                result?.success(true)
                            } catch (e: Exception) {
                                result.error("create_keys_error", "Error generating public private keys: " + e.message, null)
                            }
                        }
            }

            override fun onError(code: String?, error: String?) {
                if (authInProgress.compareAndSet(true, false)) {
                    result.error(code, error, null)
                }
            }

            override fun onFailure() {
                if (authInProgress.compareAndSet(true, false)) {
                    result.success(false)
                }
            }
        }
        val authenticationHelper = AuthenticationHelper(lifecycle, activity, call, null, completionHandler, false)
        authenticationHelper.authenticate()
    }


    /*
   * Starts authentication process
   */
    fun authenticate(call: MethodCall, result: MethodChannel.Result) {
        if (authInProgress.get()) {
            result.error(AUTH_IN_PROGRESS, "Authentication in progress", null)
            return
        }
        if (activity.isFinishing) {
            result.error(ERROR_NO_ACTIVITY, "Biometric plugin requires a foreground activity", null)
            return
        }
        if (activity !is FragmentActivity) {
            result.error(
                    ERROR_NO_FRAGMENT,
                    "Biometric plugin requires activity to be a FragmentActivity.",
                    null)
            return
        }
        if (!isDeviceSupported()) {
            authInProgress.set(false)
            result.error("NotAvailable", "Required security features not enabled", null)
            return
        }
        authInProgress.set(true)
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey

            val signature = Signature.getInstance("SHA256withRSA")
            signature.initSign(privateKey)

            val crypto = BiometricPrompt.CryptoObject(signature)
//            val crypto = BiometricPrompt.CryptoObject(secureLocalManager.getLocalEncryptionCipher())
            val completionHandler: AuthenticationHelper.AuthCompletionHandler = object : AuthenticationHelper.AuthCompletionHandler {

                override fun onSuccess(cryptoObject: BiometricPrompt.CryptoObject?) {
//                    val cipher = cryptoObject?.cipher!!
//                        secureLocalManager.loadOrGenerateApplicationKey(cipher)
                    authenticateSuccess(result)
                }

                override fun onError(code: String?, error: String?) {
                    if (authInProgress.compareAndSet(true, false)) {
                        result.error(code, error, null)
                    }
                }

                override fun onFailure() {
                    authenticateFail(result)
                }
            }

            // if is biometricOnly try biometric prompt - might not work
            val isBiometricOnly = call.argument<Boolean>("biometricOnly")!!
            if (isBiometricOnly) {
                if (!canAuthenticateWithBiometrics()) {
                    if (!hasBiometricHardware()) {
                        completionHandler.onError("NoHardware", "No biometric hardware found")
                    }
                    completionHandler.onError("NotEnrolled", "No biometrics enrolled on this device.")
                    return
                }
                authHelper = AuthenticationHelper(lifecycle, (activity as FragmentActivity?)!!, call, crypto, completionHandler, false)
                authHelper?.authenticate()
                return
            }

            // API 29 and above
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                authHelper = AuthenticationHelper(lifecycle, (activity as FragmentActivity?)!!, call, crypto, completionHandler, true)
                authHelper?.authenticate()
                return
            }

            // API 23 - 28 with fingerprint
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && fingerprintManager != null) {
                if (fingerprintManager?.hasEnrolledFingerprints()!!) {
                    authHelper = AuthenticationHelper(lifecycle, (activity as FragmentActivity?)!!, call, crypto, completionHandler, false)
                    authHelper?.authenticate()
                    return
                }
            }

            // API 23 or higher with device credentials
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && keyguardManager != null && keyguardManager?.isDeviceSecure!!) {
                val title = call.argument<String>("signInTitle")
                val reason = call.argument<String>("localizedReason")
                val authIntent: Intent? = keyguardManager?.createConfirmDeviceCredentialIntent(title, reason)

                // save result for async response
                lockRequestResult = result
                activity.startActivityForResult(authIntent, LOCK_REQUEST_CODE)
                return
            }

            // Unable to authenticate
            result.error("NotSupported", "This device does not support required security features", null)

        } catch (invalidatedException: KeyPermanentlyInvalidatedException) {
            if (authInProgress.compareAndSet(true, false)) {
                result.error(ERROR_INVALIDATE, "Biometric keys are invalidated: " + invalidatedException.message, null)
            }
        } catch (e: java.lang.Exception) {
            if (authInProgress.compareAndSet(true, false)) {
                result.error(ERROR_SIGN_KEY, "Error retrieving keys: " + e.message, null)
            }
        }
    }

    fun authenticateSuccess(result: MethodChannel.Result?) {
        if (authInProgress.compareAndSet(true, false)) {
            result?.success(true)
        }
    }

    fun authenticateFail(result: MethodChannel.Result?) {
        if (authInProgress.compareAndSet(true, false)) {
            result?.success(false)
        }
    }

    /*
   * Stops the authentication if in progress.
   */
    fun stopAuthentication(result: MethodChannel.Result) {
        try {
            if (authHelper != null && authInProgress.get()) {
                authHelper?.stopAuthentication()
                authHelper = null
            }
            authInProgress.set(false)
            result.success(true)
        } catch (e: java.lang.Exception) {
            result.success(false)
        }
    }

    /*
   * Returns biometric types available on device
   */
    fun getAvailableBiometrics(result: MethodChannel.Result) {
        try {
            if (activity.isFinishing) {
                result.error(ERROR_NO_ACTIVITY, "Biometric plugin requires a foreground activity", null)
                return
            }
            val biometrics = getAvailableBiometrics()
            result.success(biometrics)
        } catch (e: java.lang.Exception) {
            result.error(ERROR_NO_BIOMETRIC_AVAILABLE, e.message, null)
        }
    }

    private fun getAvailableBiometrics(): ArrayList<String> {
        val biometrics = ArrayList<String>()
        val packageManager = activity.packageManager
        if (Build.VERSION.SDK_INT >= 23) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
                biometrics.add(SupportedTypes.fingerprint.name)
            }
        }
        if (Build.VERSION.SDK_INT >= 29) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
                biometrics.add(SupportedTypes.face.name)
            }
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                biometrics.add(SupportedTypes.iris.name)
            }
        }
        return biometrics
    }

    private fun isDeviceSupported(): Boolean {
        return if (keyguardManager == null) false else Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && keyguardManager?.isDeviceSecure!!
    }

    private fun canAuthenticateWithBiometrics(): Boolean {
        return if (biometricManager == null) false else biometricManager?.canAuthenticate() === BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun hasBiometricHardware(): Boolean {
        return if (biometricManager == null) false else biometricManager?.canAuthenticate() !== BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE
    }

    fun isDeviceSupported(result: MethodChannel.Result) {
        result.success(isDeviceSupported())
    }

    private fun deleteBiometricKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(KEY_ALIAS)
            true
        } catch (e: java.lang.Exception) {
            false
        }
    }

    companion object {
        const val CREATE_KEYS = "createKeys"
        const val SIGN = "sign"
        const val METHOD_AUTHENTICATE = "authenticate"
        const val AVAILABLE_BIOMETRICS = "getAvailableBiometrics"
        const val METHOD_DEVICE_SUPPORTED = "isDeviceSupported"
        const val METHOD_STOP_AUTH = "stopAuthentication"
        const val KEY_ALIAS = "biometric_key"
        const val KEYSTORE = "AndroidKeyStore"
        const val SHA256RSA = "SHA256withRSA"
        const val PAYLOAD = "payload"
        const val ERROR_INVALIDATE = "biometrics_invalidated"
        const val ERROR_SIGN_KEY = "sign_error_key"
        const val ERROR_NO_ACTIVITY = "no_activity"
        const val ERROR_NO_BIOMETRIC_AVAILABLE = "no_biometrics_available"
        const val ERROR_SIGN = "sign_error"
        const val AUTH_IN_PROGRESS = "auth_in_progress"
        const val ERROR_NO_FRAGMENT = "no_fragment_activity"
        const val KEY_REQUIRED = "required"
        const val KEY_SETTINGS_DESC = "settingsDescription"
        const val KEY_SETTINGS = "settings"
        const val KEY_CANCEL = "cancel"
        const val ERROR_NOT_AVAILABLE = "not_available"
        const val ERROR_TEMP_LOCKED = "temp_locked_out"
        const val ERROR_LOCKED_OUT = "locked_out"
        const val ERROR_KEYS = "create_keys_error"
        const val ERROR_PAYLOAD_NOT_PROVIDED = "payload_not_provided"
        const val KEY_REASON = "reason"
        const val KEY_TITLE = "title"
        const val KEY_HINT = "hint"
        const val LOCK_REQUEST_CODE = 221
    }
}

enum class SupportedTypes {
    fingerprint, face, iris
}