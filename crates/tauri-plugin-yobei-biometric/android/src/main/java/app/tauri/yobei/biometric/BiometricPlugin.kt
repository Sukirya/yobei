// Biometric unlock for yobei (ADR-0009).
//
// The vault key (32 bytes) plus its fingerprint (32 bytes, see
// `Vault::vault_key_check`) are encrypted under an Android Keystore key
// that requires one system authentication per use, and stored as a blob in
// the app-private directory. The Keystore key never leaves the secure
// area; the blob is useless without it, and the key is invalidated when
// the user enrolls a new biometric, so a stale blob fails loudly instead
// of opening the wrong vault.
//
// Prompt titles and subtitles come from the caller (the presentation layer
// owns user-visible text, ADR-0008); this file holds no UI strings.

package app.tauri.yobei.biometric

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@TauriPlugin
class BiometricPlugin(private val activity: Activity) : Plugin(activity) {
  companion object {
    private const val KEY_ALIAS = "yobei-biometric-key"
    private const val BLOB_FILE = "biometric_vault_key.bin"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_LEN = 12
    private const val KEY_LEN = 32
    private const val PLAINTEXT_LEN = 64 // vault key (32) + key check (32)
  }

  // ------------------------------------------------------------ keystore ---

  private fun keystore(): KeyStore =
    KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

  private fun getKey(): SecretKey? =
    try {
      keystore().getKey(KEY_ALIAS, null) as? SecretKey
    } catch (_: Exception) {
      null
    }

  private fun getOrCreateKey(): SecretKey {
    getKey()?.let { return it }
    val spec = KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
      .apply { init(spec) }
      .generateKey()
  }

  private fun deleteKey() {
    try {
      keystore().deleteEntry(KEY_ALIAS)
    } catch (_: Exception) {
    }
  }

  private fun blobFile(): File = File(activity.filesDir, BLOB_FILE)

  private fun deleteBlob() {
    try {
      blobFile().delete()
    } catch (_: Exception) {
    }
  }

  // ------------------------------------------------------------- prompt ---

  private sealed interface PromptResult {
    data class Success(val cipher: Cipher) : PromptResult
    data class Error(val message: String, val code: String) : PromptResult
    data object Cancelled : PromptResult
  }

  /** Shows a BiometricPrompt bound to [cipher] and reports the outcome. A
   * failed finger does not resolve: the prompt stays up for retries. */
  private fun showPrompt(
    fragmentActivity: AppCompatActivity,
    title: String,
    subtitle: String,
    cipher: Cipher,
    onResult: (PromptResult) -> Unit,
  ) {
    activity.runOnUiThread {
      val executor = ContextCompat.getMainExecutor(fragmentActivity)
      val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          val c = result.cryptoObject?.cipher
          if (c == null) onResult(PromptResult.Error("no cipher", "failed"))
          else onResult(PromptResult.Success(c))
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED -> onResult(PromptResult.Cancelled)
            BiometricPrompt.ERROR_LOCKOUT,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
              onResult(PromptResult.Error(errString.toString(), "locked_out"))
            else -> onResult(PromptResult.Error(errString.toString(), "failed"))
          }
        }

        override fun onAuthenticationFailed() {
          // A bad finger: the system keeps the prompt open for retries.
        }
      }
      val prompt = BiometricPrompt(fragmentActivity, executor, callback)
      val infoBuilder = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        infoBuilder.setAllowedAuthenticators(
          BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
      } else {
        @Suppress("DEPRECATION")
        infoBuilder.setDeviceCredentialAllowed(true)
      }
      prompt.authenticate(infoBuilder.build(), BiometricPrompt.CryptoObject(cipher))
    }
  }

  private fun fragmentActivity(): AppCompatActivity? = activity as? AppCompatActivity

  // ------------------------------------------------------------ commands ---

  @Command
  fun status(invoke: Invoke) {
    val result = BiometricManager.from(activity).canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    val state = when (result) {
      BiometricManager.BIOMETRIC_SUCCESS -> "available"
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no_hardware"
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "unavailable"
      BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "not_enrolled"
      BiometricManager.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL -> "no_device_credential"
      else -> "unavailable"
    }
    val obj = JSObject()
    obj.put("state", state)
    obj.put("enrolled", blobFile().exists())
    invoke.resolve(obj)
  }

  @InvokeArg
  class EnrollArgs {
    lateinit var vault_key_b64: String
    lateinit var key_check_b64: String
    lateinit var title: String
    lateinit var subtitle: String
  }

  @Command
  fun enroll(invoke: Invoke) {
    val args = try {
      invoke.parseArgs(EnrollArgs::class.java)
    } catch (e: Exception) {
      invoke.reject("bad enroll args", "failed", e)
      return
    }
    val plaintext = try {
      val key = Base64.decode(args.vault_key_b64, Base64.NO_WRAP)
      val check = Base64.decode(args.key_check_b64, Base64.NO_WRAP)
      if (key.size != KEY_LEN || check.size != KEY_LEN) {
        throw IllegalArgumentException("bad key length")
      }
      key + check
    } catch (e: Exception) {
      invoke.reject("bad enroll args", "failed", e)
      return
    }
    val fragmentActivity = fragmentActivity()
    if (fragmentActivity == null) {
      invoke.reject("biometrics unavailable", "not_available")
      return
    }
    val cipher = try {
      Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE, getOrCreateKey())
      }
    } catch (e: Exception) {
      invoke.reject("could not prepare device key", "failed", e)
      return
    }
    showPrompt(fragmentActivity, args.title, args.subtitle, cipher) { result ->
      when (result) {
        is PromptResult.Success -> {
          try {
            val blob = result.cipher.iv + result.cipher.doFinal(plaintext)
            blobFile().writeBytes(blob)
            invoke.resolve()
          } catch (e: Exception) {
            deleteBlob()
            invoke.reject("could not store biometric key", "failed", e)
          }
        }
        is PromptResult.Error -> invoke.reject(result.message, result.code)
        is PromptResult.Cancelled -> invoke.reject("cancelled", "cancelled")
      }
    }
  }

  @InvokeArg
  class PromptArgs {
    lateinit var title: String
    lateinit var subtitle: String
  }

  @Command
  fun unlock(invoke: Invoke) {
    val args = try {
      invoke.parseArgs(PromptArgs::class.java)
    } catch (e: Exception) {
      invoke.reject("bad unlock args", "failed", e)
      return
    }
    val blob = try {
      blobFile().readBytes()
    } catch (_: Exception) {
      invoke.reject("no biometric key stored", "not_available")
      return
    }
    if (blob.size <= IV_LEN) {
      deleteBlob()
      invoke.reject("no biometric key stored", "not_available")
      return
    }
    val iv = blob.copyOfRange(0, IV_LEN)
    val ciphertext = blob.copyOfRange(IV_LEN, blob.size)
    val fragmentActivity = fragmentActivity()
    if (fragmentActivity == null) {
      invoke.reject("biometrics unavailable", "not_available")
      return
    }
    val cipher = try {
      val key = getKey()
      if (key == null) {
        deleteBlob()
        invoke.reject("biometric key unavailable", "key_invalidated")
        return
      }
      Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
      }
    } catch (e: KeyPermanentlyInvalidatedException) {
      // A new biometric was enrolled (or the keystore was reset): the key
      // is gone for good. Drop the blob and fall back to the password.
      deleteKey()
      deleteBlob()
      invoke.reject("biometric key invalidated", "key_invalidated")
      return
    } catch (e: Exception) {
      deleteKey()
      deleteBlob()
      invoke.reject("biometric key unavailable", "key_invalidated")
      return
    }
    showPrompt(fragmentActivity, args.title, args.subtitle, cipher) { result ->
      when (result) {
        is PromptResult.Success -> {
          try {
            val plaintext = result.cipher.doFinal(ciphertext)
            if (plaintext.size != PLAINTEXT_LEN) throw IllegalStateException("bad plaintext")
            val obj = JSObject()
            obj.put(
              "vault_key_b64",
              Base64.encodeToString(plaintext.copyOfRange(0, KEY_LEN), Base64.NO_WRAP),
            )
            obj.put(
              "key_check_b64",
              Base64.encodeToString(plaintext.copyOfRange(KEY_LEN, PLAINTEXT_LEN), Base64.NO_WRAP),
            )
            invoke.resolve(obj)
          } catch (e: Exception) {
            // The blob no longer decrypts under this key: drop it and fall
            // back to the password path.
            deleteBlob()
            invoke.reject("biometric key does not match this vault", "key_invalidated", e)
          }
        }
        is PromptResult.Error -> invoke.reject(result.message, result.code)
        is PromptResult.Cancelled -> invoke.reject("cancelled", "cancelled")
      }
    }
  }

  @Command
  fun remove(invoke: Invoke) {
    deleteKey()
    deleteBlob()
    invoke.resolve()
  }
}
