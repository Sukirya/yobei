package com.sukirya.yobei

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.util.concurrent.Executor

/**
 * Android Credential Manager provider (Android 14+): lets other apps and
 * websites create and use the passkeys stored in the yobei vault.
 *
 * Current state (v0.1): the service is registered and answers begin
 * requests with entries that open the provider activities. Those
 * activities are where the vault bridge lands next (unlock, pick the
 * credential, sign with yobei-core's WebAuthn authenticator via the
 * Rust <-> Kotlin bridge). Until then the activities explain the state
 * and cancel gracefully instead of failing silently.
 */
class YobeiCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        executor: Executor,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        val publicKeyOption = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
            .firstOrNull()
        if (publicKeyOption == null) {
            callback.onResult(BeginGetCredentialResponse())
            return
        }
        val intent = Intent(this, PasskeyUnlockActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            REQUEST_CODE_GET,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val entry = PublicKeyCredentialEntry.Builder(
            this,
            "yobei 保险库",
            pendingIntent,
            publicKeyOption
        ).setDisplayName("使用 yobei 中保存的通行密钥").build()
        callback.onResult(
            BeginGetCredentialResponse.Builder().addCredentialEntry(entry).build()
        )
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        executor: Executor,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        val intent = Intent(this, PasskeyCreateActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            REQUEST_CODE_CREATE,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val entry = CreateEntry.Builder("yobei 保险库", pendingIntent)
            .setDescription("把通行密钥保存在 yobei 中（端到端加密）")
            .build()
        callback.onResult(
            BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build()
        )
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        executor: Executor,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Nothing cached provider-side; the vault is the only store.
        callback.onResult(null)
    }

    companion object {
        private const val REQUEST_CODE_GET = 0xB01
        private const val REQUEST_CODE_CREATE = 0xB02
    }
}
