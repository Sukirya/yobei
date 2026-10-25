package com.sukirya.yobei

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.TextView

/**
 * Placeholder provider activities for the credential-provider flow.
 *
 * Next step (tracked in docs/DESIGN.md): bridge into the Rust core —
 * unlock the vault, list/create the credential for the requesting RP,
 * and return the WebAuthn response via the Credential Manager result
 * intents. For now they explain and cancel cleanly.
 */
private fun showPlaceholder(activity: Activity, text: String) {
    val view = TextView(activity).apply {
        this.text = text
        gravity = Gravity.CENTER
        textSize = 16f
        setPadding(48, 48, 48, 48)
    }
    activity.setContentView(view)
    activity.setResult(Activity.RESULT_CANCELED)
    view.setOnClickListener { activity.finish() }
    view.postDelayed({ if (!activity.isFinishing) activity.finish() }, 3000)
}

class PasskeyUnlockActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showPlaceholder(this, "yobei 通行密钥：解锁与签名桥接即将完成，本次登录已取消。")
    }
}

class PasskeyCreateActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showPlaceholder(this, "yobei 通行密钥：创建桥接即将完成，本次创建已取消。")
    }
}
