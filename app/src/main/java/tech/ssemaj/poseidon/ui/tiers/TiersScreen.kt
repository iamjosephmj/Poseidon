package tech.ssemaj.poseidon.ui.tiers

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.ui.components.EventRow
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.DeepBlue
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary

private data class TierMeta(val tier: Tier, val title: String, val blurb: String)

private val TIER_META = listOf(
    TierMeta(Tier.JVM, "JVM ADAPTERS",
        "OkHttp · HttpURLConnection · Volley · Cronet Java API — gated by the plugin's bytecode-injected adapters."),
    TierMeta(Tier.NATIVE, "NATIVE LIBC SHIM",
        "Cronet & gRPC native sockets via libposeidon_shim.so (ELF DT_NEEDED interposition of connect/sendto)."),
    TierMeta(Tier.SECCOMP, "SECCOMP GATE",
        "Raw connect()/sendto() syscalls (Go-runtime style) caught by the USER_NOTIF supervisor."),
)

@Composable
fun TiersScreen(state: UiState) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("ENFORCEMENT TIERS", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        TIER_META.forEach { meta ->
            val tally = state.tierTallies.firstOrNull { it.tier == meta.tier }
            val recent = state.events.filter { it.tier == meta.tier }.take(5)
            TierCard(meta, tally?.allowed ?: 0, tally?.blocked ?: 0, recent)
        }
    }
}

@Composable
private fun TierCard(
    meta: TierMeta,
    allowed: Int,
    blocked: Int,
    recent: List<EgressEvent>,
) {
    Surface(color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(meta.title, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
            Text(meta.blurb, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("$allowed allowed", style = MaterialTheme.typography.labelMedium, color = AquaAllow)
                Text("$blocked blocked", style = MaterialTheme.typography.labelMedium, color = CoralBlock)
            }
            if (recent.isEmpty()) {
                Text("no traffic yet", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            } else {
                recent.forEach { EventRow(it) }
            }
        }
    }
}
