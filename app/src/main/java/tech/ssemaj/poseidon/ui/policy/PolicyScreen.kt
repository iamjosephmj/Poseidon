package tech.ssemaj.poseidon.ui.policy

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary

@Composable
fun PolicyScreen(policy: PolicyInfo) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("WHAT WE'RE FILTERING", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        Row { Text("mode  ", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
              Text(policy.mode, color = TextPrimary, style = MaterialTheme.typography.bodySmall) }
        Text("allow hosts: ${policy.allowedHosts.joinToString().ifEmpty { "—" }}",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("deny paths: ${policy.deniedPaths.joinToString().ifEmpty { "—" }} (JVM/HTTP-only)",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("allow CIDRs: ${policy.allowedCidrs.joinToString().ifEmpty { "—" }}",
            color = TextPrimary, style = MaterialTheme.typography.bodySmall)
        Text("Strict default-deny posture — not an absolute egress guarantee.",
            color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
    }
}
