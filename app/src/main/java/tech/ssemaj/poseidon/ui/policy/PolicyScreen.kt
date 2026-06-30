package tech.ssemaj.poseidon.ui.policy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.BioluminescentTeal
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.DeepBlue
import tech.ssemaj.poseidon.ui.theme.MarineBlue
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary
import tech.ssemaj.poseidon.ui.theme.TridentGold

/**
 * The active compiled policy (read from `assets/poseidon/policy.json`), presented as a
 * stack of accented cards: a mode banner, then the allow-hosts / deny-paths / CIDR
 * facets, then the honesty disclaimer. Read-only.
 */
@Composable
fun PolicyScreen(policy: PolicyInfo) {
    val enforcing = policy.mode.equals("enforce", ignoreCase = true)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("WHAT WE'RE FILTERING", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)

        ModeBanner(policy.mode, enforcing)

        PolicyCard(
            title = "ALLOW-LIST · HOSTS",
            accent = AquaAllow,
            blurb = "Only these hosts may receive egress; every other host is denied by default.",
        ) { ValueList(policy.allowedHosts, AquaAllow, emptyText = "none — all hosts denied") }

        PolicyCard(
            title = "DENY PATHS",
            accent = CoralBlock,
            blurb = "Blocked URL paths on allow-listed hosts. JVM/HTTP-only — TLS hides paths from the native and seccomp tiers.",
        ) { ValueList(policy.deniedPaths, CoralBlock, emptyText = "none") }

        PolicyCard(
            title = "ALLOW-LIST · IP RANGES (CIDR)",
            accent = BioluminescentTeal,
            blurb = "Bare-IP connections are permitted only inside these ranges.",
        ) { ValueList(policy.allowedCidrs, BioluminescentTeal, emptyText = "none") }

        Surface(color = MarineBlue, shape = RoundedCornerShape(16.dp)) {
            Text(
                "Strict default-deny posture — not an absolute egress guarantee.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            )
        }
    }
}

@Composable
private fun ModeBanner(mode: String, enforcing: Boolean) {
    val accent = if (enforcing) AquaAllow else TridentGold
    Surface(color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Row(Modifier.fillMaxWidth().padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("MODE", style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
                Text(mode.uppercase(), style = MaterialTheme.typography.displayLarge, color = accent)
            }
            Surface(color = accent.copy(alpha = 0.15f), shape = RoundedCornerShape(50)) {
                Text(
                    if (enforcing) "BLOCKING" else "LOG-ONLY",
                    style = MaterialTheme.typography.labelMedium,
                    color = accent,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 7.dp),
                )
            }
        }
    }
}

@Composable
private fun PolicyCard(title: String, accent: Color, blurb: String, content: @Composable () -> Unit) {
    Surface(color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = accent)
            Text(blurb, style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            content()
        }
    }
}

@Composable
private fun ValueList(values: List<String>, accent: Color, emptyText: String) {
    if (values.isEmpty()) {
        Text(emptyText, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        values.forEach { value ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Surface(color = accent, shape = RoundedCornerShape(50), modifier = Modifier.size(6.dp)) {}
                Text(value, style = MaterialTheme.typography.bodySmall, color = TextPrimary)
            }
        }
    }
}
