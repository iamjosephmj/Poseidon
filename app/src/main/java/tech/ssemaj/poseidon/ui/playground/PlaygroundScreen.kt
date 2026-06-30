package tech.ssemaj.poseidon.ui.playground

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.ClientStyle
import tech.ssemaj.poseidon.VerifyState
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.ui.components.EventRow
import tech.ssemaj.poseidon.ui.components.ModeChip
import tech.ssemaj.poseidon.ui.components.VerdictBadge
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PlaygroundScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit) {
    val ctx = LocalContext.current
    val verify = remember { VerifyState() }
    DisposableEffect(Unit) { onDispose { verify.shutdown() } }
    var style by remember { mutableStateOf(ClientStyle.OKHTTP) }

    LazyColumn(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                ModeChip(enforcing = state.mode == Mode.ENFORCE, onClick = onToggleMode)
                Spacer(Modifier.weight(1f))
                OutlinedButton(onClick = onRunAll) {
                    Text("RUN ALL", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
        item {
            OutlinedTextField(
                value = verify.url.value,
                onValueChange = { verify.url.value = it },
                singleLine = true,
                label = { Text("Target URL") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = { verify.url.value = "https://example.com/demo/path?x=1" },
                    label = { Text("allowed: example.com") },
                )
                AssistChip(
                    onClick = { verify.url.value = "https://www.google.com/" },
                    label = { Text("denied: google.com") },
                )
            }
        }
        item {
            FlowRowClients(selected = style, onSelect = { style = it })
        }
        item {
            Button(
                onClick = { verify.run(style, ctx) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("FIRE  ▸  ${style.label}", style = MaterialTheme.typography.labelMedium)
            }
        }
        item {
            Text(
                "RESULTS",
                style = MaterialTheme.typography.headlineMedium,
                color = TextSecondary,
            )
        }
        items(verify.results, key = { it.id }) { r ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                VerdictBadge(blocked = r.blocked)
                Text(
                    "${r.client}: ${r.outcome}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextPrimary,
                )
            }
        }
        item {
            Text(
                "LIVE EGRESS",
                style = MaterialTheme.typography.headlineMedium,
                color = TextSecondary,
            )
        }
        // Use itemsIndexed to avoid duplicate-key crashes (EgressEvent has no stable id field).
        itemsIndexed(state.events.take(20)) { _, e -> EventRow(e) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FlowRowClients(selected: ClientStyle, onSelect: (ClientStyle) -> Unit) {
    // Use horizontalScroll so chips don't overflow on narrow screens.
    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.horizontalScroll(rememberScrollState()),
    ) {
        ClientStyle.entries.forEach { c ->
            FilterChip(
                selected = c == selected,
                onClick = { onSelect(c) },
                label = { Text(c.label) },
            )
        }
    }
}
