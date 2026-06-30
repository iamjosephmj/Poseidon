package tech.ssemaj.poseidon.ui.overview

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.control.UiState
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.ui.components.EventRow
import tech.ssemaj.poseidon.ui.components.StatTile
import tech.ssemaj.poseidon.ui.components.TridentHeader
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.TextSecondary

@Composable
fun OverviewScreen(state: UiState, onToggleMode: () -> Unit, onRunAll: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        TridentHeader(enforcing = state.mode == Mode.ENFORCE, onModeClick = onToggleMode)
        Text(
            "Default-deny egress control across three enforcement tiers.",
            style = MaterialTheme.typography.bodyLarge,
            color = TextSecondary,
            modifier = Modifier.padding(horizontal = 20.dp),
        )
        Row(Modifier.fillMaxWidth().padding(20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile("ALLOWED", state.allowedTotal.toString(), AquaAllow, Modifier.weight(1f))
            StatTile("BLOCKED", state.blockedTotal.toString(), CoralBlock, Modifier.weight(1f))
        }
        Button(onClick = onRunAll, modifier = Modifier.padding(horizontal = 20.dp)) {
            Text("RUN ALL PROBES", style = MaterialTheme.typography.labelMedium)
        }
        Text(
            "RECENT EGRESS",
            style = MaterialTheme.typography.headlineMedium,
            color = TextSecondary,
            modifier = Modifier.padding(start = 20.dp, top = 8.dp),
        )
        LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
            items(state.events.take(25)) { EventRow(it) }
        }
    }
}
