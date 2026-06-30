package tech.ssemaj.poseidon.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.ui.NavDisplay
import tech.ssemaj.poseidon.control.PoseidonViewModel
import tech.ssemaj.poseidon.ui.components.WaveBackground
import tech.ssemaj.poseidon.ui.overview.OverviewScreen
import tech.ssemaj.poseidon.ui.policy.PolicyScreen

// ─── Destination keys ────────────────────────────────────────────────────────

private sealed interface Dest {
    val label: String
    val icon: ImageVector
}

private data object Overview : Dest {
    override val label = "Overview"
    override val icon = Icons.Default.Shield
}

private data object Tiers : Dest {
    override val label = "Tiers"
    override val icon = Icons.Default.List
}

private data object Playground : Dest {
    override val label = "Play"
    override val icon = Icons.Default.PlayArrow
}

private data object Policy : Dest {
    override val label = "Policy"
    override val icon = Icons.Default.Lock
}

private val DESTS: List<Dest> = listOf(Overview, Tiers, Playground, Policy)

// ─── Top-level back-stack manager ────────────────────────────────────────────
// Mirrors the TopLevelBackStack from the Nav3 common-ui recipe.
// Each tab has its own history; back removes the last entry and pops tabs.

private class TopLevelBackStack<T : Any>(startKey: T) {

    private var topLevelStacks: LinkedHashMap<T, SnapshotStateList<T>> = linkedMapOf(
        startKey to mutableStateListOf(startKey)
    )

    var topLevelKey by mutableStateOf(startKey)
        private set

    val backStack: SnapshotStateList<T> = mutableStateListOf(startKey)

    private fun updateBackStack() = backStack.apply {
        clear()
        addAll(topLevelStacks.flatMap { it.value })
    }

    fun addTopLevel(key: T) {
        if (topLevelStacks[key] == null) {
            topLevelStacks[key] = mutableStateListOf(key)
        } else {
            topLevelStacks.apply {
                remove(key)?.let { put(key, it) }
            }
        }
        topLevelKey = key
        updateBackStack()
    }

    fun removeLast() {
        val removedKey = topLevelStacks[topLevelKey]?.removeLastOrNull()
        topLevelStacks.remove(removedKey)
        if (topLevelStacks.isEmpty()) return
        topLevelKey = topLevelStacks.keys.last()
        updateBackStack()
    }
}

// ─── Root composable ─────────────────────────────────────────────────────────

@Composable
fun PoseidonApp(vm: PoseidonViewModel) {
    val state by vm.state.collectAsState()
    val policy = remember { vm.policySnapshot() }
    val topLevelBackStack = remember { TopLevelBackStack<Any>(Overview) }

    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            NavigationBar {
                DESTS.forEach { dest ->
                    NavigationBarItem(
                        selected = dest == topLevelBackStack.topLevelKey,
                        onClick = { topLevelBackStack.addTopLevel(dest) },
                        icon = { Icon(dest.icon, contentDescription = dest.label) },
                        label = {
                            Text(dest.label, style = MaterialTheme.typography.labelMedium)
                        },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize()) {
            WaveBackground()
            Box(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                NavDisplay(
                    backStack = topLevelBackStack.backStack,
                    onBack = { topLevelBackStack.removeLast() },
                    entryProvider = entryProvider {
                        entry<Overview> {
                            OverviewScreen(state, vm::toggleMode, vm::runAllProbes)
                        }
                        entry<Tiers> {
                            PlaceholderScreen("Tiers — Phase 2")
                        }
                        entry<Playground> {
                            PlaceholderScreen("Playground — Phase 2")
                        }
                        entry<Policy> {
                            PolicyScreen(policy)
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun PlaceholderScreen(text: String) {
    Box(Modifier.fillMaxSize()) {
        Text(text, modifier = Modifier.padding(24.dp))
    }
}
