package tech.ssemaj.poseidon.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.ui.theme.*

@Composable
fun WaveBackground(modifier: Modifier = Modifier) {
    val t = rememberInfiniteTransition(label = "wave")
    val phase by t.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(6000, easing = LinearEasing), RepeatMode.Restart),
        label = "phase",
    )
    Canvas(modifier.fillMaxSize().background(Brush.verticalGradient(listOf(AbyssalNavy, MarineBlue)))) {
        val w = size.width; val h = size.height
        val path = Path().apply {
            moveTo(0f, h * 0.5f)
            var x = 0f
            while (x <= w) {
                val y = h * 0.5f + 24f * kotlin.math.sin((x / w * 6.28f) + phase * 6.28f)
                lineTo(x, y); x += 8f
            }
            lineTo(w, h); lineTo(0f, h); close()
        }
        drawPath(path, BioluminescentTeal.copy(alpha = 0.06f))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ModeChip(enforcing: Boolean, onClick: () -> Unit) {
    val accent = if (enforcing) AquaAllow else TridentGold
    Surface(
        color = accent.copy(alpha = 0.15f),
        shape = RoundedCornerShape(50),
        onClick = onClick,
    ) {
        Text(
            text = if (enforcing) "◐ ENFORCE" else "○ MONITOR",
            style = MaterialTheme.typography.labelMedium,
            color = accent,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 7.dp),
        )
    }
}

@Composable
fun TridentHeader(enforcing: Boolean, onModeClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("⟁ POSEIDON", style = MaterialTheme.typography.displayLarge, color = TridentGold)
        Spacer(Modifier.weight(1f))
        ModeChip(enforcing, onModeClick)
    }
}

@Composable
fun StatTile(label: String, value: String, accent: Color, modifier: Modifier = Modifier) {
    Surface(modifier, color = DeepBlue, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(18.dp)) {
            Text(value, style = MaterialTheme.typography.displayLarge, color = accent)
            Text(label, style = MaterialTheme.typography.headlineMedium, color = TextSecondary)
        }
    }
}

@Composable
fun VerdictBadge(blocked: Boolean) {
    val accent = if (blocked) CoralBlock else AquaAllow
    Surface(color = accent.copy(alpha = 0.15f), shape = RoundedCornerShape(6.dp)) {
        Text(
            if (blocked) "BLOCK" else "ALLOW",
            style = MaterialTheme.typography.labelSmall, color = accent,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

@Composable
fun EventRow(event: EgressEvent) {
    val blocked = event.decision?.block == true
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically) {
        VerdictBadge(blocked)
        Spacer(Modifier.width(10.dp))
        Text("[${event.tier}] ${event.host ?: event.ip ?: "?"}${event.path ?: ""}",
            style = MaterialTheme.typography.bodySmall, color = TextPrimary)
    }
}
