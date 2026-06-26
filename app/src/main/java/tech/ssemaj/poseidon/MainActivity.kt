package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.ui.platform.LocalContext
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.model.Tier
import tech.ssemaj.poseidon.ui.theme.AbyssalNavy
import tech.ssemaj.poseidon.ui.theme.AquaAllow
import tech.ssemaj.poseidon.ui.theme.BioluminescentTeal
import tech.ssemaj.poseidon.ui.theme.CoralBlock
import tech.ssemaj.poseidon.ui.theme.DeepBlue
import tech.ssemaj.poseidon.ui.theme.MarineBlue
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme
import tech.ssemaj.poseidon.ui.theme.TextPrimary
import tech.ssemaj.poseidon.ui.theme.TextSecondary
import tech.ssemaj.poseidon.ui.theme.TridentGold

class MainActivity : ComponentActivity() {

    private val dashboardState = EgressDashboardState()
    private val verifyState = VerifyState()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Register Observer sink before the probes fire so no events are missed.
        dashboardState.start()
        val policy = PolicyInfo.load(applicationContext)
        setContent {
            PoseidonTheme(darkTheme = true) {
                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = MaterialTheme.colorScheme.background,
                ) { innerPadding ->
                    PoseidonDashboard(
                        state    = dashboardState,
                        verify   = verifyState,
                        policy   = policy,
                        modifier = Modifier.padding(innerPadding),
                    )
                }
            }
        }
        // Fire all demo probes after UI is set up (background threads; won't block UI).
        DemoProbes.runAll(applicationContext)
    }

    override fun onDestroy() {
        super.onDestroy()
        dashboardState.stop()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Root screen
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun PoseidonDashboard(
    state: EgressDashboardState,
    verify: VerifyState,
    policy: PolicyInfo,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()

    // Re-pin to the top only when the user is already there, so scrolling/typing isn't yanked.
    LaunchedEffect(state.events.size) {
        if (listState.firstVisibleItemIndex == 0) {
            listState.scrollToItem(0)
        }
    }

    LazyColumn(
        state    = listState,
        modifier = modifier.fillMaxSize(),
    ) {
        item(key = "header")     { PoseidonHeader(policy) }
        item(key = "policy")     { PolicyCard(policy) }
        item(key = "verify")     { VerifyCard(verify) }
        item(key = "tiers")      { TiersSection(state = state) }
        item(key = "log_header") { LiveLogHeader(eventCount = state.events.size) }

        if (state.events.isEmpty()) {
            item(key = "empty") { EmptyLogPlaceholder() }
        } else {
            items(items = state.events, key = { it.id }) { logged ->
                EgressLogRow(event = logged.event)
            }
        }

        item(key = "footer") { LogFooter() }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Header — bioluminescent trident aura + wordmark + mode chip
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun PoseidonHeader(policy: PolicyInfo) {
    // Signature element: animated bioluminescent aura radiates from the trident.
    // A security tool should feel alive — this is the deep-ocean heartbeat.
    val infiniteTransition = rememberInfiniteTransition(label = "trident_aura")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue  = 0.22f,
        targetValue   = 0.54f,
        animationSpec = infiniteRepeatable(
            animation  = tween(durationMillis = 2800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "glow_alpha",
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(
                    colors = listOf(MarineBlue, AbyssalNavy),
                    startY = 0f,
                    endY   = 480f,
                )
            )
            .padding(horizontal = 24.dp, vertical = 36.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // Trident glyph inside its animated aura
        Box(
            contentAlignment = Alignment.Center,
            modifier         = Modifier.size(128.dp),
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                drawTridentAura(glowAlpha)
            }
            Text(
                text  = "🔱",   // 🔱  U+1F531 TRIDENT EMBLEM
                style = MaterialTheme.typography.displayLarge.copy(fontSize = 54.sp),
            )
        }

        Spacer(Modifier.height(14.dp))

        Text(
            text  = "POSEIDON",
            style = MaterialTheme.typography.displayLarge,
            color = TextPrimary,
        )

        Spacer(Modifier.height(6.dp))

        Text(
            text  = "Network egress gate for your SDKs",
            style = MaterialTheme.typography.bodyLarge,
            color = TextSecondary,
        )

        Spacer(Modifier.height(20.dp))

        ModeStatusChip(policy)
    }
}

/** Draws the deep-sea bioluminescent halo around the trident. */
private fun DrawScope.drawTridentAura(alpha: Float) {
    // Outer diffuse wash
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                BioluminescentTeal.copy(alpha = alpha * 0.30f),
                BioluminescentTeal.copy(alpha = alpha * 0.08f),
                Color.Transparent,
            ),
            center = center,
            radius = size.minDimension / 2f,
        ),
    )
    // Inner concentrated core glow
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                BioluminescentTeal.copy(alpha = alpha * 0.75f),
                Color.Transparent,
            ),
            center = center,
            radius = size.minDimension / 5f,
        ),
    )
}

@Composable
fun ModeStatusChip(policy: PolicyInfo) {
    val mode = Mode.current
    val (label, chipColor) = if (mode == Mode.ENFORCE) {
        "ENFORCE" to AquaAllow
    } else {
        "MONITOR" to TridentGold
    }

    Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment     = Alignment.CenterVertically,
    ) {
        // Mode badge
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = chipColor.copy(alpha = 0.15f),
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(chipColor)
                )
                Text(
                    text  = label,
                    style = MaterialTheme.typography.labelSmall,
                    color = chipColor,
                )
            }
        }

        Text(
            text  = "${policy.allowedHosts.size} host(s) · ${policy.deniedPaths.size} path(s) · ${policy.allowedCidrs.size} CIDRs",
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier cards
// ─────────────────────────────────────────────────────────────────────────────

private data class TierMeta(
    val tier: Tier,
    val label: String,
    val description: String,
)

private val TIER_META = listOf(
    TierMeta(
        tier        = Tier.JVM,
        label       = "JVM ADAPTERS",
        description = "OkHttp interceptor · HttpURLConnection rewrite · Volley gate · Cronet Java API",
    ),
    TierMeta(
        tier        = Tier.NATIVE,
        label       = "NATIVE LIBC",
        description = "ELF DT_NEEDED interposition via libposeidon_shim.so · covers NDK + Cronet native",
    ),
    TierMeta(
        tier        = Tier.SECCOMP,
        label       = "SECCOMP GO/RAW",
        description = "In-process USER_NOTIF supervisor · raw connect() / sendto() · DNS IP correlation",
    ),
)

@Composable
fun TiersSection(state: EgressDashboardState) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TIER_META.forEach { meta ->
            TierCard(
                meta  = meta,
                allow = state.allowCount(meta.tier),
                block = state.blockCount(meta.tier),
            )
        }
    }
}

@Composable
private fun TierCard(meta: TierMeta, allow: Int, block: Int) {
    Surface(
        shape          = RoundedCornerShape(10.dp),
        color          = DeepBlue,
        tonalElevation = 2.dp,
        modifier       = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min),
        ) {
            // Left teal accent stripe
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .fillMaxHeight()
                    .background(BioluminescentTeal.copy(alpha = 0.65f)),
            )

            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 14.dp, vertical = 10.dp),
            ) {
                Row(
                    modifier              = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment     = Alignment.CenterVertically,
                ) {
                    Text(
                        text  = meta.label,
                        style = MaterialTheme.typography.titleMedium,
                        color = BioluminescentTeal,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(
                            text  = "↑ $allow",
                            style = MaterialTheme.typography.labelSmall,
                            color = AquaAllow,
                        )
                        Text(
                            text  = "✕ $block",
                            style = MaterialTheme.typography.labelSmall,
                            color = CoralBlock,
                        )
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text     = meta.description,
                    style    = MaterialTheme.typography.bodyMedium,
                    color    = TextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live egress log
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun LiveLogHeader(eventCount: Int) {
    // Pulsing indicator — alive as long as the audit stream is running
    val infiniteTransition = rememberInfiniteTransition(label = "live_dot")
    val dotAlpha by infiniteTransition.animateFloat(
        initialValue  = 0.35f,
        targetValue   = 1.0f,
        animationSpec = infiniteRepeatable(
            animation  = tween(durationMillis = 850, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "dot_alpha",
    )

    Column {
        Row(
            modifier              = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment     = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(AquaAllow.copy(alpha = dotAlpha)),
                )
                Text(
                    text  = "LIVE EGRESS LOG",
                    style = MaterialTheme.typography.headlineMedium,
                    color = TextPrimary,
                )
            }
            if (eventCount > 0) {
                Text(
                    text  = "$eventCount",
                    style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary,
                )
            }
        }
        HorizontalDivider(color = MarineBlue, thickness = 1.dp)
    }
}

@Composable
fun EgressLogRow(event: EgressEvent) {
    val isBlock      = event.decision?.block == true
    val verdictColor = if (isBlock) CoralBlock else AquaAllow
    val verdict      = if (isBlock) "BLOCK" else "ALLOW"
    val tierLabel    = when (event.tier) {
        Tier.JVM     -> "JVM    "
        Tier.NATIVE  -> "NATIVE "
        Tier.SECCOMP -> "SECCOMP"
    }

    val host    = event.host ?: event.ip ?: "?"
    val path    = event.path.orEmpty()
    val display = if (path.isNotEmpty()) "$host$path" else host

    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min),
        ) {
            // Verdict colour stripe — the fastest visual signal in the log
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .fillMaxHeight()
                    .background(verdictColor.copy(alpha = 0.60f)),
            )

            Row(
                modifier              = Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp, vertical = 7.dp),
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text     = "[$tierLabel]",
                    style    = MaterialTheme.typography.bodySmall,
                    color    = BioluminescentTeal.copy(alpha = 0.65f),
                    modifier = Modifier.width(80.dp),
                )
                Text(
                    text     = display,
                    style    = MaterialTheme.typography.bodySmall,
                    color    = TextSecondary,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text  = verdict,
                    style = MaterialTheme.typography.labelSmall,
                    color = verdictColor,
                )
            }
        }
        HorizontalDivider(
            color     = MarineBlue.copy(alpha = 0.45f),
            thickness = 0.5.dp,
        )
    }
}

@Composable
fun EmptyLogPlaceholder() {
    Box(
        modifier         = Modifier
            .fillMaxWidth()
            .padding(vertical = 40.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text  = "Awaiting egress events…",
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary.copy(alpha = 0.55f),
        )
    }
}

@Composable
fun LogFooter() {
    Text(
        text     = "Decisions also stream to Logcat · tag: Poseidon",
        style    = MaterialTheme.typography.bodySmall,
        color    = TextSecondary.copy(alpha = 0.45f),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 20.dp),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy panel + interactive verifier
// ─────────────────────────────────────────────────────────────────────────────

/** A titled ocean-styled card used by the policy + verify panels. */
@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        shape          = RoundedCornerShape(10.dp),
        color          = DeepBlue,
        tonalElevation = 2.dp,
        modifier       = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp),
    ) {
        Column(
            modifier            = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = BioluminescentTeal)
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

/** Shows the compiled policy — exactly what the manifest is filtering. */
@Composable
fun PolicyCard(policy: PolicyInfo) {
    SectionCard(title = "WHAT WE'RE FILTERING") {
        val modeColor = if (policy.mode == "enforce") AquaAllow else TridentGold
        PolicyRow("Mode", policy.mode.uppercase(), modeColor)
        PolicyRow("Allowed hosts", policy.allowedHosts.joinToString("  ·  ").ifEmpty { "— (default-deny off)" }, BioluminescentTeal)
        PolicyRow("Denied paths", policy.deniedPaths.joinToString("  ·  ").ifEmpty { "—" }, CoralBlock)
        PolicyRow("Allowed CIDRs", policy.allowedCidrs.joinToString("  ·  ").ifEmpty { "—" }, TextSecondary)
        PolicyRow("DNS correlation", if (policy.dnsCorrelation) "on (Go/raw gated by host)" else "off", TextSecondary)
    }
}

@Composable
private fun PolicyRow(label: String, value: String, valueColor: Color) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.width(120.dp))
        Text(value, style = MaterialTheme.typography.bodySmall, color = valueColor, modifier = Modifier.weight(1f))
    }
}

/** Editable URL + a button per Android call style; fires the request live and shows the verdict. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun VerifyCard(verify: VerifyState) {
    val context = LocalContext.current
    SectionCard(title = "VERIFY A URL") {
        Text(
            "Type a URL and fire it through each client. Try an allowed host, a /blocked/* path, or a non-listed host.",
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value         = verify.url.value,
            onValueChange = { verify.url.value = it },
            singleLine    = true,
            label         = { Text("URL", color = TextSecondary) },
            modifier      = Modifier.fillMaxWidth(),
            colors        = OutlinedTextFieldDefaults.colors(
                focusedBorderColor   = BioluminescentTeal,
                unfocusedBorderColor  = MarineBlue,
                focusedTextColor      = TextPrimary,
                unfocusedTextColor    = TextPrimary,
                cursorColor           = BioluminescentTeal,
            ),
        )
        Spacer(Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ClientStyle.values().forEach { style ->
                Button(
                    onClick = { verify.run(style, context) },
                    shape   = RoundedCornerShape(8.dp),
                    colors  = ButtonDefaults.buttonColors(
                        containerColor = MarineBlue,
                        contentColor   = BioluminescentTeal,
                    ),
                ) {
                    Text(style.label, style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        if (verify.results.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MarineBlue, thickness = 0.5.dp)
            Spacer(Modifier.height(8.dp))
            verify.results.forEach { res ->
                val color = if (res.blocked) CoralBlock else AquaAllow
                Row(
                    modifier              = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(res.client, style = MaterialTheme.typography.labelSmall, color = BioluminescentTeal, modifier = Modifier.width(108.dp))
                    Text(
                        text     = res.outcome,
                        style    = MaterialTheme.typography.bodySmall,
                        color    = color,
                        modifier = Modifier.weight(1f),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Preview
// ─────────────────────────────────────────────────────────────────────────────

@Preview(showBackground = true, backgroundColor = 0xFF050D18, widthDp = 380, heightDp = 780)
@Composable
fun PoseidonDashboardPreview() {
    PoseidonTheme(darkTheme = true) {
        PoseidonDashboard(
            state  = EgressDashboardState(),
            verify = VerifyState(),
            policy = PolicyInfo(
                mode = "enforce",
                allowedHosts = listOf("example.com"),
                deniedPaths = listOf("/blocked/*"),
                allowedCidrs = listOf("104.16.0.0/13", "172.64.0.0/13"),
                dnsCorrelation = true,
            ),
        )
    }
}
