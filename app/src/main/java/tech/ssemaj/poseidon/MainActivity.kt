package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PoseidonTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    ProbeTierScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
        // Fire all demo probes after the UI is set up.
        DemoProbes.runAll(applicationContext)
    }
}

/**
 * Displays the three Poseidon interception tiers that the demo probes exercise.
 * Logcat tag "PoseidonDemo" shows live results for each probe.
 */
@Composable
fun ProbeTierScreen(modifier: Modifier = Modifier) {
    Column(modifier = modifier.padding(16.dp)) {
        Text(
            text = "Poseidon Demo",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "Tier 1 — JVM adapters",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "OkHttp interceptor · HttpURLConnection call-site rewrite · " +
                "Volley RequestQueue gate · Cronet Java API",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tier 2 — native libc shim",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "ELF DT_NEEDED interposition via libposeidon_shim.so · " +
                "covers Cronet native stack + any NDK HTTP client",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tier 3 — seccomp Go-raw gate",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "In-process seccomp USER_NOTIF supervisor · catches raw connect() / " +
                "sendto() syscalls that bypass libc (Go runtime, raw-syscall callers) · " +
                "DNS correlation maps IPs back to hostnames for policy enforcement",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "See Logcat tag: PoseidonDemo",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline,
        )
    }
}

@Preview(showBackground = true)
@Composable
fun ProbeTierScreenPreview() {
    PoseidonTheme {
        ProbeTierScreen()
    }
}
