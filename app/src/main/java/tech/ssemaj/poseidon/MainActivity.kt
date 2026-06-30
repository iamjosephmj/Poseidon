package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import tech.ssemaj.poseidon.control.PoseidonViewModel
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.ui.PoseidonApp
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme

class MainActivity : ComponentActivity() {
    private val vm: PoseidonViewModel by viewModels { PoseidonViewModel.Factory }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { PoseidonTheme { PoseidonApp(vm) } }
        // Fire the probe suite once on launch so the dashboard has live data.
        DemoProbes.runAll(applicationContext)
    }
}
