package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import tech.ssemaj.poseidon.control.PoseidonViewModel
import tech.ssemaj.poseidon.ui.PoseidonApp
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme

class MainActivity : ComponentActivity() {
    private val vm: PoseidonViewModel by viewModels { PoseidonViewModel.Factory }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { PoseidonTheme { PoseidonApp(vm) } }
        // Force ViewModel creation now so its sink is registered before probes fire.
        vm.runAllProbes()
    }
}
