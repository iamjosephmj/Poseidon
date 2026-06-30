package tech.ssemaj.poseidon.control

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import tech.ssemaj.poseidon.PolicyInfo
import tech.ssemaj.poseidon.probes.DemoProbes
import tech.ssemaj.poseidon.runtime.model.EgressEvent
import tech.ssemaj.poseidon.runtime.model.Mode
import tech.ssemaj.poseidon.runtime.pipeline.Observer

class PoseidonViewModel(app: Application) : AndroidViewModel(app) {

    private val policy = PolicyInfo.load(app)
    private val controller = PoseidonController(
        initialMode = if (policy.mode == "enforce") Mode.ENFORCE else Mode.MONITOR,
        gate = RuntimeEnforcementGate(policy.allowedHosts),
    )

    val state: StateFlow<UiState> = controller.state

    private val sink: (EgressEvent) -> Unit = { controller.onEvent(it) }

    init { Observer.addSink(sink) }

    fun toggleMode() = controller.toggleMode()

    fun runAllProbes() {
        viewModelScope.launch(Dispatchers.IO) {
            DemoProbes.runAll(getApplication())
        }
    }

    fun policySnapshot(): PolicyInfo = policy

    override fun onCleared() {
        super.onCleared()
        Observer.removeSink(sink)
    }

    companion object {
        val Factory: ViewModelProvider.Factory = viewModelFactory {
            initializer { PoseidonViewModel(this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]!!) }
        }
    }
}
