package tech.ssemaj.poseidon

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import tech.ssemaj.poseidon.ui.theme.PoseidonTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RawSyscallProbe.run()          // Go-class raw-syscall connect (seccomp gate)
        RawDnsProbe.run()              // raw DNS -> in-process correlation -> host on raw connect
        OkHttpProbe.run()              // OkHttp adapter (bytecode)
        HttpUrlProbe.run()             // HttpURLConnection adapter (call-site rewrite)
        VolleyProbe.run(applicationContext) // Volley adapter (RequestQueue.add)
        CronetProbe.run(applicationContext) // native host + Cronet Java-API path observe
        enableEdgeToEdge()
        setContent {
            PoseidonTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    PoseidonTheme {
        Greeting("Android")
    }
}