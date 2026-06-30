package tech.ssemaj.poseidon

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.grpc.CallOptions
import io.grpc.MethodDescriptor
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.grpc.cronet.CronetChannelBuilder
import io.grpc.stub.ClientCalls
import org.chromium.net.CronetEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit

/**
 * Verifies Poseidon blocks egress from a real networking SDK whose packets are emitted
 * by NATIVE code: gRPC running over Cronet's native transport.
 *
 * `grpc.googleapis.com` is not in the app allow-list, so the native `connect()` is
 * refused by `libposeidon_shim.so` and the RPC fails with `Status UNAVAILABLE` — before
 * any byte leaves the device.  (With enforcement off, the call would instead reach the
 * server and return `UNIMPLEMENTED` for the bogus method, so `UNAVAILABLE` specifically
 * proves the native-tier block.)
 *
 * Run: ./gradlew :app:connectedDebugAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=tech.ssemaj.poseidon.GrpcCronetBlockTest
 */
@RunWith(AndroidJUnit4::class)
class GrpcCronetBlockTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private val passthrough = object : MethodDescriptor.Marshaller<ByteArray> {
        override fun stream(value: ByteArray): InputStream = ByteArrayInputStream(value)
        override fun parse(stream: InputStream): ByteArray = stream.readBytes()
    }

    @Test
    fun grpcOverCronetNativeEgressIsBlocked() {
        val engine = CronetEngine.Builder(context).build()
        val channel = CronetChannelBuilder.forAddress("grpc.googleapis.com", 443, engine).build()
        val method = MethodDescriptor.newBuilder<ByteArray, ByteArray>()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName("poseidon.Probe/Echo")
            .setRequestMarshaller(passthrough)
            .setResponseMarshaller(passthrough)
            .build()
        try {
            val ex = assertThrows(StatusRuntimeException::class.java) {
                ClientCalls.blockingUnaryCall(channel, method, CallOptions.DEFAULT, ByteArray(0))
            }
            assertEquals(
                "Expected Poseidon to refuse the native connect (UNAVAILABLE)",
                Status.Code.UNAVAILABLE,
                ex.status.code,
            )
        } finally {
            channel.shutdownNow()
            channel.awaitTermination(2, TimeUnit.SECONDS)
        }
    }
}
