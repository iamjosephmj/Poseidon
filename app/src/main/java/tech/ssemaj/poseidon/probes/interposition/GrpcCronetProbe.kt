package tech.ssemaj.poseidon.probes.interposition

import android.content.Context
import android.util.Log
import io.grpc.CallOptions
import io.grpc.ManagedChannel
import io.grpc.MethodDescriptor
import io.grpc.StatusRuntimeException
import io.grpc.cronet.CronetChannelBuilder
import io.grpc.stub.ClientCalls
import org.chromium.net.CronetEngine
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Tier: native libc shim (ELF DT_NEEDED interposition).
 *
 * Drives gRPC over Cronet's NATIVE transport (`libcronet`).  The RPC's bytes leave the
 * process through Cronet's native socket stack, so `connect()` is issued from native
 * code — only Poseidon's `libposeidon_shim.so` (or the seccomp gate) can stop it, NOT
 * the JVM bytecode adapters (gRPC has no JVM-tier adapter here).
 *
 * [DENIED_HOST] is NOT in the allow-list, so Poseidon refuses the native connect and the
 * RPC fails fast with `Status UNAVAILABLE`.  This is cleanly distinguishable from a
 * normal failure: with Poseidon OFF the connect + TLS succeed and the (bogus) method
 * comes back `UNIMPLEMENTED` from the server; `UNAVAILABLE` means the native tier blocked
 * egress before a single byte left the device.
 */
object GrpcCronetProbe {
    private const val TAG = "PoseidonDemo"

    /** A real public gRPC endpoint, deliberately NOT allow-listed -> expect a native block. */
    private const val DENIED_HOST = "grpc.googleapis.com"
    private const val PORT = 443

    /** No-proto passthrough marshaller so we can issue an RPC without generated stubs. */
    private val passthrough = object : MethodDescriptor.Marshaller<ByteArray> {
        override fun stream(value: ByteArray): InputStream = ByteArrayInputStream(value)
        override fun parse(stream: InputStream): ByteArray = stream.readBytes()
    }

    fun run(ctx: Context) {
        Executors.newSingleThreadExecutor().execute {
            val engine = CronetEngine.Builder(ctx).build()
            val channel: ManagedChannel =
                CronetChannelBuilder.forAddress(DENIED_HOST, PORT, engine).build()
            val method = MethodDescriptor.newBuilder<ByteArray, ByteArray>()
                .setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName("poseidon.Probe/Echo")
                .setRequestMarshaller(passthrough)
                .setResponseMarshaller(passthrough)
                .build()
            try {
                ClientCalls.blockingUnaryCall(channel, method, CallOptions.DEFAULT, ByteArray(0))
                Log.i(TAG, "grpc(native/cronet) $DENIED_HOST -> UNEXPECTED success (NOT blocked)")
            } catch (e: StatusRuntimeException) {
                Log.i(
                    TAG,
                    "grpc(native/cronet) $DENIED_HOST -> ${e.status.code} " +
                        "(UNAVAILABLE=blocked by Poseidon native shim)",
                )
            } finally {
                channel.shutdownNow()
                channel.awaitTermination(2, TimeUnit.SECONDS)
            }
        }
    }
}
