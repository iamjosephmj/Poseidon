package tech.ssemaj.poseidon.runtime

import okhttp3.OkHttpClient

/**
 * Called from `OkHttpClient.Builder.build()` by the bytecode the Gradle plugin injects.
 * Idempotent: newBuilder() copies our interceptor into the new builder.
 */
object PoseidonOkHttp {
    @JvmStatic
    fun install(builder: OkHttpClient.Builder) {
        if (builder.interceptors().any { it is PoseidonInterceptor }) return
        builder.addInterceptor(PoseidonInterceptor())
    }
}
