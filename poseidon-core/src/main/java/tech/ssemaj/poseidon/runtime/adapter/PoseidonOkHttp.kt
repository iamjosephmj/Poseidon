@file:OptIn(InternalPoseidonApi::class)

package tech.ssemaj.poseidon.runtime.adapter

import tech.ssemaj.poseidon.runtime.internal.InternalPoseidonApi

import okhttp3.OkHttpClient

/**
 * Pattern: **Adapter** — bridges OkHttp to the Poseidon gate by installing
 * [PoseidonInterceptor]. Called from `OkHttpClient.Builder.build()` by the bytecode the
 * Gradle plugin injects. Idempotent: newBuilder() copies our interceptor into the new builder.
 */
@InternalPoseidonApi
object PoseidonOkHttp {
    @JvmStatic
    fun install(builder: OkHttpClient.Builder) {
        if (builder.interceptors().any { it is PoseidonInterceptor }) return
        builder.addInterceptor(PoseidonInterceptor())
    }
}
