package tech.ssemaj.poseidon.runtime

import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody

/** Path deny-list enforcement at OkHttp's plaintext layer (above TLS). */
class PoseidonInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val req = chain.request()
        val url = req.url
        if (PoseidonGate.shouldBlock(url.host, url.encodedPath)) {
            return Response.Builder()
                .request(req)
                .protocol(Protocol.HTTP_1_1)
                .code(403)
                .message("Blocked by Poseidon")
                .body("".toResponseBody(null))
                .build()
        }
        return chain.proceed(req)
    }
}
