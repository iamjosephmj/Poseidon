package tech.ssemaj.poseidon.gradle.transform

/** Internal path to the runtime package (slash-separated, as used in bytecode). */
internal const val RUNTIME = "tech/ssemaj/poseidon/runtime"

/** Inject `Poseidon…(localVar)` at the top of a specific library method. */
internal data class EntryRule(
    val className: String,      // dotted, e.g. okhttp3.OkHttpClient$Builder
    val method: String,
    val descriptor: String,
    val loadVar: Int,           // local to pass: 0 = this, 1 = first arg, …
    val ownerInternal: String,  // where the static lives
    val staticName: String,
    val staticDesc: String,
)

/** Rewrite a call site `owner.name desc` (a platform/library call) to a Poseidon static. */
internal data class CallSiteRule(
    val owner: String, val name: String, val desc: String,
    val toOwner: String, val toName: String, val toDesc: String,
)

// === Adapter registry — add HTTP clients here ===
internal val ENTRY_RULES = listOf(
    // OkHttp (covers Retrofit, Ktor-OkHttp engine): add interceptor at Builder.build().
    EntryRule(
        "okhttp3.OkHttpClient\$Builder", "build", "()Lokhttp3/OkHttpClient;", 0,
        "$RUNTIME/PoseidonOkHttp", "install", "(Lokhttp3/OkHttpClient\$Builder;)V",
    ),
    // Volley: gate (and cancel if denied) at RequestQueue.add(Request) — pass the request (arg 1).
    EntryRule(
        "com.android.volley.RequestQueue", "add",
        "(Lcom/android/volley/Request;)Lcom/android/volley/Request;", 1,
        "$RUNTIME/PoseidonVolley", "onAdd", "(Lcom/android/volley/Request;)V",
    ),
)

internal val CALL_SITE_RULES = listOf(
    // HttpURLConnection (covers raw HUC, Volley HurlStack, Ktor-Android engine).
    CallSiteRule(
        "java/net/URL", "openConnection", "()Ljava/net/URLConnection;",
        "$RUNTIME/PoseidonHttpUrl", "open", "(Ljava/net/URL;)Ljava/net/URLConnection;",
    ),
    CallSiteRule(
        "java/net/URL", "openConnection", "(Ljava/net/Proxy;)Ljava/net/URLConnection;",
        "$RUNTIME/PoseidonHttpUrl", "open", "(Ljava/net/URL;Ljava/net/Proxy;)Ljava/net/URLConnection;",
    ),
    CallSiteRule(
        "java/net/URL", "openStream", "()Ljava/io/InputStream;",
        "$RUNTIME/PoseidonHttpUrl", "openStream", "(Ljava/net/URL;)Ljava/io/InputStream;",
    ),
    // Cronet: PATH visibility at its Java API (host BLOCK is enforced by the native shim).
    CallSiteRule(
        "org/chromium/net/CronetEngine", "newUrlRequestBuilder",
        "(Ljava/lang/String;Lorg/chromium/net/UrlRequest\$Callback;Ljava/util/concurrent/Executor;)Lorg/chromium/net/UrlRequest\$Builder;",
        "$RUNTIME/PoseidonCronet", "newUrlRequestBuilder",
        "(Lorg/chromium/net/CronetEngine;Ljava/lang/String;Lorg/chromium/net/UrlRequest\$Callback;Ljava/util/concurrent/Executor;)Lorg/chromium/net/UrlRequest\$Builder;",
    ),
)
