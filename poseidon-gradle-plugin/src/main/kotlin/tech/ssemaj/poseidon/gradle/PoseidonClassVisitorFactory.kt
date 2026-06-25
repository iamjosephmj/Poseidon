package tech.ssemaj.poseidon.gradle

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

private const val RUNTIME = "tech/ssemaj/poseidon/runtime"

/** Inject `Poseidon…(localVar)` at the top of a specific library method. */
private data class EntryRule(
    val className: String,      // dotted, e.g. okhttp3.OkHttpClient$Builder
    val method: String,
    val descriptor: String,
    val loadVar: Int,           // local to pass: 0 = this, 1 = first arg, …
    val ownerInternal: String,  // where the static lives
    val staticName: String,
    val staticDesc: String,
)

/** Rewrite a call site `owner.name desc` (a platform/library call) to a Poseidon static. */
private data class CallSiteRule(
    val owner: String, val name: String, val desc: String,
    val toOwner: String, val toName: String, val toDesc: String,
)

// === Adapter registry — add HTTP clients here ===
private val ENTRY_RULES = listOf(
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
private val CALL_SITE_RULES = listOf(
    // HttpURLConnection (covers raw HUC, Volley HurlStack, Ktor-Android engine).
    CallSiteRule("java/net/URL", "openConnection", "()Ljava/net/URLConnection;",
        "$RUNTIME/PoseidonHttpUrl", "open", "(Ljava/net/URL;)Ljava/net/URLConnection;"),
    CallSiteRule("java/net/URL", "openConnection", "(Ljava/net/Proxy;)Ljava/net/URLConnection;",
        "$RUNTIME/PoseidonHttpUrl", "open", "(Ljava/net/URL;Ljava/net/Proxy;)Ljava/net/URLConnection;"),
    CallSiteRule("java/net/URL", "openStream", "()Ljava/io/InputStream;",
        "$RUNTIME/PoseidonHttpUrl", "openStream", "(Ljava/net/URL;)Ljava/io/InputStream;"),
    // Cronet: PATH visibility at its Java API (host BLOCK is enforced by the native shim).
    CallSiteRule(
        "org/chromium/net/CronetEngine", "newUrlRequestBuilder",
        "(Ljava/lang/String;Lorg/chromium/net/UrlRequest\$Callback;Ljava/util/concurrent/Executor;)Lorg/chromium/net/UrlRequest\$Builder;",
        "$RUNTIME/PoseidonCronet", "newUrlRequestBuilder",
        "(Lorg/chromium/net/CronetEngine;Ljava/lang/String;Lorg/chromium/net/UrlRequest\$Callback;Ljava/util/concurrent/Executor;)Lorg/chromium/net/UrlRequest\$Builder;",
    ),
)

abstract class PoseidonClassVisitorFactory :
    AsmClassVisitorFactory<InstrumentationParameters.None> {

    // Instrument everything except our own runtime (avoids rewriting our own
    // URL.openConnection calls into recursion).
    override fun isInstrumentable(classData: ClassData): Boolean =
        !classData.className.startsWith("tech.ssemaj.poseidon.runtime")

    override fun createClassVisitor(
        classContext: ClassContext,
        nextClassVisitor: ClassVisitor,
    ): ClassVisitor = PoseidonClassVisitor(
        instrumentationContext.apiVersion.get(),
        classContext.currentClassData.className,
        nextClassVisitor,
    )
}

private class PoseidonClassVisitor(
    private val api: Int,
    private val className: String,
    cv: ClassVisitor,
) : ClassVisitor(api, cv) {
    override fun visitMethod(
        access: Int, name: String?, descriptor: String?,
        signature: String?, exceptions: Array<out String>?,
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        val entry = ENTRY_RULES.firstOrNull {
            it.className == className && it.method == name && it.descriptor == descriptor
        }
        return if (entry != null) {
            object : MethodVisitor(api, CallSiteRewriter(api, mv)) {
                override fun visitCode() {
                    super.visitCode()
                    visitVarInsn(Opcodes.ALOAD, entry.loadVar) // this / arg
                    visitMethodInsn(
                        Opcodes.INVOKESTATIC, entry.ownerInternal, entry.staticName, entry.staticDesc, false,
                    )
                }
            }
        } else {
            CallSiteRewriter(api, mv)
        }
    }
}

/** Rewrites known network call sites to Poseidon statics (stack-compatible). */
private class CallSiteRewriter(api: Int, mv: MethodVisitor) : MethodVisitor(api, mv) {
    override fun visitMethodInsn(
        opcode: Int, owner: String?, name: String?, descriptor: String?, isInterface: Boolean,
    ) {
        val rule = CALL_SITE_RULES.firstOrNull {
            it.owner == owner && it.name == name && it.desc == descriptor
        }
        if (rule != null) {
            super.visitMethodInsn(Opcodes.INVOKESTATIC, rule.toOwner, rule.toName, rule.toDesc, false)
        } else {
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
        }
    }
}
