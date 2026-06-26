package tech.ssemaj.poseidon.gradle.transform

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

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
