package tech.ssemaj.poseidon.gradle.elf

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-JVM ELF DT_NEEDED injector (ELF32/64, little-endian — all Android ABIs).
 *
 * Adds a DT_NEEDED entry by appending ONE new PT_LOAD segment at end-of-file that
 * holds: a relocated program-header table (old phdrs + the new PT_LOAD, with
 * PT_PHDR/PT_DYNAMIC repointed), a copied+extended .dynstr (old bytes kept so every
 * existing offset stays valid, soname appended), and a relocated .dynamic (old
 * entries + our DT_NEEDED placed FIRST so the shim wins symbol resolution). The ELF
 * header's e_phoff/e_phnum are updated to the relocated phdr table. Section headers
 * for .dynamic/.dynstr are also repointed so tooling agrees with the loader.
 *
 * No external dependencies (replaces the LIEF/python interim).
 */
object ElfDtNeededInjector {

    /** @return true if injected, false if already present. Throws on malformed/unsupported ELF. */
    fun inject(file: File, soname: String): Boolean {
        val bytes = file.readBytes()
        validateElf(bytes, file)
        val image = readHeaders(file, bytes)
        if (alreadyNeeded(image, soname)) return false
        val regionData = buildAppendedRegion(image, soname)
        patchHeaderAndSections(image, regionData)
        writeOut(file, image.b, regionData)
        return true
    }

    // ---- Phase 1: validate + parse ----

    private fun validateElf(b: ByteArray, file: File) {
        require(
            b.size > ElfIdent.MIN_SIZE &&
                b[ElfIdent.MAG0_OFF].toInt() == ElfIdent.MAG0 &&
                b[ElfIdent.MAG1_OFF].toInt() == ElfIdent.MAG1 &&
                b[ElfIdent.MAG2_OFF].toInt() == ElfIdent.MAG2 &&
                b[ElfIdent.MAG3_OFF].toInt() == ElfIdent.MAG3
        ) { "not an ELF: ${file.name}" }
        require(b[ElfIdent.DATA_OFF].toInt() == ElfIdent.DATA_LSB) {
            "big-endian ELF unsupported: ${file.name}"
        }
    }

    private fun readHeaders(file: File, bytes: ByteArray): ElfImage = ElfImage(file, bytes)

    // ---- Phase 2: idempotency check (part of readDynamic semantics) ----

    private fun alreadyNeeded(image: ElfImage, soname: String): Boolean =
        image.dyns.any { d -> d.tag == DT_NEEDED && image.cstr(image.oldStrtab, d.v.toInt()) == soname }

    // ---- Phase 3: build the appended region (phdr table + dynstr + .dynamic) ----

    private data class RegionData(
        val region: ByteArray,
        val regionOff: Long,
        val regionVaddr: Long,
        val newPhNum: Int,
        val offPhdr: Long,
        val offDyn: Long,
        val offDynstr: Long,
        val newDynSize: Long,
        val newStrtabSize: Int,
        val origStrtabVaddr: Long,
    )

    private fun buildAppendedRegion(image: ElfImage, soname: String): RegionData {
        val align = (image.loads.maxOf { it.align }.takeIf { it > 1 } ?: DEFAULT_PAGE_ALIGN)
        fun up(x: Long, a: Long) = (x + a - 1) / a * a
        val regionOff   = up(image.b.size.toLong(), align)
        val maxVEnd     = image.loads.maxOf { it.vaddr + it.memsz }
        val regionVaddr = up(maxVEnd, align)

        val newPhNum     = image.phNum + 1
        val phTableSize  = newPhNum.toLong() * image.phEntSize
        val offPhdr      = 0L
        val offDynstr    = up(phTableSize, 8)
        val sonameBytes  = soname.toByteArray(Charsets.US_ASCII)
        val newStrtab    = image.oldStrtab + sonameBytes + byteArrayOf(0)
        val newStrOffset = image.oldStrtab.size.toLong()
        val offDyn       = up(offDynstr + newStrtab.size, 8)

        // new .dynamic: our DT_NEEDED first, old entries (sans DT_NULL, strtab updated), DT_NULL
        val newDyns = buildList {
            add(ElfImage.Dyn(DT_NEEDED, newStrOffset))
            for (d in image.dyns) {
                if (d.tag == DT_NULL) continue
                add(when (d.tag) {
                    DT_STRTAB -> ElfImage.Dyn(DT_STRTAB, regionVaddr + offDynstr)
                    DT_STRSZ  -> ElfImage.Dyn(DT_STRSZ, newStrtab.size.toLong())
                    else      -> d
                })
            }
            add(ElfImage.Dyn(DT_NULL, 0))
        }
        val newDynSize  = newDyns.size.toLong() * image.dynEntSize
        val regionSize  = offDyn + newDynSize

        val region = ByteArray(regionSize.toInt())
        val rb     = ByteBuffer.wrap(region).order(ByteOrder.LITTLE_ENDIAN)

        // phdr table: copy originals (PT_PHDR/PT_DYNAMIC repointed), then new PT_LOAD
        val updatedPhs = image.phs.map { p ->
            when (p.type) {
                PT_PHDR    -> p.copy(
                    off = regionOff + offPhdr, vaddr = regionVaddr + offPhdr,
                    paddr = regionVaddr + offPhdr, filesz = phTableSize, memsz = phTableSize,
                )
                PT_DYNAMIC -> p.copy(
                    off = regionOff + offDyn, vaddr = regionVaddr + offDyn,
                    paddr = regionVaddr + offDyn, filesz = newDynSize, memsz = newDynSize,
                )
                else       -> p
            }
        }.toMutableList()
        updatedPhs.add(
            ElfImage.Ph(
                newPhNum - 1, PT_LOAD, PF_R.toLong(), regionOff, regionVaddr,
                regionVaddr, regionSize, regionSize, align,
            )
        )

        updatedPhs.forEachIndexed { i, p ->
            val o = (offPhdr + i.toLong() * image.phEntSize).toInt()
            if (image.is64) {
                rb.putInt(o + ElfPhdrOff.TYPE_64,   p.type)
                rb.putInt(o + ElfPhdrOff.FLAGS_64,  p.flags.toInt())
                rb.putLong(o + ElfPhdrOff.OFFSET_64, p.off)
                rb.putLong(o + ElfPhdrOff.VADDR_64,  p.vaddr)
                rb.putLong(o + ElfPhdrOff.PADDR_64,  p.paddr)
                rb.putLong(o + ElfPhdrOff.FILESZ_64, p.filesz)
                rb.putLong(o + ElfPhdrOff.MEMSZ_64,  p.memsz)
                rb.putLong(o + ElfPhdrOff.ALIGN_64,  p.align)
            } else {
                rb.putInt(o + ElfPhdrOff.TYPE_32,   p.type)
                rb.putInt(o + ElfPhdrOff.OFFSET_32, p.off.toInt())
                rb.putInt(o + ElfPhdrOff.VADDR_32,  p.vaddr.toInt())
                rb.putInt(o + ElfPhdrOff.PADDR_32,  p.paddr.toInt())
                rb.putInt(o + ElfPhdrOff.FILESZ_32, p.filesz.toInt())
                rb.putInt(o + ElfPhdrOff.MEMSZ_32,  p.memsz.toInt())
                rb.putInt(o + ElfPhdrOff.FLAGS_32,  p.flags.toInt())
                rb.putInt(o + ElfPhdrOff.ALIGN_32,  p.align.toInt())
            }
        }

        // dynstr
        System.arraycopy(newStrtab, 0, region, offDynstr.toInt(), newStrtab.size)
        // dynamic
        val dValOff64 = ElfDynEnt.D_VAL_64
        val dValOff32 = ElfDynEnt.D_VAL_32
        newDyns.forEachIndexed { i, d ->
            val o = (offDyn + i.toLong() * image.dynEntSize).toInt()
            if (image.is64) { rb.putLong(o, d.tag); rb.putLong(o + dValOff64, d.v) }
            else { rb.putInt(o, d.tag.toInt()); rb.putInt(o + dValOff32, d.v.toInt()) }
        }

        return RegionData(
            region = region, regionOff = regionOff, regionVaddr = regionVaddr,
            newPhNum = newPhNum, offPhdr = offPhdr, offDyn = offDyn, offDynstr = offDynstr,
            newDynSize = newDynSize, newStrtabSize = newStrtab.size,
            origStrtabVaddr = image.strtabVaddr,
        )
    }

    // ---- Phase 4: patch ELF header + section headers in the in-memory buffer ----

    private fun patchHeaderAndSections(image: ElfImage, data: RegionData) {
        val bb   = image.bb
        val is64 = image.is64

        // Update e_phoff (program-header table offset) and e_phnum.
        if (is64) bb.putLong(ElfHeaderOff.E_PHOFF_64, data.regionOff + data.offPhdr)
        else       bb.putInt(ElfHeaderOff.E_PHOFF_32, (data.regionOff + data.offPhdr).toInt())
        bb.putShort(image.phnumOff, data.newPhNum.toShort())

        // Repoint .dynamic / .dynstr section headers so tooling agrees with the loader.
        if (image.eShoff != 0L && image.shNum > 0) {
            for (i in 0 until image.shNum) {
                val so     = (image.eShoff + i.toLong() * image.shEntSize).toInt()
                val shType = bb.getInt(so + ElfShdrOff.SH_TYPE)
                when (shType) {
                    SHT_DYNAMIC -> if (is64) {
                        bb.putLong(so + ElfShdrOff.SH_ADDR_64,   data.regionVaddr + data.offDyn)
                        bb.putLong(so + ElfShdrOff.SH_OFFSET_64, data.regionOff   + data.offDyn)
                        bb.putLong(so + ElfShdrOff.SH_SIZE_64,   data.newDynSize)
                    } else {
                        bb.putInt(so + ElfShdrOff.SH_ADDR_32,   (data.regionVaddr + data.offDyn).toInt())
                        bb.putInt(so + ElfShdrOff.SH_OFFSET_32, (data.regionOff   + data.offDyn).toInt())
                        bb.putInt(so + ElfShdrOff.SH_SIZE_32,   data.newDynSize.toInt())
                    }
                    SHT_STRTAB -> {
                        val shAddr = if (is64) bb.getLong(so + ElfShdrOff.SH_ADDR_64)
                                     else      bb.getULong(so + ElfShdrOff.SH_ADDR_32)
                        if (shAddr == data.origStrtabVaddr) {
                            if (is64) {
                                bb.putLong(so + ElfShdrOff.SH_ADDR_64,   data.regionVaddr + data.offDynstr)
                                bb.putLong(so + ElfShdrOff.SH_OFFSET_64, data.regionOff   + data.offDynstr)
                                bb.putLong(so + ElfShdrOff.SH_SIZE_64,   data.newStrtabSize.toLong())
                            } else {
                                bb.putInt(so + ElfShdrOff.SH_ADDR_32,   (data.regionVaddr + data.offDynstr).toInt())
                                bb.putInt(so + ElfShdrOff.SH_OFFSET_32, (data.regionOff   + data.offDynstr).toInt())
                                bb.putInt(so + ElfShdrOff.SH_SIZE_32,   data.newStrtabSize)
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- Phase 5: assemble and write: original (padded to regionOff) + appended region ----

    private fun writeOut(file: File, b: ByteArray, data: RegionData) {
        file.outputStream().buffered().use { out ->
            out.write(b)
            repeat((data.regionOff - b.size).toInt()) { out.write(0) }
            out.write(data.region)
        }
    }
}
