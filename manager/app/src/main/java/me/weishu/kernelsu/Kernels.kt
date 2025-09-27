package me.weishu.kernelsu

import android.system.Os
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.ui.component.KsuGetVersion

/**
 * @author weishu
 * @date 2022/12/10.
 */

data class KernelVersion(val major: Int, val patchLevel: Int, val subLevel: Int) {
    override fun toString(): String {
        return "$major.$patchLevel.$subLevel"
    }

    fun isGKI(): Boolean {
        // kernel driver-based detection
        val ksuVersion: Int? = KsuGetVersion()
        if (ksuVersion ?: 0 >= 12272) {
            return Natives.isRealGKI
        }

        // kernel 6.x
        if (major > 5) {
            return true
        }

        // kernel 5.10.x
        if (major == 5) {
            return patchLevel >= 10
        }

        return false
    }
}

fun parseKernelVersion(version: String): KernelVersion {
    val find = "(\\d+)\\.(\\d+)\\.(\\d+)".toRegex().find(version)
    return if (find != null) {
        KernelVersion(find.groupValues[1].toInt(), find.groupValues[2].toInt(), find.groupValues[3].toInt())
    } else {
        KernelVersion(-1, -1, -1)
    }
}

fun getKernelVersion(): KernelVersion {
    Os.uname().release.let {
        return parseKernelVersion(it)
    }
}
