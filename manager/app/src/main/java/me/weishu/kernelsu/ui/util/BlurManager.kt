package me.weishu.kernelsu.ui.util

import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

val LocalBlurEnabled = compositionLocalOf { true }

fun blurRadius(enabled: Boolean): Dp {
    return if (enabled) 30.dp else 0.dp
}
