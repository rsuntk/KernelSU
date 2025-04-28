package me.weishu.kernelsu.ui.component

import androidx.compose.runtime.Composable
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.ksuApp

@Composable
fun KsuIsValid(
    content: @Composable () -> Unit
) {
    if (val ksuIsValid = Natives.isKsuValid(ksuApp.packageName)) {
        content()
    }
}