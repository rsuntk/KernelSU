package me.weishu.kernelsu.ui.component

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cottage
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.hazeEffect
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ui.LocalHandlePageChange
import me.weishu.kernelsu.ui.LocalSelectedPage
import me.weishu.kernelsu.ui.util.rootAvailable
import top.yukonga.miuix.kmp.basic.NavigationBar
import top.yukonga.miuix.kmp.basic.NavigationItem
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun BottomBar(
    hazeState: HazeState,
    hazeStyle: HazeStyle
) {
    val isManager = Natives.isManager
    val fullFeatured = isManager && !Natives.requireNewKernel() && rootAvailable()

    val page = LocalSelectedPage.current
    val handlePageChange = LocalHandlePageChange.current
    val blurEnabled = me.weishu.kernelsu.ui.util.LocalBlurEnabled.current

    if (!fullFeatured) return

    val item = BottomBarDestination.entries.map { destination ->
        NavigationItem(
            label = stringResource(destination.label),
            icon = destination.icon,
        )
    }

    NavigationBar(
        modifier = if (blurEnabled) {
            Modifier.hazeEffect(hazeState) {
                style = hazeStyle
                blurRadius = me.weishu.kernelsu.ui.util.blurRadius(blurEnabled)
                noiseFactor = 0f
            }
        } else {
            Modifier
        },
        color = if (blurEnabled) Color.Transparent else MiuixTheme.colorScheme.surface,
        items = item,
        selected = page,
        onClick = handlePageChange
    )
}

enum class BottomBarDestination(
    @get:StringRes val label: Int,
    val icon: ImageVector,
) {
    Home(R.string.home, Icons.Rounded.Cottage),
    SuperUser(R.string.superuser, Icons.Rounded.Security),
    Module(R.string.module, Icons.Rounded.Extension),
    Setting(R.string.settings, Icons.Rounded.Settings)
}
