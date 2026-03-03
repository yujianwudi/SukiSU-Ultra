package com.sukisu.ultra.ui.component.profile

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveColumn
import com.sukisu.ultra.ui.component.material.ExpressiveSwitchItem
import com.sukisu.ultra.ui.component.material.ExpressiveTextField

@Composable
fun AppProfileConfigMaterial(
    modifier: Modifier = Modifier,
    fixedName: Boolean,
    enabled: Boolean,
    profile: Natives.Profile,
    onProfileChange: (Natives.Profile) -> Unit,
) {
    Column(modifier = modifier) {
        if (!fixedName) {
            ExpressiveColumn(
                modifier = Modifier.padding(horizontal = 16.dp),
                content = listOf {
                    ExpressiveTextField(
                        value = profile.name,
                        onValueChange = { onProfileChange(profile.copy(name = it)) },
                        label = stringResource(R.string.profile_name),
                        readOnly = !enabled,
                        singleLine = true
                    )
                }
            )
        }

        ExpressiveColumn(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            content = listOf {
                ExpressiveSwitchItem(
                    title = stringResource(R.string.profile_umount_modules),
                    summary = stringResource(R.string.profile_umount_modules_summary),
                    checked = if (enabled) {
                        profile.umountModules
                    } else {
                        Natives.isDefaultUmountModules()
                    },
                    enabled = enabled,
                    onCheckedChange = {
                        onProfileChange(
                            profile.copy(
                                umountModules = it,
                                nonRootUseDefault = false
                            )
                        )
                    }
                )
            }
        )
    }
}
