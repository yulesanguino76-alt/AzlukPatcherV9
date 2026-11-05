package com.azluk.patcher.ui.screens

import androidx.activity.ComponentActivity
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.PatchType
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PatchViewModel
import org.json.JSONArray
import org.json.JSONObject

private data class PatchPack(
    val id:          String,
    val name:        String,
    val icon:        String,
    val category:    String,
    val description: String
)

/** Maps pack.id to the PatchTypes it enables. */
private val PACK_TYPES = mapOf(
    "lucky_core"  to setOf(PatchType.LICENSE_BYPASS, PatchType.IAP_BYPASS, PatchType.SIGNATURE_BYPASS),
    "np_ssl"      to setOf(PatchType.SSL_BYPASS),
    "gg_stealth"  to setOf(PatchType.ROOT_BYPASS, PatchType.SAFETYNET_BYPASS, PatchType.FRIDA_BYPASS),
    "ads_nuke"    to setOf(PatchType.REMOVE_ADS, PatchType.BLOCK_AD_DOMAINS, PatchType.DISABLE_ANALYTICS, PatchType.REMOVE_TELEMETRY),
    "dev_tools"   to setOf(PatchType.FORCE_DEBUGGABLE, PatchType.DISABLE_FLAG_SECURE, PatchType.EXPORT_ALL_COMPONENTS, PatchType.ALLOW_BACKUP),
    "full_patch"  to PatchType.values().toSet()
)

private fun packIcon(icon: String): ImageVector = when (icon) {
    "verified_user" -> Icons.Default.VerifiedUser
    "lock_open"     -> Icons.Default.LockOpen
    "shield"        -> Icons.Default.Shield
    "block"         -> Icons.Default.Block
    "code"          -> Icons.Default.Code
    "auto_fix_high" -> Icons.Default.AutoFixHigh
    else            -> Icons.Default.Extension
}

private fun packColor(cat: String) = when (cat) {
    "bypass"   -> AzlukBlue
    "security" -> AzlukError
    "ads"      -> AzlukWarning
    "dev"      -> AzlukCyan
    "all"      -> AzlukSuccess
    else       -> AzlukOnSurface
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchPacksScreen(
    navController: NavController
) {
    val ctx = LocalContext.current

    val packs = remember {
        try {
            val json = ctx.assets.open("azluk_patchpacks.json")
                .bufferedReader().readText()
            val arr: JSONArray = JSONObject(json).getJSONArray("packs")
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                PatchPack(
                    id          = o.getString("id"),
                    name        = o.getString("name"),
                    icon        = o.getString("icon"),
                    category    = o.getString("category"),
                    description = o.getString("description")
                )
            }
        } catch (_: Exception) { emptyList() }
    }

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = {
                    Text("Patch Packs", color = AzlukOnBg, fontWeight = FontWeight.SemiBold)
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AzlukSurface)
            )
        }
    ) { padding ->
        if (packs.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No packs found", color = AzlukOnSurface)
            }
            return@Scaffold
        }

        LazyColumn(
            modifier            = Modifier.fillMaxSize().padding(padding),
            contentPadding      = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Text(
                    "Tap a pack to apply it to any app — these are preset combinations " +
                    "of patch types tuned for common use cases.",
                    color    = AzlukOnSurface,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
            }

            items(packs, key = { it.id }) { pack ->
                val color   = packColor(pack.category)
                val types   = PACK_TYPES[pack.id] ?: emptySet()

                Surface(
                    color    = AzlukSurface,
                    shape    = RoundedCornerShape(16.dp),
                    border   = BorderStroke(1.dp, color.copy(.25f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            // Navigate to home — user picks an app, then pack types
                            // are pre-selected via deep-link. For V10 we store the
                            // pack selection in the back stack note.
                            navController.popBackStack()
                        }
                ) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            color  = color.copy(.12f),
                            shape  = RoundedCornerShape(12.dp),
                            modifier = Modifier.size(50.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(packIcon(pack.icon), null, tint = color, modifier = Modifier.size(26.dp))
                            }
                        }

                        Spacer(Modifier.width(14.dp))

                        Column(Modifier.weight(1f)) {
                            Text(
                                pack.name,
                                color      = AzlukOnBg,
                                fontSize   = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                pack.description,
                                color    = AzlukOnSurface,
                                fontSize = 11.sp,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(Modifier.height(6.dp))
                            // Type chips
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                                modifier = Modifier.padding(top = 2.dp)
                            ) {
                                types.take(4).forEach { t ->
                                    Surface(color = color.copy(.08f), shape = RoundedCornerShape(4.dp)) {
                                        Text(
                                            t.displayName.take(12),
                                            color    = color,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                                if (types.size > 4) {
                                    Surface(color = color.copy(.08f), shape = RoundedCornerShape(4.dp)) {
                                        Text(
                                            "+${types.size - 4}",
                                            color    = color,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                            }
                        }

                        Icon(Icons.Default.ChevronRight, null, tint = color.copy(.5f), modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
    }
}
