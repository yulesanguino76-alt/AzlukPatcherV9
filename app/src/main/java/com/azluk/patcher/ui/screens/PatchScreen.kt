package com.azluk.patcher.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.*
import androidx.activity.ComponentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.*
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PatchViewModel

private fun patchIcon(type: PatchType) = when (type) {
    PatchType.LICENSE_BYPASS        -> Icons.Default.VerifiedUser
    PatchType.IAP_BYPASS            -> Icons.Default.ShoppingCart
    PatchType.SIGNATURE_BYPASS      -> Icons.Default.Fingerprint
    PatchType.GOOGLE_PLAY_BYPASS    -> Icons.Default.Shop
    PatchType.REMOVE_ADS            -> Icons.Default.Block
    PatchType.BLOCK_AD_DOMAINS      -> Icons.Default.Domain
    PatchType.SSL_BYPASS            -> Icons.Default.LockOpen
    PatchType.ROOT_BYPASS           -> Icons.Default.Security
    PatchType.SAFETYNET_BYPASS      -> Icons.Default.Shield
    PatchType.FRIDA_BYPASS          -> Icons.Default.BugReport
    PatchType.EMULATOR_BYPASS       -> Icons.Default.PhoneAndroid
    PatchType.FORCE_DEBUGGABLE      -> Icons.Default.Code
    PatchType.DISABLE_FLAG_SECURE   -> Icons.Default.ScreenshotMonitor
    PatchType.EXPORT_ALL_COMPONENTS -> Icons.Default.OpenInNew
    PatchType.ALLOW_BACKUP          -> Icons.Default.Backup
    PatchType.DISABLE_ANALYTICS     -> Icons.Default.Analytics
    PatchType.OPTIMIZE_ZIP          -> Icons.Default.Compress
    PatchType.REMOVE_TELEMETRY      -> Icons.Default.VisibilityOff
}

private fun catColor(cat: String) = when (cat) {
    "bypass"   -> AzlukBlue
    "ads"      -> AzlukWarning
    "security" -> AzlukError
    "dev"      -> AzlukCyan
    "util"     -> AzlukSuccess
    else       -> AzlukOnSurface
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchScreen(pkg: String, navController: NavController, vm: PatchViewModel = viewModel(LocalContext.current as ComponentActivity)) {
    val state by vm.state.collectAsStateWithLifecycle()

    LaunchedEffect(pkg) {
        vm.ensureScanned(pkg)
    }

    val categories = PatchType.values().groupBy { it.category }
    val catOrder    = listOf("bypass", "ads", "security", "dev", "util")
    val catLabels   = mapOf(
        "bypass"   to "Bypass",
        "ads"      to "Ads & Tracking",
        "security" to "Anti-Detection",
        "dev"      to "Developer",
        "util"     to "Utility"
    )
    val catIcons = mapOf(
        "bypass"   to Icons.Default.LockOpen,
        "ads"      to Icons.Default.Block,
        "security" to Icons.Default.Shield,
        "dev"      to Icons.Default.Code,
        "util"     to Icons.Default.Tune
    )
    val detectedTypes = state.scanResults
        .mapNotNull { runCatching { PatchType.valueOf(it.patchType) }.getOrNull() }.toSet()

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Select Patches", color = AzlukOnBg, fontWeight = FontWeight.SemiBold)
                        Text(pkg, color = AzlukOnSurface, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AzlukSurface)
            )
        },
        bottomBar = {
            Surface(color = AzlukSurface, tonalElevation = 3.dp) {
                Column(Modifier.navigationBarsPadding().padding(12.dp)) {
                    if (state.scanResults.isNotEmpty()) {
                        Row(
                            Modifier.fillMaxWidth().padding(bottom = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Default.Analytics, null, tint = AzlukBlue, modifier = Modifier.size(16.dp))
                            Text("${state.scanResults.size} targets detected",
                                color = AzlukBlue, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick  = { vm.scan(pkg) },
                            enabled  = !state.isScanning,
                            modifier = Modifier.weight(1f),
                            shape    = RoundedCornerShape(12.dp),
                            border   = BorderStroke(1.dp, AzlukSurfaceVar)
                        ) {
                            if (state.isScanning) {
                                CircularProgressIndicator(Modifier.size(14.dp), color = AzlukBlue, strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Default.Search, null, Modifier.size(16.dp), tint = AzlukBlue)
                            }
                            Spacer(Modifier.width(6.dp))
                            Text("Scan", color = AzlukBlue, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                        }
                        Button(
                            onClick  = { vm.resetPatch(); navController.navigate("patchlog/$pkg") },
                            enabled  = state.selectedPatches.isNotEmpty() && !state.isScanning,
                            modifier = Modifier.weight(2f),
                            shape    = RoundedCornerShape(12.dp),
                            colors   = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                        ) {
                            Icon(Icons.Default.Build, null, Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Patch (${state.selectedPatches.size})", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier            = Modifier.fillMaxSize().padding(padding),
            contentPadding       = PaddingValues(16.dp),
            verticalArrangement  = Arrangement.spacedBy(10.dp)
        ) {
            if (detectedTypes.isNotEmpty()) {
                item {
                    Surface(color = AzlukBlue.copy(.08f), shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, AzlukBlue.copy(.2f))) {
                        Row(
                            Modifier.fillMaxWidth().padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.AutoAwesome, null, tint = AzlukBlue, modifier = Modifier.size(18.dp))
                                Column {
                                    Text("${detectedTypes.size} patches auto-detected", color = AzlukBlue,
                                        fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                                    Text(detectedTypes.take(4).joinToString(", ") { it.displayName } +
                                        if (detectedTypes.size > 4) "…" else "",
                                        color = AzlukOnSurface, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                            TextButton(onClick = { vm.selectAll(detectedTypes) }) {
                                Text("Select All", color = AzlukBlue, fontSize = 12.sp)
                            }
                        }
                    }
                }
            }

            state.scanError?.let { err ->
                item {
                    Surface(
                        color  = AzlukError.copy(.08f),
                        shape  = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, AzlukError.copy(.25f))
                    ) {
                        Row(
                            Modifier.fillMaxWidth().padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, null, tint = AzlukError, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Scan failed: $err", color = AzlukError, fontSize = 12.sp)
                        }
                    }
                }
            }

            for (cat in catOrder) {
                val types = categories[cat] ?: continue
                val color = catColor(cat)
                item {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(top = 6.dp, bottom = 4.dp)
                    ) {
                        Icon(catIcons[cat] ?: Icons.Default.Tune, null, tint = color, modifier = Modifier.size(14.dp))
                        Text(catLabels[cat] ?: cat.uppercase(),
                            color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.weight(1f))
                        Text("${types.size}", color = AzlukOnSurface.copy(.5f), fontSize = 10.sp)
                    }
                }
                items(types) { type ->
                    val selected    = type in state.selectedPatches
                    val wasDetected = type in detectedTypes
                    val tint        = color

                    val scale by animateFloatAsState(
                        targetValue   = if (selected) 1f else 0.98f,
                        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
                        label = "card_scale"
                    )

                    Surface(
                        color    = if (selected) tint.copy(.08f) else AzlukSurface,
                        shape    = RoundedCornerShape(14.dp),
                        border   = BorderStroke(1.dp, if (selected) tint.copy(.4f) else AzlukSurfaceVar),
                        modifier = Modifier
                            .fillMaxWidth()
                            .graphicsLayer { scaleX = scale; scaleY = scale }
                            .clickable { vm.togglePatch(type) }
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Surface(color = tint.copy(.12f), shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.size(40.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(patchIcon(type), null, tint = tint, modifier = Modifier.size(22.dp))
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.CenterVertically) {
                                    Text(type.displayName, color = AzlukOnBg, fontSize = 13.sp,
                                        fontWeight = FontWeight.SemiBold)
                                    if (wasDetected) {
                                        Surface(color = AzlukSuccess.copy(.12f), shape = RoundedCornerShape(4.dp)) {
                                            Text("FOUND", color = AzlukSuccess, fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                        }
                                    }
                                }
                                Text(type.description, color = AzlukOnSurface, fontSize = 11.sp,
                                    maxLines = 2, overflow = TextOverflow.Ellipsis)
                            }
                            Checkbox(
                                checked        = selected,
                                onCheckedChange = { vm.togglePatch(type) },
                                colors = CheckboxDefaults.colors(checkedColor = tint, uncheckedColor = AzlukOnSurface.copy(.4f))
                            )
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}
