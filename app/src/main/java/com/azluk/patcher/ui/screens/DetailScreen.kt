package com.azluk.patcher.ui.screens

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.provider.Settings
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.navigation.NavController
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import com.azluk.patcher.ui.theme.*
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

data class AppDetails(
    val name: String,
    val pkg: String,
    val version: String,
    val versionCode: Long,
    val apkSize: Long,
    val installDate: Long,
    val updateDate: Long,
    val isSystem: Boolean,
    val isDebuggable: Boolean,
    val dataDir: String,
    val nativeLibDir: String,
    val targetSdk: Int,
    val minSdk: Int,
    val permissions: List<String>,
    val activities: List<String>,
    val services: List<String>,
    val receivers: List<String>,
    val icon: Drawable?
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(pkg: String, navController: NavController) {
    val ctx = LocalContext.current
    val pm  = ctx.packageManager

    val details = remember(pkg) {
        try {
            val ai = pm.getApplicationInfo(pkg, PackageManager.GET_META_DATA)
            val pi = pm.getPackageInfo(pkg,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS)

            AppDetails(
                name        = pm.getApplicationLabel(ai).toString(),
                pkg         = pkg,
                version     = pi.versionName ?: "?",
                versionCode = if (android.os.Build.VERSION.SDK_INT >= 28)
                    pi.longVersionCode else @Suppress("DEPRECATION") pi.versionCode.toLong(),
                apkSize     = File(ai.sourceDir).length(),
                installDate = pi.firstInstallTime,
                updateDate  = pi.lastUpdateTime,
                isSystem    = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                isDebuggable= (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                dataDir     = ai.dataDir ?: "N/A",
                nativeLibDir= ai.nativeLibraryDir ?: "N/A",
                targetSdk   = ai.targetSdkVersion,
                minSdk      = if (android.os.Build.VERSION.SDK_INT >= 24) ai.minSdkVersion else 0,
                permissions = pi.requestedPermissions?.toList() ?: emptyList(),
                activities  = pi.activities?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                services    = pi.services?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                receivers   = pi.receivers?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                icon        = try { pm.getApplicationIcon(ai) } catch (_: Exception) { null }
            )
        } catch (e: Exception) { null }
    }

    if (details == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("App not found", color = AzlukError)
        }
        return
    }

    var activeTab by remember { mutableStateOf(0) }
    val fmt = remember { SimpleDateFormat("MMM d, yyyy", Locale.getDefault()) }

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = {
                    Text(details.name, color = AzlukOnBg,
                        fontWeight = FontWeight.SemiBold, maxLines = 1,
                        overflow = TextOverflow.Ellipsis)
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AzlukSurface)
            )
        },
        // Bottom sheet style action bar
        bottomBar = {
            Surface(
                color = AzlukSurface,
                tonalElevation = 3.dp
            ) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Launch
                    OutlinedButton(
                        onClick = {
                            try {
                                ctx.startActivity(
                                    pm.getLaunchIntentForPackage(pkg)
                                        ?: return@OutlinedButton
                                )
                            } catch (_: Exception) {}
                        },
                        modifier = Modifier.weight(1f),
                        shape  = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, AzlukSurfaceVar)
                    ) {
                        Icon(Icons.Default.PlayArrow, null,
                            Modifier.size(16.dp), tint = AzlukSuccess)
                        Spacer(Modifier.width(4.dp))
                        Text("Launch", color = AzlukSuccess, fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold)
                    }
                    // App Settings
                    OutlinedButton(
                        onClick = {
                            ctx.startActivity(
                                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.parse("package:$pkg"))
                            )
                        },
                        modifier = Modifier.weight(1f),
                        shape  = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, AzlukSurfaceVar)
                    ) {
                        Icon(Icons.Default.Settings, null,
                            Modifier.size(16.dp), tint = AzlukOnSurface)
                        Spacer(Modifier.width(4.dp))
                        Text("Settings", color = AzlukOnSurface, fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold)
                    }
                    // Patch — main CTA
                    Button(
                        onClick = { navController.navigate("patch/$pkg") },
                        modifier = Modifier.weight(1.5f),
                        shape  = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                    ) {
                        Icon(Icons.Default.Build, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Patch", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // App header card with gradient
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.verticalGradient(listOf(AzlukSurface, AzlukBg)),
                    )
                    .padding(16.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Icon
                    Box(
                        Modifier
                            .size(64.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(AzlukSurfaceVar),
                        contentAlignment = Alignment.Center
                    ) {
                        if (details.icon != null) {
                            Image(
                                painter = rememberDrawablePainter(details.icon),
                                contentDescription = null,
                                modifier = Modifier.size(56.dp)
                            )
                        } else {
                            Icon(Icons.Default.Android, null,
                                Modifier.size(36.dp), tint = AzlukBlue)
                        }
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(details.name, color = AzlukOnBg,
                            fontWeight = FontWeight.Bold, fontSize = 16.sp,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(details.pkg, color = AzlukOnSurface,
                            fontSize = 11.sp, maxLines = 1,
                            overflow = TextOverflow.Ellipsis)
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            AppChip("v${details.version}", AzlukBlue)
                            AppChip(fmtSize(details.apkSize), AzlukOnSurface)
                            if (details.isSystem) AppChip("SYS", AzlukWarning)
                            if (details.isDebuggable) AppChip("DEBUG", AzlukSuccess)
                        }
                    }
                }
            }

            // Tab row
            val tabs = listOf("Info", "Permissions", "Components")
            TabRow(
                selectedTabIndex = activeTab,
                containerColor   = AzlukSurface,
                contentColor     = AzlukBlue,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[activeTab]),
                        color = AzlukBlue
                    )
                }
            ) {
                tabs.forEachIndexed { i, title ->
                    Tab(
                        selected = activeTab == i,
                        onClick  = { activeTab = i },
                        text = {
                            Text(title, fontSize = 13.sp,
                                color = if (activeTab == i) AzlukBlue else AzlukOnSurface)
                        }
                    )
                }
            }

            // Tab content
            when (activeTab) {
                0 -> InfoTab(details, fmt)
                1 -> PermissionsTab(details.permissions)
                2 -> ComponentsTab(details)
            }
        }
    }
}

@Composable
private fun InfoTab(d: AppDetails, fmt: SimpleDateFormat) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        InfoSection("Package Info") {
            InfoRow2("Package",     d.pkg)
            InfoRow2("Version",     "${d.version} (${d.versionCode})")
            InfoRow2("APK Size",    fmtSize(d.apkSize))
            InfoRow2("Target SDK",  "API ${d.targetSdk}")
            InfoRow2("Min SDK",     "API ${d.minSdk}")
            InfoRow2("Type",        if (d.isSystem) "System App" else "User App")
            InfoRow2("Debuggable",  if (d.isDebuggable) "Yes" else "No")
        }
        InfoSection("Dates") {
            InfoRow2("Installed",  fmt.format(Date(d.installDate)))
            InfoRow2("Updated",    fmt.format(Date(d.updateDate)))
        }
        InfoSection("Paths") {
            InfoRow2("Data Dir",    d.dataDir)
            InfoRow2("Native Libs", d.nativeLibDir)
        }
        InfoSection("Components") {
            InfoRow2("Activities",  d.activities.size.toString())
            InfoRow2("Services",    d.services.size.toString())
            InfoRow2("Receivers",   d.receivers.size.toString())
            InfoRow2("Permissions", d.permissions.size.toString())
        }
    }
}

@Composable
private fun PermissionsTab(perms: List<String>) {
    if (perms.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No permissions declared", color = AzlukOnSurface)
        }
        return
    }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text("${perms.size} permissions", color = AzlukOnSurface,
            fontSize = 12.sp, modifier = Modifier.padding(bottom = 4.dp))
        perms.forEach { perm ->
            val isDangerous = perm.contains("READ_") || perm.contains("WRITE_") ||
                perm.contains("LOCATION") || perm.contains("CAMERA") ||
                perm.contains("CONTACTS") || perm.contains("PHONE") ||
                perm.contains("SMS") || perm.contains("STORAGE")
            val color = if (isDangerous) AzlukWarning else AzlukOnSurface
            Surface(
                color = if (isDangerous) AzlukWarning.copy(.06f) else AzlukSurface,
                shape = RoundedCornerShape(8.dp)
            ) {
                Row(
                    Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(color)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        perm.removePrefix("android.permission."),
                        color = color, fontSize = 12.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun ComponentsTab(d: AppDetails) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ComponentSection("Activities (${d.activities.size})",
            Icons.Default.Window, d.activities, AzlukBlue)
        ComponentSection("Services (${d.services.size})",
            Icons.Default.Dns, d.services, AzlukSuccess)
        ComponentSection("Receivers (${d.receivers.size})",
            Icons.Default.Notifications, d.receivers, AzlukWarning)
    }
}

@Composable
private fun ComponentSection(
    title: String, icon: ImageVector,
    items: List<String>, color: Color
) {
    if (items.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, Modifier.size(14.dp), tint = color)
            Spacer(Modifier.width(6.dp))
            Text(title, color = color, fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold)
        }
        items.forEach { name ->
            Surface(color = AzlukSurface, shape = RoundedCornerShape(8.dp)) {
                Text(name, color = AzlukOnSurface, fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun InfoSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Surface(color = AzlukSurface, shape = RoundedCornerShape(14.dp)) {
        Column(Modifier.padding(14.dp)) {
            Text(title, color = AzlukBlue, fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(bottom = 8.dp))
            content()
        }
    }
}

@Composable
private fun InfoRow2(label: String, value: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AzlukOnSurface, fontSize = 12.sp)
        Text(value, color = AzlukOnBg, fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.widthIn(max = 220.dp))
    }
}

@Composable
private fun AppChip(text: String, color: Color) {
    Surface(
        color = color.copy(alpha = .12f),
        shape = RoundedCornerShape(6.dp)
    ) {
        Text(text, color = color, fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp))
    }
}

private fun fmtSize(b: Long) = when {
    b < 1024 -> "$b B"
    b < 1024*1024 -> "%.1f KB".format(b/1024f)
    b < 1024L*1024*1024 -> "%.1f MB".format(b/(1024f*1024))
    else -> "%.2f GB".format(b/(1024f*1024*1024))
}

