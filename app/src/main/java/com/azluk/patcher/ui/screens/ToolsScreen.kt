package com.azluk.patcher.ui.screens

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.ui.theme.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

// ── ViewModel ────────────────────────────────────────────────────────────────

data class ToolsState(
    val ramTotal: Long = 0L,
    val ramAvail: Long = 0L,
    val cacheSize: Long = 0L,
    val patchedSize: Long = 0L,
    val wifiNets: List<WifiNet> = emptyList(),
    val wifiScanning: Boolean = false,
    val wifiEnabled: Boolean = false,
    val cleaning: Boolean = false,
    val cleanedBytes: Long = 0L,
    val message: String? = null
)

data class WifiNet(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val frequency: Int,
    val security: String,
    val channel: Int
)

class ToolsViewModel : ViewModel() {
    private val _state = MutableStateFlow(ToolsState())
    val state = _state.asStateFlow()

    fun loadStats(ctx: Context) = viewModelScope.launch(Dispatchers.IO) {
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)

        val cacheSize = ctx.cacheDir
            .walkTopDown()
            .filter { it.isFile }
            .sumOf { it.length() }

        val patchedDir = File(
            android.os.Environment.getExternalStorageDirectory(),
            "AzlukPatcher/Patched"
        )

        val patchedSize = if (patchedDir.exists()) {
            patchedDir
                .walkTopDown()
                .filter { it.isFile }
                .sumOf { it.length() }
        } else {
            0L
        }

        _state.update {
            it.copy(
                ramTotal    = mi.totalMem,
                ramAvail    = mi.availMem,
                cacheSize   = cacheSize,
                patchedSize = patchedSize
            )
        }
    }

    fun scanWifi(ctx: Context) = viewModelScope.launch(Dispatchers.IO) {
        _state.update {
            it.copy(
                wifiScanning = true,
                wifiNets     = emptyList()
            )
        }

        try {
            val wm = ctx.applicationContext.getSystemService(
                Context.WIFI_SERVICE
            ) as WifiManager

            val enabled = wm.isWifiEnabled

            _state.update { it.copy(wifiEnabled = enabled) }

            if (!enabled) {
                _state.update { it.copy(wifiScanning = false) }
                return@launch
            }

            wm.startScan()
            delay(2000)

            val results = wm.scanResults

            val nets = results
                .map { r ->
                    val ssid = if (Build.VERSION.SDK_INT >= 33) {
                        r.wifiSsid?.toString()?.trim('"') ?: ""
                    } else {
                        @Suppress("DEPRECATION")
                        r.SSID ?: ""
                    }

                    val sec = when {
                        r.capabilities.contains("WPA3") -> "WPA3"
                        r.capabilities.contains("WPA2") -> "WPA2"
                        r.capabilities.contains("WPA")  -> "WPA"
                        r.capabilities.contains("WEP")  -> "WEP"
                        else                            -> "Open"
                    }

                    val ch = when {
                        r.frequency < 2484  -> ((r.frequency - 2412) / 5) + 1
                        r.frequency == 2484 -> 14
                        else                -> ((r.frequency - 5180) / 5) + 36
                    }

                    WifiNet(
                        ssid     = ssid.ifEmpty { "<hidden>" },
                        bssid    = r.BSSID ?: "",
                        rssi     = r.level,
                        frequency = r.frequency,
                        security = sec,
                        channel  = ch
                    )
                }
                .sortedByDescending { it.rssi }

            _state.update {
                it.copy(
                    wifiNets     = nets,
                    wifiScanning = false
                )
            }
        } catch (e: Exception) {
            _state.update {
                it.copy(
                    wifiScanning = false,
                    message      = "Scan failed: ${e.message}"
                )
            }
        }
    }

    fun cleanCache(ctx: Context) = viewModelScope.launch(Dispatchers.IO) {
        _state.update { it.copy(cleaning = true, cleanedBytes = 0L) }

        var cleaned = 0L

        ctx.cacheDir.walkTopDown().forEach { f ->
            if (f.isFile) { cleaned += f.length(); f.delete() }
        }

        ctx.externalCacheDir?.walkTopDown()?.forEach { f ->
            if (f.isFile) { cleaned += f.length(); f.delete() }
        }

        _state.update {
            it.copy(
                cleaning     = false,
                cleanedBytes = cleaned,
                message      = "Cleaned ${fmt(cleaned)}"
            )
        }

        loadStats(ctx)
    }

    fun dismissMessage() {
        _state.update { it.copy(message = null) }
    }

    private fun fmt(b: Long) = when {
        b < 1024            -> "$b B"
        b < 1024 * 1024     -> "%.1f KB".format(b / 1024f)
        b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / (1024f * 1024))
        else                -> "%.2f GB".format(b / (1024f * 1024 * 1024))
    }
}

// ── UI ───────────────────────────────────────────────────────────────────────

@Composable
fun ToolsScreen(
    navController: NavController,
    vm: ToolsViewModel = viewModel()
) {
    val state by vm.state.collectAsState()
    val ctx = LocalContext.current

    var activeTab by remember { mutableStateOf(0) }

    LaunchedEffect(Unit) { vm.loadStats(ctx) }

    state.message?.let { msg ->
        LaunchedEffect(msg) {
            delay(3000)
            vm.dismissMessage()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(AzlukBg)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Brush.verticalGradient(listOf(AzlukSurface2, AzlukBg)))
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { navController.popBackStack() }) {
                    Icon(Icons.Default.ArrowBack, "Back", tint = AzlukOnBg)
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    "Tools",
                    color      = AzlukOnBg,
                    fontSize   = 20.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        val tabs = listOf("Device", "WiFi Scanner", "Cleaner")

        ScrollableTabRow(
            selectedTabIndex = activeTab,
            containerColor   = AzlukSurface,
            contentColor     = AzlukBlue,
            edgePadding      = 16.dp
        ) {
            tabs.forEachIndexed { i, title ->
                Tab(
                    selected = activeTab == i,
                    onClick  = { activeTab = i },
                    text     = { Text(title, fontSize = 13.sp) }
                )
            }
        }

        when (activeTab) {
            0 -> DeviceTab(state, ctx, vm)
            1 -> WifiTab(state, ctx, vm)
            2 -> CleanerTab(state, ctx, vm)
        }
    }
}

@Composable
private fun DeviceTab(
    state: ToolsState,
    ctx: Context,
    vm: ToolsViewModel
) {
    val ramUsed = state.ramTotal - state.ramAvail
    val ramPct  = if (state.ramTotal > 0)
        (ramUsed.toFloat() / state.ramTotal * 100).toInt() else 0

    LazyColumn(
        modifier        = Modifier.fillMaxSize(),
        contentPadding  = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            GlassCard {
                Column(Modifier.padding(16.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment     = Alignment.CenterVertically
                    ) {
                        Text("RAM", color = AzlukOnBg, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        Text("$ramPct%", color = AzlukBlue, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    }

                    Spacer(Modifier.height(8.dp))

                    LinearProgressIndicator(
                        progress   = { ramPct / 100f },
                        modifier   = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
                        color      = if (ramPct > 80) AzlukError else AzlukBlue,
                        trackColor = AzlukSurface2
                    )

                    Spacer(Modifier.height(8.dp))

                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Used: ${fmtRam(ramUsed)}",      color = AzlukOnSurface, fontSize = 12.sp)
                        Text("Free: ${fmtRam(state.ramAvail)}", color = AzlukSuccess,   fontSize = 12.sp)
                        Text("Total: ${fmtRam(state.ramTotal)}", color = AzlukOnSurface, fontSize = 12.sp)
                    }
                }
            }
        }

        item {
            GlassCard {
                Column(Modifier.padding(16.dp)) {
                    Text("Storage", color = AzlukOnBg, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(Modifier.height(12.dp))
                    StorageRow("App Cache",    state.cacheSize)
                    StorageRow("Patched APKs", state.patchedSize)
                    val extDir = android.os.Environment.getExternalStorageDirectory()
                    StorageRow("Storage Free",  extDir.freeSpace)
                    StorageRow("Storage Total", extDir.totalSpace)
                }
            }
        }

        item {
            Text(
                "Quick Access",
                color      = AzlukOnSurface,
                fontSize   = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier   = Modifier.padding(bottom = 4.dp)
            )
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                QuickLink("Developer Options", Icons.Default.Code) {
                    ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
                }
                QuickLink("App Management", Icons.Default.Apps) {
                    ctx.startActivity(Intent(Settings.ACTION_APPLICATION_SETTINGS))
                }
                QuickLink("Private DNS", Icons.Default.Dns) {
                    try {
                        ctx.startActivity(Intent("android.settings.PRIVATE_DNS_SETTINGS"))
                    } catch (e: Exception) {
                        ctx.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
                    }
                }
                QuickLink("AzlukPatcher Folder", Icons.Default.Folder) {
                    val dir = File(
                        android.os.Environment.getExternalStorageDirectory(),
                        "AzlukPatcher"
                    )
                    dir.mkdirs()
                    android.widget.Toast.makeText(ctx, dir.absolutePath, android.widget.Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}

@Composable
private fun WifiTab(
    state: ToolsState,
    ctx: Context,
    vm: ToolsViewModel
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Button(
            onClick  = { vm.scanWifi(ctx) },
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            enabled  = !state.wifiScanning,
            colors   = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
        ) {
            if (state.wifiScanning) {
                CircularProgressIndicator(Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Scanning…")
            } else {
                Icon(Icons.Default.Wifi, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Scan WiFi Networks")
            }
        }

        if (!state.wifiEnabled && !state.wifiScanning) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("WiFi is disabled", color = AzlukOnSurface)
            }
            return@Column
        }

        if (state.wifiNets.isEmpty() && !state.wifiScanning) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Tap scan to find networks", color = AzlukOnSurface)
            }
            return@Column
        }

        Text(
            "${state.wifiNets.size} networks found",
            color    = AzlukOnSurface,
            fontSize = 12.sp,
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        Spacer(Modifier.height(8.dp))

        LazyColumn(
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(state.wifiNets) { net -> WifiNetCard(net) }
        }
    }
}

@Composable
private fun WifiNetCard(net: WifiNet) {
    val signalPct  = WifiManager.calculateSignalLevel(net.rssi, 100)
    val signalColor = when {
        signalPct > 66 -> AzlukSuccess
        signalPct > 33 -> AzlukWarning
        else           -> AzlukError
    }
    val secColor = if (net.security == "Open") AzlukError else AzlukSuccess

    GlassCard {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Wifi, null, tint = signalColor, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(net.ssid, color = AzlukOnBg, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                Text(net.bssid, color = AzlukOnSurface, fontSize = 11.sp)
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    MiniChip(net.security,         secColor)
                    MiniChip("Ch ${net.channel}",  AzlukBlue)
                    MiniChip("${net.frequency} MHz", AzlukOnSurface)
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("$signalPct%", color = signalColor, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text("${net.rssi} dBm", color = AzlukOnSurface, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun CleanerTab(
    state: ToolsState,
    ctx: Context,
    vm: ToolsViewModel
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        GlassCard {
            Column(Modifier.padding(16.dp)) {
                Text("App Cache", color = AzlukOnBg, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Spacer(Modifier.height(4.dp))
                Text("Current cache: ${fmtRam(state.cacheSize)}", color = AzlukOnSurface, fontSize = 13.sp)
                if (state.cleanedBytes > 0) {
                    Text("Last cleaned: ${fmtRam(state.cleanedBytes)}", color = AzlukSuccess, fontSize = 13.sp)
                }
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick  = { vm.cleanCache(ctx) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled  = !state.cleaning,
                    colors   = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                ) {
                    if (state.cleaning) {
                        CircularProgressIndicator(Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Cleaning…")
                    } else {
                        Icon(Icons.Default.CleaningServices, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Clean Cache")
                    }
                }
            }
        }

        GlassCard {
            Column(Modifier.padding(16.dp)) {
                Text("DNS Quick Switch", color = AzlukOnBg, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Spacer(Modifier.height(12.dp))

                listOf(
                    Triple("AdGuard DNS", "dns.adguard-dns.com", AzlukSuccess),
                    Triple("Cloudflare",  "one.one.one.one",     AzlukBlue),
                    Triple("NextDNS",     "dns.nextdns.io",      AzlukWarning)
                ).forEach { (name, host, color) ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable {
                                try {
                                    ctx.startActivity(Intent("android.settings.PRIVATE_DNS_SETTINGS"))
                                } catch (e: Exception) {
                                    ctx.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
                                }
                                android.widget.Toast.makeText(
                                    ctx, "Set hostname: $host", android.widget.Toast.LENGTH_LONG
                                ).show()
                            }
                            .padding(vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment     = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(name, color = AzlukOnBg, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                            Text(host, color = AzlukOnSurface, fontSize = 11.sp)
                        }
                        Icon(Icons.Default.ChevronRight, null, tint = color)
                    }
                    HorizontalDivider(color = AzlukSurface2, thickness = 0.5.dp)
                }
            }
        }

        state.message?.let {
            Card(colors = CardDefaults.cardColors(containerColor = AzlukSuccess.copy(alpha = .15f))) {
                Text(it, color = AzlukSuccess, modifier = Modifier.padding(12.dp), fontSize = 13.sp)
            }
        }
    }
}

// ── Reusable components ───────────────────────────────────────────────────────

@Composable
private fun GlassCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(18.dp),
        colors   = CardDefaults.cardColors(containerColor = AzlukSurface),
        border   = BorderStroke(1.dp, AzlukSurface2)
    ) { content() }
}

@Composable
private fun StorageRow(label: String, bytes: Long) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label,         color = AzlukOnSurface, fontSize = 13.sp)
        Text(fmtRam(bytes), color = AzlukBlue, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun QuickLink(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape    = RoundedCornerShape(14.dp),
        colors   = CardDefaults.cardColors(containerColor = AzlukSurface),
        border   = BorderStroke(1.dp, AzlukSurface2)
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = AzlukBlue, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(12.dp))
            Text(label, color = AzlukOnBg, fontSize = 14.sp, modifier = Modifier.weight(1f))
            Icon(Icons.Default.ChevronRight, null, tint = AzlukOnSurface)
        }
    }
}

@Composable
private fun MiniChip(text: String, color: Color) {
    Surface(shape = RoundedCornerShape(6.dp), color = color.copy(alpha = .15f)) {
        Text(
            text,
            color    = color,
            fontSize = 10.sp,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

private fun fmtRam(b: Long) = when {
    b <= 0                  -> "0 B"
    b < 1024                -> "$b B"
    b < 1024 * 1024         -> "%.1f KB".format(b / 1024f)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / (1024f * 1024))
    else                    -> "%.2f GB".format(b / (1024f * 1024 * 1024))
}
