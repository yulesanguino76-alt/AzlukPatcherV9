package com.azluk.patcher.ui.screens

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.utils.StorageUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * APK Toolkit — replaces the old WiFi/DNS grab-bag with tools that
 * actually belong to a patcher: output inventory, checksums, temp
 * cleanup and device facts.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ToolsScreen(navController: NavController) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current

    var files by remember { mutableStateOf<List<File>>(emptyList()) }
    var hashes by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var busy by remember { mutableStateOf(false) }
    var expanded by remember { mutableStateOf<String?>(null) }

    val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }

    suspend fun reload() = withContext(Dispatchers.IO) {
        val list = StorageUtils.getPatchedFiles()
        val map = list.associate { f ->
            f.absolutePath to runCatching {
                val d = MessageDigest.getInstance("SHA-256")
                f.inputStream().use { input ->
                    val buf = ByteArray(256 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n == -1) break
                        d.update(buf, 0, n)
                    }
                }
                d.digest().joinToString("") { "%02x".format(it) }
            }.getOrDefault("error")
        }
        files = list
        hashes = map
    }

    LaunchedEffect(Unit) {
        busy = true
        reload()
        busy = false
    }

    val totalBytes = files.sumOf { it.length() }

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = { Text("APK Toolkit", color = AzlukOnBg, fontWeight = FontWeight.SemiBold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AzlukSurface)
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Outputs summary ──────────────────────────────────────────
            Surface(color = AzlukSurface, shape = RoundedCornerShape(14.dp)) {
                Row(
                    Modifier.fillMaxWidth().padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.FolderOpen, null,
                        Modifier.size(20.dp), tint = AzlukBlue)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text("${files.size} patched outputs",
                            color = AzlukOnBg, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        Text("%.1f MB total".format(totalBytes / 1048576f),
                            color = AzlukOnSurface, fontSize = 11.sp)
                    }
                }
            }

            // ── Temp cleanup ─────────────────────────────────────────────
            Surface(color = AzlukSurface, shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.fillMaxWidth().padding(14.dp)) {
                    Text("Engine temporaries", color = AzlukBlue,
                        fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Removes leftover scan/staging artifacts " +
                                "(azluk-* in app cache). Safe: outputs live in AzlukPatcher/Patched.",
                        color = AzlukOnSurface, fontSize = 11.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = {
                            busy = true
                            kotlinx.coroutines.MainScope().launch {
                                val n = withContext(Dispatchers.IO) {
                                    StorageUtils.clearEngineArtifacts(ctx.cacheDir)
                                }
                                Toast.makeText(
                                    ctx, "$n artifacts deleted", Toast.LENGTH_SHORT
                                ).show()
                                busy = false
                            }
                        },
                        enabled = !busy,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                    ) {
                        Icon(Icons.Default.CleaningServices, null, Modifier.size(14.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Clean", fontSize = 12.sp)
                    }
                }
            }

            // ── Device facts ─────────────────────────────────────────────
            Surface(color = AzlukSurface, shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.fillMaxWidth().padding(14.dp)) {
                    Text("Device", color = AzlukBlue,
                        fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    FactRow("Model", "${Build.MANUFACTURER} ${Build.MODEL}")
                    FactRow("Android", "API ${Build.VERSION.SDK_INT}")
                    FactRow("ABI", Build.SUPPORTED_ABIS.firstOrNull() ?: "?")
                }
            }

            // ── Outputs list with checksums ──────────────────────────────
            if (files.isNotEmpty()) {
                Text("Checksums (SHA-256)", color = AzlukOnBg,
                    fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }

            files.forEach { f ->
                Surface(color = AzlukSurface, shape = RoundedCornerShape(12.dp)) {
                    Column(Modifier.fillMaxWidth()) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable {
                                    expanded =
                                        if (expanded == f.absolutePath) null else f.absolutePath
                                }
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.ApkDocument, null,
                                Modifier.size(18.dp), tint = AzlukBlue)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(f.name, color = AzlukOnBg,
                                    fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(
                                    "%.1f MB · ${fmt.format(Date(f.lastModified()))}"
                                        .format(f.length() / 1048576f),
                                    color = AzlukOnSurface, fontSize = 10.sp
                                )
                            }
                            Icon(
                                if (expanded == f.absolutePath)
                                    Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                null, tint = AzlukOnSurface
                            )
                        }

                        if (expanded == f.absolutePath) {
                            Column(Modifier.padding(start = 12.dp, end = 12.dp, bottom = 12.dp)) {
                                Surface(
                                    color = AzlukBg,
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(
                                        hashes[f.absolutePath] ?: "computing…",
                                        color = AzlukOnSurface,
                                        fontSize = 9.sp,
                                        fontFamily = FontFamily.Monospace,
                                        modifier = Modifier.padding(8.dp)
                                    )
                                }
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedButton(
                                        onClick = {
                                            clipboard.setText(AnnotatedString(
                                                hashes[f.absolutePath] ?: ""))
                                            Toast.makeText(ctx,
                                                "Checksum copied", Toast.LENGTH_SHORT).show()
                                        },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Icon(Icons.Default.ContentCopy, null,
                                            Modifier.size(13.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text("Copy", fontSize = 11.sp)
                                    }
                                    OutlinedButton(
                                        onClick = {
                                            busy = true
                                            kotlinx.coroutines.MainScope().launch {
                                                withContext(Dispatchers.IO) {
                                                    f.delete()
                                                    reload()
                                                }
                                                busy = false
                                            }
                                        },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(8.dp),
                                        border = androidx.compose.foundation.BorderStroke(
                                            1.dp, AzlukError.copy(.5f))
                                    ) {
                                        Icon(Icons.Default.DeleteOutline, null,
                                            Modifier.size(13.dp), tint = AzlukError)
                                        Spacer(Modifier.width(4.dp))
                                        Text("Delete", fontSize = 11.sp, color = AzlukError)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FactRow(label: String, value: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AzlukOnSurface, fontSize = 12.sp)
        Text(value, color = AzlukOnBg, fontSize = 12.sp, fontWeight = FontWeight.Medium)
    }
}

private fun kotlinx.coroutines.CoroutineScope.launch(block: suspend () -> Unit) =
    kotlinx.coroutines.launch { block() }
