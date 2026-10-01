package com.azluk.patcher.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.FolderOff
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.utils.StorageUtils
import com.azluk.patcher.viewmodel.SystemCheckViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

private data class FileChecksum(
    val name: String,
    val sizeMb: Float,
    val sha256: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ToolsScreen(
    navController: NavController,
    vm: SystemCheckViewModel = viewModel()
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    val profile by vm.profile.collectAsStateWithLifecycle()

    var patchedFiles by remember { mutableStateOf<List<File>>(emptyList()) }
    var checksums by remember { mutableStateOf<List<FileChecksum>>(emptyList()) }
    var computing by remember { mutableStateOf(false) }
    var cleanedMessage by remember { mutableStateOf<String?>(null) }

    fun reload() {
        patchedFiles = runCatching {
            StorageUtils.getPatchedFiles()
        }.getOrDefault(emptyList())
        checksums = emptyList()
    }

    LaunchedEffect(Unit) { reload() }

    fun computeChecksums() {
        if (computing) return

        computing = true

        scope.launch {
            val files = patchedFiles

            val result = withContext(Dispatchers.IO) {
                files.map { f ->
                    FileChecksum(
                        name = f.name,
                        sizeMb = f.length() / 1048576f,
                        sha256 = sha256Of(f)
                    )
                }
            }

            checksums = result
            computing = false
        }
    }

    fun cleanArtifacts() {
        scope.launch {
            val deleted = withContext(Dispatchers.IO) {
                StorageUtils.clearEngineArtifacts(ctx.cacheDir)
            }
            cleanedMessage =
                if (deleted > 0) "$deleted artifact(s) removed"
                else "Nothing to clean"
        }
    }

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "APK Toolkit",
                        color = AzlukOnBg,
                        fontWeight = FontWeight.SemiBold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            null,
                            tint = AzlukOnSurface
                        )
                    }
                },
                actions = {
                    IconButton(onClick = ::reload) {
                        Icon(Icons.Default.Refresh, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = AzlukSurface
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // ── Device profile ───────────────────────────────────────────
            item {
                SectionCard(title = "Device", icon = Icons.Default.DeveloperBoard) {
                    InfoRow(
                        Icons.Default.Memory,
                        "RAM",
                        "${profile.ramFreeMb} free / ${profile.ramTotalMb} MB"
                    )
                    InfoRow(
                        Icons.Default.Storage,
                        "Storage",
                        String.format("%.1f GB free", profile.storageFreeGb)
                    )
                    InfoRow(
                        Icons.Default.Speed,
                        "CPU",
                        "${profile.cpuCores} cores · ${profile.arch} · ${profile.performanceTier}"
                    )
                    InfoRow(
                        Icons.Default.Info,
                        "Android",
                        "API ${profile.androidApi}"
                    )
                    InfoRow(
                        Icons.Default.Fingerprint,
                        "Root",
                        if (profile.hasRoot) profile.rootMethod else "Not detected"
                    )
                }
            }

            // ── Warnings ─────────────────────────────────────────────────
            if (profile.warnings.isNotEmpty()) {
                item {
                    SectionCard(
                        title = "Warnings",
                        icon = Icons.Default.Warning,
                        tint = AzlukWarning
                    ) {
                        profile.warnings.forEach { w ->
                            Text(
                                "• $w",
                                color = AzlukOnSurface,
                                fontSize = 11.sp,
                                lineHeight = 15.sp
                            )
                        }
                    }
                }
            }

            // ── Maintenance ──────────────────────────────────────────────
            item {
                SectionCard(
                    title = "Maintenance",
                    icon = Icons.Default.DeleteSweep,
                    tint = AzlukWarning
                ) {
                    OutlinedButton(
                        onClick = ::cleanArtifacts,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, AzlukWarning.copy(.5f))
                    ) {
                        Icon(
                            Icons.Default.DeleteSweep,
                            null,
                            Modifier.size(14.dp),
                            tint = AzlukWarning
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "Clean scan/temp artifacts",
                            fontSize = 12.sp,
                            color = AzlukWarning
                        )
                    }

                    cleanedMessage?.let {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            it,
                            color = AzlukSuccess,
                            fontSize = 11.sp
                        )
                    }
                }
            }

            // ── Patched outputs + checksums ──────────────────────────────
            item {
                SectionCard(
                    title = "Patched outputs (${patchedFiles.size})",
                    icon = Icons.Default.Terminal
                ) {
                    if (patchedFiles.isEmpty()) {
                        Text(
                            "No patched files yet",
                            color = AzlukOnSurface,
                            fontSize = 11.sp
                        )
                    } else {
                        OutlinedButton(
                            onClick = ::computeChecksums,
                            enabled = !computing,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, AzlukBlue.copy(.5f))
                        ) {
                            if (computing) {
                                CircularProgressIndicator(
                                    Modifier.size(14.dp),
                                    color = AzlukBlue,
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    null,
                                    Modifier.size(14.dp),
                                    tint = AzlukBlue
                                )
                            }
                            Spacer(Modifier.width(6.dp))
                            Text(
                                if (computing) "Computing…" else "Compute SHA-256",
                                fontSize = 12.sp,
                                color = AzlukBlue
                            )
                        }
                    }
                }
            }

            checksums.forEach { fc ->
                item(key = fc.name) {
                    Surface(
                        color = AzlukSurface,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, AzlukSurfaceVar),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    fc.name,
                                    color = AzlukOnBg,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    String.format("%.1f MB", fc.sizeMb),
                                    color = AzlukOnSurface,
                                    fontSize = 11.sp
                                )
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                fc.sha256,
                                color = AzlukCyan,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                lineHeight = 12.sp
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Tap and hold the hash above to copy",
                                color = AzlukOnSurface.copy(.6f),
                                fontSize = 9.sp
                            )
                        }
                    }
                }
            }

            if (patchedFiles.isEmpty()) {
                item {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.FolderOff,
                            null,
                            tint = AzlukOnSurface,
                            modifier = Modifier.size(32.dp)
                        )
                    }
                }
            }
        }
    }
}

// ── Building blocks ──────────────────────────────────────────────────────────

@Composable
private fun SectionCard(
    title: String,
    icon: ImageVector,
    tint: androidx.compose.ui.graphics.Color = AzlukBlue,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit
) {
    Surface(
        color = AzlukSurface,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, AzlukSurfaceVar),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(icon, null, tint = tint, modifier = Modifier.size(16.dp))
                Text(
                    title,
                    color = AzlukOnBg,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun InfoRow(
    icon: ImageVector,
    label: String,
    value: String
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = AzlukOnSurface, modifier = Modifier.size(13.dp))
        Spacer(Modifier.width(8.dp))
        Text(
            label,
            color = AzlukOnSurface,
            fontSize = 11.sp,
            modifier = Modifier.width(64.dp)
        )
        Text(
            value,
            color = AzlukOnBg,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

private fun sha256Of(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")

    file.inputStream().buffered(64 * 1024).use { input ->
        val buffer = ByteArray(64 * 1024)

        while (true) {
            val read = input.read(buffer)

            if (read <= 0) break

            digest.update(buffer, 0, read)
        }
    }

    return digest.digest()
        .joinToString("") { "%02x".format(it) }
}
