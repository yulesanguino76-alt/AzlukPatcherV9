package com.azluk.patcher.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.*
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.*
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PatchViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportFilesScreen(
    navController: NavController,
    vm: PatchViewModel = viewModel(LocalContext.current as ComponentActivity)
) {
    val state by vm.state.collectAsStateWithLifecycle()

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { vm.importAndScan(it) }
    }

    val detectedTypes = state.scanResults
        .mapNotNull { runCatching { PatchType.valueOf(it.patchType) }.getOrNull() }.toSet()

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = { Text("Patch a File", color = AzlukOnBg, fontWeight = FontWeight.SemiBold) },
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
                    Button(
                        onClick  = { vm.resetPatch(); navController.navigate("patchlog/import") },
                        enabled  = state.selectedPatches.isNotEmpty() && !state.isScanning,
                        modifier = Modifier.fillMaxWidth(),
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
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Import hero
            Surface(
                color    = AzlukBlue.copy(.08f),
                shape    = RoundedCornerShape(14.dp),
                border   = BorderStroke(1.dp, AzlukBlue.copy(.2f)),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = !state.isScanning) { filePicker.launch("*/*") }
            ) {
                Column(
                    Modifier.fillMaxWidth().padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Default.FolderZip, null,
                        tint = AzlukBlue, modifier = Modifier.size(36.dp)
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Import APK / XAPK / APKM / APKS",
                        color = AzlukBlue, fontWeight = FontWeight.SemiBold, fontSize = 14.sp
                    )
                    Text(
                        "Splits included — no more missing-splits errors",
                        color = AzlukOnSurface, fontSize = 11.sp
                    )
                }
            }

            if (state.isScanning) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(Modifier.size(16.dp), color = AzlukBlue, strokeWidth = 2.dp)
                    Text("Scanning…", color = AzlukOnSurface, fontSize = 12.sp)
                }
            }

            state.scanError?.let { err ->
                Surface(
                    color = AzlukError.copy(.08f),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, AzlukError.copy(.25f))
                ) {
                    Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, null, tint = AzlukError, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Scan failed: $err", color = AzlukError, fontSize = 12.sp)
                    }
                }
            }

            state.scannedFileName?.let { name ->
                Surface(
                    color = AzlukSurface,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, AzlukSurfaceVar)
                ) {
                    Column(Modifier.fillMaxWidth().padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.InsertDriveFile, null, tint = AzlukBlue, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(name, color = AzlukOnBg, fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Spacer(Modifier.height(10.dp))

                        if (detectedTypes.isEmpty()) {
                            Text("No structural targets detected in this file.",
                                color = AzlukOnSurface, fontSize = 11.sp)
                        } else {
                            Text("${detectedTypes.size} patches available:",
                                color = AzlukSuccess, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(6.dp))
                            detectedTypes.forEach { type ->
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.padding(vertical = 3.dp)
                                ) {
                                    Checkbox(
                                        checked = type in state.selectedPatches,
                                        onCheckedChange = { vm.togglePatch(type) }
                                    )
                                    Text(type.displayName, color = AzlukOnBg, fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
