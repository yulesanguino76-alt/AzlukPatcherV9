package com.azluk.patcher.ui.screens

import android.app.PendingIntent
import android.content.*
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.*
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.InstallState
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.utils.StorageUtils
import com.azluk.patcher.viewmodel.AiDiagnosis
import com.azluk.patcher.viewmodel.PatchViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchedFilesScreen(
    navController: NavController,
    vm: PatchViewModel = viewModel()
) {
    val ctx     = LocalContext.current
    val state   by vm.state.collectAsState()
    var files   by remember { mutableStateOf<List<File>>(emptyList()) }
    val fmt     = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())

    // Track which file is currently being installed (for per-card state)
    var activeFile by remember { mutableStateOf<String?>(null) }

    // Log lines shown in the install log panel
    val installLog = remember { mutableStateListOf<String>() }
    var showLog    by remember { mutableStateOf(false) }
    val logState   = rememberLazyListState()

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val result = runCatching { StorageUtils.getPatchedFiles() }.getOrDefault(emptyList())
            withContext(Dispatchers.Main) { files = result }
        }
    }

    // Auto-scroll log
    LaunchedEffect(installLog.size) {
        if (installLog.isNotEmpty()) logState.animateScrollToItem(installLog.size - 1)
    }

    // Install broadcast receiver — fixed all 3 bugs
    DisposableEffect(Unit) {
        val filter   = IntentFilter("com.azluk.patcher.INSTALL_RESULT_LOCAL")
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
                val msg    = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                when (status) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        installLog.add("Waiting for user confirmation...")
                        val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                            i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                        else @Suppress("DEPRECATION") i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        confirm?.let { ctx.startActivity(it) }
                    }
                    else -> {
                        vm.onInstallResult(status, msg)
                        installLog.add(if (status == PackageInstaller.STATUS_SUCCESS)
                            "[SUCCESS] Installation complete"
                        else "[ERROR] Install failed: ${msg ?: "code $status"}")
                        activeFile = null
                    }
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            ctx.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else
            ctx.registerReceiver(receiver, filter)
        onDispose { ctx.unregisterReceiver(receiver) }
    }

    fun refresh() {
        files = runCatching { StorageUtils.getPatchedFiles() }.getOrDefault(emptyList())
    }

    fun doInstallWithLog(file: File) {
        activeFile = file.absolutePath
        installLog.clear()
        showLog    = true
        installLog.add("Starting installation: ${file.name}")
        installLog.add("Size: ${"%.1f".format(file.length() / 1048576f)} MB")
        installLog.add("Opening PackageInstaller session...")
        try {
            val pi        = ctx.packageManager.packageInstaller
            val params    = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            val sessionId = pi.createSession(params)
            val session   = pi.openSession(sessionId)
            installLog.add("Session created: #$sessionId")
            installLog.add("Writing APK data...")
            FileInputStream(file).use { fis ->
                session.openWrite("base.apk", 0, file.length()).use { os ->
                    fis.copyTo(os, 65536)
                    session.fsync(os)
                }
            }
            installLog.add("APK data written successfully")
            val receiverIntent = Intent("com.azluk.patcher.INSTALL_RESULT").apply {
                setPackage(ctx.packageName)   // FIX: explicit package
            }
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            else PendingIntent.FLAG_UPDATE_CURRENT
            val pending = PendingIntent.getBroadcast(ctx, sessionId, receiverIntent, flags)
            session.commit(pending.intentSender)   // FIX: commit before close
            session.close()
            installLog.add("Session committed — waiting for Android installer...")
        } catch (e: Exception) {
            installLog.add("[ERROR] ${e.message}")
            activeFile = null
            vm.onInstallResult(-1, e.message)
        }
    }

    Scaffold(
        containerColor = AzlukBg,
        topBar = {
            TopAppBar(
                title = { Text("Patched Files", color = AzlukOnBg, fontWeight = FontWeight.SemiBold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = AzlukOnSurface)
                    }
                },
                actions = {
                    IconButton(onClick = ::refresh) {
                        Icon(Icons.Default.Refresh, null, tint = AzlukOnSurface)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AzlukSurface)
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {

            // ── Install log panel ─────────────────────────────────────────────
            AnimatedVisibility(
                visible = showLog,
                enter   = expandVertically() + fadeIn(),
                exit    = shrinkVertically() + fadeOut()
            ) {
                Surface(
                    color  = AzlukSurface,
                    border = BorderStroke(1.dp, AzlukSurfaceVar),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(12.dp)) {
                        // Log header
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment     = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment     = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                if (activeFile != null) {
                                    CircularProgressIndicator(
                                        Modifier.size(14.dp), color = AzlukBlue, strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Terminal, null,
                                        tint = AzlukOnSurface, modifier = Modifier.size(14.dp))
                                }
                                Text("Install Log", color = AzlukOnSurface,
                                    fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                            IconButton(onClick = { showLog = false }, modifier = Modifier.size(28.dp)) {
                                Icon(Icons.Default.Close, null, tint = AzlukOnSurface, modifier = Modifier.size(16.dp))
                            }
                        }

                        Spacer(Modifier.height(6.dp))

                        // Log lines
                        Box(Modifier.heightIn(max = 160.dp)) {
                            LazyColumn(state = logState) {
                                items(installLog) { line ->
                                    Text(
                                        line,
                                        color = when {
                                            line.contains("[SUCCESS]") -> AzlukSuccess
                                            line.contains("[ERROR]")   -> AzlukError
                                            line.startsWith("Session") || line.startsWith("APK") -> AzlukCyan
                                            else -> AzlukOnSurface
                                        },
                                        fontSize   = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        lineHeight = 14.sp
                                    )
                                }
                            }
                        }

                        // AI suggestion — appears seamlessly after install failure
                        val ai = state.aiDiagnosis
                        AnimatedVisibility(ai.loading || ai.suggestion.isNotEmpty()) {
                            Column(Modifier.padding(top = 8.dp)) {
                                HorizontalDivider(color = AzlukSurfaceVar, thickness = .5.dp)
                                Spacer(Modifier.height(8.dp))
                                if (ai.loading) {
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        verticalAlignment     = Alignment.CenterVertically
                                    ) {
                                        CircularProgressIndicator(Modifier.size(12.dp), color = AzlukBlue, strokeWidth = 1.5.dp)
                                        Text("Analyzing error…", color = AzlukOnSurface, fontSize = 11.sp)
                                    }
                                } else if (ai.suggestion.isNotEmpty()) {
                                    // No "AI" label — suggestion appears as plain helpful text
                                    Surface(
                                        color  = AzlukBlue.copy(.06f),
                                        shape  = RoundedCornerShape(8.dp)
                                    ) {
                                        Row(
                                            Modifier.fillMaxWidth().padding(10.dp),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            Icon(Icons.Default.Lightbulb, null,
                                                tint = AzlukBlue, modifier = Modifier.size(14.dp))
                                            Text(ai.suggestion, color = AzlukOnBg,
                                                fontSize = 11.sp, lineHeight = 16.sp)
                                        }
                                    }
                                }
                            }
                        }

                        // Install result action
                        when (val ist = state.installState) {
                            is InstallState.Success -> {
                                Spacer(Modifier.height(8.dp))
                                Row(
                                    verticalAlignment     = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(Icons.Default.CheckCircle, null,
                                        tint = AzlukSuccess, modifier = Modifier.size(16.dp))
                                    Text("Installed successfully!", color = AzlukSuccess,
                                        fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                                }
                            }
                            is InstallState.Failure -> {
                                if (ist.canRetry && activeFile == null) {
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick  = { activeFile?.let { doInstallWithLog(File(it)) } },
                                        modifier = Modifier.fillMaxWidth(),
                                        shape    = RoundedCornerShape(10.dp),
                                        colors   = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                                    ) {
                                        Icon(Icons.Default.Refresh, null, Modifier.size(14.dp))
                                        Spacer(Modifier.width(6.dp))
                                        Text("Retry Install", fontSize = 12.sp)
                                    }
                                }
                            }
                            else -> {}
                        }
                    }
                }
            }

            // ── File list ─────────────────────────────────────────────────────
            if (files.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.FolderOff, null, tint = AzlukOnSurface, modifier = Modifier.size(48.dp))
                        Spacer(Modifier.height(12.dp))
                        Text("No patched files yet", color = AzlukOnSurface)
                    }
                }
            } else {
                LazyColumn(
                    contentPadding      = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(files, key = { it.absolutePath }) { file ->
                        val isInstalling = activeFile == file.absolutePath
                        val guessedPkg   = remember(file.name) {
                            file.nameWithoutExtension.removeSuffix("_azluk_v8").removeSuffix("_azluk")
                        }
                        val isInstalled = remember(guessedPkg) {
                            runCatching { ctx.packageManager.getPackageInfo(guessedPkg, 0); true }
                                .getOrDefault(false)
                        }
                        FileCard(
                            file         = file,
                            date         = fmt.format(Date(file.lastModified())),
                            isInstalling = isInstalling,
                            isInstalled  = isInstalled,
                            onInstall    = { doInstallWithLog(file) },
                            onReinstall  = {
                                ctx.startActivity(Intent(Intent.ACTION_DELETE,
                                    Uri.parse("package:$guessedPkg")).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                })
                                Toast.makeText(ctx, "Uninstall the app, then tap Install again", Toast.LENGTH_LONG).show()
                            },
                            onDelete     = { file.delete(); refresh() }
                        )
                    }
                }
            }
        }
    }
}

// ── File card ─────────────────────────────────────────────────────────────────

@Composable
private fun FileCard(
    file:         File,
    date:         String,
    isInstalling: Boolean,
    isInstalled:  Boolean,
    onInstall:    () -> Unit,
    onReinstall:  () -> Unit,
    onDelete:     () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Surface(
        color    = AzlukSurface,
        shape    = RoundedCornerShape(14.dp),
        border   = BorderStroke(1.dp, if (isInstalling) AzlukBlue.copy(.3f) else AzlukSurfaceVar),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column {
            Row(
                Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Icon with installing indicator
                Surface(
                    color  = if (isInstalling) AzlukBlue.copy(.15f) else AzlukBlue.copy(.08f),
                    shape  = RoundedCornerShape(10.dp)
                ) {
                    Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                        if (isInstalling) {
                            CircularProgressIndicator(Modifier.size(22.dp), color = AzlukBlue, strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Default.Android, null, tint = AzlukBlue, modifier = Modifier.size(24.dp))
                        }
                    }
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        file.name,
                        color      = AzlukOnBg,
                        fontSize   = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        fontFamily = FontFamily.Monospace,
                        maxLines   = 1,
                        overflow   = TextOverflow.Ellipsis
                    )
                    Text(
                        "${"%.1f".format(file.length() / 1048576f)} MB · $date",
                        color    = AzlukOnSurface,
                        fontSize = 11.sp
                    )
                    if (isInstalling) {
                        Spacer(Modifier.height(3.dp))
                        Text("Installing...", color = AzlukBlue, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                    } else if (isInstalled) {
                        Spacer(Modifier.height(3.dp))
                        Surface(color = AzlukSuccess.copy(.1f), shape = RoundedCornerShape(4.dp)) {
                            Text("Installed", color = AzlukSuccess, fontSize = 10.sp,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                        }
                    }
                }
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        null, tint = AzlukOnSurface
                    )
                }
            }

            // Expandable action row
            AnimatedVisibility(expanded) {
                Row(
                    Modifier
                    .fillMaxWidth()
                        .padding(start = 12.dp, end = 12.dp, bottom = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Install
                    Button(
                        onClick  = { expanded = false; onInstall() },
                        enabled  = !isInstalling,
                        modifier = Modifier.weight(1f),
                        shape    = RoundedCornerShape(10.dp),
                        colors   = ButtonDefaults.buttonColors(containerColor = AzlukBlue)
                    ) {
                        Icon(Icons.Default.InstallMobile, null, Modifier.size(15.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("Install", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }

                    // Reinstall if already installed
                    if (isInstalled) {
                        OutlinedButton(
                            onClick  = { expanded = false; onReinstall() },
                            enabled  = !isInstalling,
                            modifier = Modifier.weight(1.2f),
                            shape    = RoundedCornerShape(10.dp),
                            border   = BorderStroke(1.dp, AzlukWarning.copy(.5f))
                        ) {
                            Icon(Icons.Default.SwapHoriz, null, Modifier.size(14.dp), tint = AzlukWarning)
                            Spacer(Modifier.width(4.dp))
                            Text("Reinstall", fontSize = 12.sp, color = AzlukWarning, fontWeight = FontWeight.SemiBold)
                        }
                    }

                    // Delete
                    IconButton(onClick = onDelete, modifier = Modifier.size(40.dp)) {
                        Icon(Icons.Default.DeleteOutline, null, tint = AzlukError, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
    }
}
