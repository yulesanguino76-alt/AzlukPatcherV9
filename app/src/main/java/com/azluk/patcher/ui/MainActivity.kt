package com.azluk.patcher.ui

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.compose.*
import androidx.navigation.navArgument
import com.azluk.patcher.ui.screens.*
import com.azluk.patcher.ui.theme.AzlukTheme
import com.azluk.patcher.viewmodel.SystemCheckViewModel

class MainActivity : ComponentActivity() {

    private val permReady = mutableStateOf(false)
    private val sysVm: SystemCheckViewModel by viewModels()

    private val permLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permReady.value = hasPermission() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        permReady.value = hasPermission()
        sysVm.run()
        setContent {
            AzlukTheme {
                val ready by permReady
                if (ready) AzlukApp(sysVm) else PermissionScreen { requestPerm() }
            }
        }
        if (!hasPermission()) requestPerm()
    }

    override fun onResume() { super.onResume(); permReady.value = hasPermission() }

    private fun hasPermission() =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            Environment.isExternalStorageManager()
        else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun requestPerm() {
        if (hasPermission()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))) }
                .onFailure { runCatching { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) } }
        } else {
            permLauncher.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
        }
    }
}

@Composable
private fun AzlukApp(sysVm: SystemCheckViewModel) {
    val profile by sysVm.profile.collectAsStateWithLifecycle()
    val nav = rememberNavController()
    var splashDone by remember { mutableStateOf(false) }

    if (!splashDone) {
        SplashScreen(profile = profile, onComplete = { splashDone = true })
    } else {
        NavHost(nav, startDestination = "home", modifier = Modifier.fillMaxSize()) {
            composable("home")    { HomeScreen(nav) }
            composable("patched") { PatchedFilesScreen(nav) }
            composable("tools")   { ToolsScreen(nav) }
            composable(
                "patch/{pkg}",
                arguments = listOf(navArgument("pkg") { type = NavType.StringType })
            ) { back ->
                val pkg = back.arguments?.getString("pkg") ?: return@composable
                PatchScreen(pkg = pkg, navController = nav)
            }
            // Separate log + install screen — navigated to after choosing patch options
            composable(
                "patchlog/{pkg}",
                arguments = listOf(navArgument("pkg") { type = NavType.StringType })
            ) { back ->
                val pkg = back.arguments?.getString("pkg") ?: return@composable
                PatchLogScreen(pkg = pkg, navController = nav)
            }
        }
    }
}

@Composable
private fun PermissionScreen(onRequest: () -> Unit) {
    Column(
        Modifier.fillMaxSize().systemBarsPadding().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Storage Access Required", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text("AzlukPatcher needs full storage access to read and patch APK files.")
        Spacer(Modifier.height(24.dp))
        Button(onClick = onRequest) { Text("Grant Access") }
    }
}

// ── InstallReceiver — all 3 bugs fixed ───────────────────────────────────────
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
        val msg    = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        ctx.sendBroadcast(Intent("com.azluk.patcher.INSTALL_RESULT_LOCAL").apply {
            setPackage(ctx.packageName)
            putExtra(PackageInstaller.EXTRA_STATUS, status)
            putExtra(PackageInstaller.EXTRA_STATUS_MESSAGE, msg)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                    ?.let { putExtra(Intent.EXTRA_INTENT, it) }
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    ?.let { putExtra(Intent.EXTRA_INTENT, it) }
            }
        })
    }
}
