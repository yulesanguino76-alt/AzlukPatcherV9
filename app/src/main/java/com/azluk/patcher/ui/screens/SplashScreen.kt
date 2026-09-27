package com.azluk.patcher.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import com.azluk.patcher.R
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PerformanceTier
import com.azluk.patcher.viewmodel.SystemProfile
import kotlinx.coroutines.delay

/**
 * Splash / system check screen.
 * Shows on first launch, runs SystemCheckViewModel.run(), then transitions
 * to HomeScreen. The logo rotates while the check runs, then snaps to done.
 * System check results are shown as animated rows — no mention of AI anywhere.
 */
@Composable
fun SplashScreen(
    profile:    SystemProfile,
    onComplete: () -> Unit
) {
    // Logo infinite rotation while loading, stops when ready
    val infiniteTransition = rememberInfiniteTransition(label = "spin")
    val spinAngle by infiniteTransition.animateFloat(
        initialValue   = 0f,
        targetValue    = 360f,
        animationSpec  = infiniteRepeatable(
            animation  = tween(1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "logo_spin"
    )

    // Overall content alpha — fade in on enter
    val contentAlpha by animateFloatAsState(
        targetValue   = 1f,
        animationSpec = tween(600),
        label = "fade_in"
    )

    // Navigate away once profile is ready + short delay for UX
    LaunchedEffect(profile.isReady) {
        if (profile.isReady) {
            delay(900)
            onComplete()
        }
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors  = listOf(AzlukSurface2, AzlukBg),
                    radius  = 1200f
                )
            )
            .alpha(contentAlpha),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(0.dp)
        ) {
            // ── Logo with rotation + glow ring ─────────────────────────────────
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(130.dp)) {
                // Outer glow pulse
                val pulseAlpha by infiniteTransition.animateFloat(
                    initialValue  = 0.15f,
                    targetValue   = 0.35f,
                    animationSpec = infiniteRepeatable(
                        animation  = tween(900, easing = FastOutSlowInEasing),
                        repeatMode = RepeatMode.Reverse
                    ),
                    label = "pulse"
                )
                Box(
                    Modifier
                        .size(120.dp)
                        .background(
                            Brush.radialGradient(listOf(AzlukBlue.copy(pulseAlpha), Color.Transparent)),
                            CircleShape
                        )
                )
                // Spinning logo — transparent PNG, no background
                Image(
                    painter            = painterResource(R.mipmap.ic_launcher_foreground),
                    contentDescription = "AzlukPatcher",
                    modifier           = Modifier
                        .size(96.dp)
                        .rotate(if (!profile.isReady) spinAngle else 0f)
                )
            }

            Spacer(Modifier.height(20.dp))

            // ── App name + version ─────────────────────────────────────────────
            Text(
                "AzlukPatcher",
                color      = AzlukOnBg,
                fontSize   = 28.sp,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = (-1).sp
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Surface(color = AzlukBlue, shape = RoundedCornerShape(5.dp)) {
                    Text("V8", color = Color.White, fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp))
                }
                Text("by Azluk", color = AzlukOnSurface, fontSize = 12.sp)
            }

            Spacer(Modifier.height(40.dp))

            // ── System check rows — animate in one by one ──────────────────────
            Surface(
                color  = AzlukSurface,
                shape  = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, AzlukSurfaceVar),
                modifier = Modifier.width(300.dp)
            ) {
                Column(
                    Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    CheckRow("System",     profile.androidApi > 0,
                        if (profile.androidApi > 0) "Android API ${profile.androidApi}" else "…")
                    CheckRow("CPU",        profile.cpuCores > 0,
                        if (profile.cpuCores > 0) "${profile.cpuCores} cores · ${profile.arch}" else "…")
                    CheckRow("RAM",        profile.ramTotalMb > 0,
                        if (profile.ramTotalMb > 0) "${profile.ramFreeMb}/${profile.ramTotalMb} MB free" else "…")
                    CheckRow("Storage",    profile.storageFreeGb > 0,
                        if (profile.storageFreeGb > 0) "${"%.1f".format(profile.storageFreeGb)} GB free" else "…")
                    CheckRow("Root",       profile.isReady,
                        if (!profile.isReady) "…"
                        else if (profile.hasRoot) "✓ ${profile.rootMethod}" else "Not rooted")
                    CheckRow("Performance", profile.isReady,
                        if (!profile.isReady) "…"
                        else when (profile.performanceTier) {
                            PerformanceTier.HIGH   -> "High — parallel patching enabled"
                            PerformanceTier.MEDIUM -> "Medium"
                            PerformanceTier.LOW    -> "Low — sequential mode"
                        })
                }
            }

            // Warnings
            if (profile.warnings.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    profile.warnings.forEach { w ->
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment     = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, null, tint = AzlukWarning,
                                modifier = Modifier.size(14.dp))
                            Text(w, color = AzlukWarning, fontSize = 11.sp)
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))

            // Progress indicator
            if (!profile.isReady) {
                LinearProgressIndicator(
                    modifier   = Modifier.width(200.dp).height(3.dp).clip(CircleShape),
                    color      = AzlukBlue,
                    trackColor = AzlukSurfaceVar
                )
                Spacer(Modifier.height(8.dp))
                Text("Checking system…", color = AzlukOnSurface, fontSize = 12.sp)
            } else {
                Text("Ready", color = AzlukSuccess, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
private fun CheckRow(label: String, done: Boolean, value: String) {
    val alpha by animateFloatAsState(
        targetValue   = if (done) 1f else 0.5f,
        animationSpec = tween(400),
        label         = "row_alpha_$label"
    )
    Row(
        Modifier.fillMaxWidth().alpha(alpha),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically
    ) {
        Text(label, color = AzlukOnSurface, fontSize = 12.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Text(value, color = if (done) AzlukOnBg else AzlukOnSurface,
                fontSize = 12.sp, fontWeight = if (done) FontWeight.SemiBold else FontWeight.Normal)
            if (done) {
                Icon(Icons.Default.CheckCircle, null, tint = AzlukSuccess, modifier = Modifier.size(14.dp))
            } else {
                CircularProgressIndicator(Modifier.size(12.dp), color = AzlukBlue, strokeWidth = 1.5.dp)
            }
        }
    }
}
