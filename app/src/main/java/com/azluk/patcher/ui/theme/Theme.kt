package com.azluk.patcher.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight

// AzlukPatcher V9 — Midnight Hacker palette (refined)
val AzlukBlue       = Color(0xFF4D8BFF)
val AzlukBlueDim    = Color(0xFF2455C7)
val AzlukBlueGlow   = Color(0xFF82AEFF)
val AzlukCyan       = Color(0xFF38D8F0)
val AzlukBg         = Color(0xFF060810)
val AzlukSurface    = Color(0xFF0C1119)
val AzlukSurface2   = Color(0xFF111A28)
val AzlukSurfaceVar = Color(0xFF192336)
val AzlukOnBg       = Color(0xFFF0F5FF)
val AzlukOnSurface  = Color(0xFF8A9DBB)
val AzlukError      = Color(0xFFFF4466)
val AzlukSuccess    = Color(0xFF2EEAA0)
val AzlukWarning    = Color(0xFFFFB340)

private val DarkColorScheme = darkColorScheme(
    primary          = AzlukBlue,
    onPrimary        = Color.White,
    primaryContainer = AzlukBlueDim,
    secondary        = AzlukCyan,
    background       = AzlukBg,
    surface          = AzlukSurface,
    surfaceVariant   = AzlukSurfaceVar,
    onBackground     = AzlukOnBg,
    onSurface        = AzlukOnSurface,
    error            = AzlukError,
    onError          = Color.White
)

@Composable
fun AzlukTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(
            titleLarge = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
            titleMedium = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
            labelLarge = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold)
        ),
        content = content
    )
}
