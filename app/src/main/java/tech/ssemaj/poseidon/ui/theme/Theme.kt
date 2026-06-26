package tech.ssemaj.poseidon.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary              = BioluminescentTeal,
    onPrimary            = AbyssalNavy,
    primaryContainer     = MarineBlue,
    onPrimaryContainer   = BioluminescentTeal,
    secondary            = TridentGold,
    onSecondary          = AbyssalNavy,
    secondaryContainer   = Color(0xFF2A1F00),
    onSecondaryContainer = TridentGold,
    tertiary             = NeptuneSilver,
    onTertiary           = AbyssalNavy,
    background           = AbyssalNavy,
    onBackground         = TextPrimary,
    surface              = DeepBlue,
    onSurface            = TextPrimary,
    surfaceVariant       = MarineBlue,
    onSurfaceVariant     = TextSecondary,
    outline              = SurfaceBlue,
    outlineVariant       = MarineBlue,
)

private val LightColorScheme = lightColorScheme(
    primary              = LightPrimary,
    onPrimary            = Color.White,
    secondary            = LightSecondary,
    onSecondary          = Color.White,
    background           = LightBackground,
    onBackground         = LightOnBg,
    surface              = LightSurface,
    onSurface            = LightOnBg,
)

/**
 * Poseidon brand theme. Dynamic colour is intentionally disabled so the
 * deep-ocean palette is always shown; dark theme is the showcase default.
 */
@Composable
fun PoseidonTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme,
        typography  = Typography,
        content     = content,
    )
}
