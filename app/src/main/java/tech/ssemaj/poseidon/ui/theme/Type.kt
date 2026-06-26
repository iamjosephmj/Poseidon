package tech.ssemaj.poseidon.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Poseidon type scale.
 *
 * Monospace is the primary display face — the app is a security instrument, and
 * monospace reads like a terminal / system tool (intentional signal, not decoration).
 * Descriptions use the default sans-serif for legibility contrast.
 */
val Typography = Typography(
    // "POSEIDON" display title — wide-spaced, commanding
    displayLarge = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.Bold,
        fontSize      = 34.sp,
        lineHeight    = 38.sp,
        letterSpacing = 6.sp,
    ),
    // Section eyebrow labels ("LIVE EGRESS LOG")
    headlineMedium = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.SemiBold,
        fontSize      = 11.sp,
        lineHeight    = 16.sp,
        letterSpacing = 2.sp,
    ),
    // Tier card titles ("JVM ADAPTERS")
    titleMedium = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.Bold,
        fontSize      = 11.sp,
        lineHeight    = 14.sp,
        letterSpacing = 1.5.sp,
    ),
    // Tier one-line descriptions
    bodyMedium = TextStyle(
        fontFamily    = FontFamily.Default,
        fontWeight    = FontWeight.Normal,
        fontSize      = 12.sp,
        lineHeight    = 18.sp,
        letterSpacing = 0.sp,
    ),
    // Log row text (host / path)
    bodySmall = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.Normal,
        fontSize      = 11.sp,
        lineHeight    = 16.sp,
        letterSpacing = 0.sp,
    ),
    // ALLOW / BLOCK verdict labels; tier badges
    labelSmall = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.Bold,
        fontSize      = 10.sp,
        lineHeight    = 12.sp,
        letterSpacing = 1.sp,
    ),
    // Mode chip / event count
    labelMedium = TextStyle(
        fontFamily    = FontFamily.Monospace,
        fontWeight    = FontWeight.Medium,
        fontSize      = 11.sp,
        lineHeight    = 14.sp,
        letterSpacing = 0.8.sp,
    ),
    // Tagline / body copy
    bodyLarge = TextStyle(
        fontFamily    = FontFamily.Default,
        fontWeight    = FontWeight.Normal,
        fontSize      = 14.sp,
        lineHeight    = 20.sp,
        letterSpacing = 0.15.sp,
    ),
)
