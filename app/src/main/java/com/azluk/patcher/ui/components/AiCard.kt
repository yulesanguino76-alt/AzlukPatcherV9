package com.azluk.patcher.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.AiDiagnosis

/**
 * Self-contained AI diagnosis card. Renders nothing when idle — safe to
 * drop anywhere in a Scaffold without conditionals.
 */
@Composable
fun AiCard(
    diagnosis: AiDiagnosis,
    onDismiss: () -> Unit
) {
    val visible = diagnosis.loading ||
            diagnosis.suggestion.isNotEmpty() ||
            diagnosis.error.isNotEmpty()

    AnimatedVisibility(visible, enter = expandVertically() + fadeIn()) {
        Surface(
            color = when {
                diagnosis.error.isNotEmpty() -> AzlukError.copy(.06f)
                else                         -> AzlukBlue.copy(.06f)
            },
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                Modifier.padding(10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (diagnosis.loading) {
                    CircularProgressIndicator(
                        Modifier.size(14.dp), color = AzlukBlue, strokeWidth = 1.5.dp)
                } else {
                    Icon(
                        Icons.Default.Lightbulb, null,
                        tint = if (diagnosis.error.isNotEmpty()) AzlukError else AzlukBlue,
                        modifier = Modifier.size(14.dp)
                    )
                }
                Column(Modifier.weight(1f)) {
                    if (diagnosis.loading) {
                        Text("Analyzing failure…", color = AzlukOnSurface, fontSize = 11.sp)
                    }
                    diagnosis.suggestion.takeIf { it.isNotEmpty() }?.let {
                        Text(it, color = AzlukOnBg, fontSize = 11.sp, lineHeight = 16.sp)
                    }
                    diagnosis.error.takeIf { it.isNotEmpty() }?.let {
                        Text(it, color = AzlukError, fontSize = 11.sp)
                    }
                }
                if (!diagnosis.loading) {
                    TextButton(onClick = onDismiss, contentPadding = PaddingValues(0.dp)) {
                        Text("OK", fontSize = 11.sp, color = AzlukOnSurface)
                    }
                }
            }
        }
    }
}
