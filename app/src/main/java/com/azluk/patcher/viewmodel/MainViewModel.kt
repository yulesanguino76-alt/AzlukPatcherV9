package com.azluk.patcher.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.azluk.patcher.core.*
import com.azluk.patcher.engine.ApkEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

data class MainUiState(
    val apps: List<AppInfo> = emptyList(),
    val filteredApps: List<AppInfo> = emptyList(),
    val query: String = "",
    val filter: Int = 0, // 0=user,1=system,2=all
    val isLoading: Boolean = false,
    val isScanning: Boolean = false
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(MainUiState())
    val state: StateFlow<MainUiState> = _state.asStateFlow()

    private val engine = ApkEngine(app)
    private val cache = ScanCache(app)

    private var scanJob: Job? = null

    /**
     * Stable per-install fingerprint of an app's APK. lastModified()
     * changes on every app update, so cached badges keyed with it can
     * never survive an update — stale entries re-scan automatically.
     */
    private fun apkFingerprint(apkPath: String): Long {
        return runCatching {
            File(apkPath).lastModified()
        }.getOrDefault(0L)
    }

    fun load() {
        viewModelScope.launch {
            _state.update { it.copy(isLoading = true) }

            val apps = withContext(Dispatchers.IO) {
                AppScanner(getApplication()).getAll().also { list ->
                    list.forEach { a ->
                        val fingerprint = apkFingerprint(a.apkPath)

                        if (cache.hasFresh(a.packageName, fingerprint)) {
                            a.patchStatus = cache.getStatus(a.packageName)
                            a.opportunityCount = cache.getCount(a.packageName)
                        }
                    }
                }
            }

            _state.update { s ->
                s.copy(apps = apps, isLoading = false).applyFilter()
            }

            startBgScan(apps)
        }
    }

    /**
     * Force-refresh: clears the cache so every app re-scans, then
     * reloads the list.
     */
    fun refresh() {
        cache.clear()
        load()
    }

    fun setQuery(q: String) {
        _state.update { it.copy(query = q).applyFilter() }
    }

    fun setFilter(f: Int) {
        _state.update { it.copy(filter = f).applyFilter() }
    }

    private fun startBgScan(apps: List<AppInfo>) {
        scanJob?.cancel()

        scanJob = viewModelScope.launch(Dispatchers.IO + CoroutineName("BgScan")) {
            _state.update { it.copy(isScanning = true) }

            for (a in apps) {
                if (!isActive) break

                /*
                 * Fresh cache hit (fingerprint matches the current APK)
                 * = badge still valid, skip.
                 */
                val fingerprint = apkFingerprint(a.apkPath)

                if (cache.hasFresh(a.packageName, fingerprint)) {
                    continue
                }

                val apk = File(a.apkPath)

                if (!apk.exists()) {
                    continue
                }

                try {
                    /*
                     * One scan feeds both status and count — the previous
                     * quickStatus + quickCount pair parsed the whole APK
                     * twice per app.
                     */
                    val results = runCatching {
                        engine.scan(a.packageName)
                    }.getOrDefault(emptyList())

                    val st = when {
                        results.isEmpty()  -> PatchStatus.UNKNOWN
                        results.size >= 3  -> PatchStatus.PATCHABLE
                        else               -> PatchStatus.LIKELY
                    }

                    a.patchStatus = st
                    a.opportunityCount = results.size

                    cache.save(
                        a.packageName,
                        st,
                        results.size,
                        fingerprint
                    )

                    _state.update { s -> s.copy(apps = s.apps).applyFilter() }
                } catch (_: Exception) {
                    /*
                     * One bad app must not stop the background pass.
                     */
                }

                /*
                 * Keep the pass cooperative — parsing APKs back to back
                 * can starve the UI thread's IO on low-end devices.
                 */
                delay(25)
            }

            _state.update { it.copy(isScanning = false) }
        }
    }

    private fun MainUiState.applyFilter(): MainUiState {
        val qL = query.lowercase().trim()

        val filtered = apps.filter { a ->
            when (filter) {
                0 -> !a.isSystemApp
                1 -> a.isSystemApp
                else -> true
            } && (qL.isEmpty() ||
                    a.appName.lowercase().contains(qL) ||
                    a.packageName.lowercase().contains(qL))
        }

        return copy(filteredApps = filtered)
    }
}
