package com.azluk.patcher.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.azluk.patcher.core.*
import com.azluk.patcher.engine.ApkEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

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

        scanJob = viewModelScope.launch(
            Dispatchers.IO + CoroutineName("BgScan")
        ) {
            _state.update { it.copy(isScanning = true) }

            /*
             * N worker coroutines pull from a shared index: ~3x the
             * throughput of the sequential walk on mid-range devices,
             * still throttled per worker by the pacing delay.
             */
            val next = AtomicInteger(0)
            val workerCount = SCAN_WORKERS.coerceAtLeast(1)

            val jobs = List(workerCount) {
                launch(Dispatchers.IO) {
                    while (isActive) {
                        val i = next.getAndIncrement()

                        if (i >= apps.size) break

                        val a = apps[i]
                        val fingerprint = apkFingerprint(a.apkPath)

                        if (cache.hasFresh(a.packageName, fingerprint)) {
                            continue
                        }

                        if (!File(a.apkPath).exists()) {
                            continue
                        }

                        try {
                            val (status, count) = engine.classify(a.packageName)

                            a.patchStatus = status
                            a.opportunityCount = count

                            cache.save(
                                a.packageName, status, count, fingerprint
                            )

                            _state.update { s ->
                                s.copy(apps = s.apps).applyFilter()
                            }
                        } catch (_: Exception) {
                            // One bad app must not stop the pass.
                        }

                        delay(SCAN_PACING_MS)
                    }
                }
            }

            jobs.joinAll()

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

    companion object {
        private const val SCAN_WORKERS = 3
        private const val SCAN_PACING_MS = 25L
    }
}
