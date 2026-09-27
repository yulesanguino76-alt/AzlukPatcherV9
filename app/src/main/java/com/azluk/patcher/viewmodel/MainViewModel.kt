package com.azluk.patcher.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.azluk.patcher.core.*
import com.azluk.patcher.engine.ApkEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

data class MainUiState(
    val apps: List<AppInfo>       = emptyList(),
    val filteredApps: List<AppInfo> = emptyList(),
    val query: String             = "",
    val filter: Int               = 0,            // 0=user,1=system,2=all
    val isLoading: Boolean        = false,
    val isScanning: Boolean       = false
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(MainUiState())
    val state: StateFlow<MainUiState> = _state.asStateFlow()

    private val engine = ApkEngine(app)
    private val cache  = ScanCache(app)
    private var scanJob: Job? = null

    fun load() {
        viewModelScope.launch {
            _state.update { it.copy(isLoading = true) }
            val apps = withContext(Dispatchers.IO) {
                AppScanner(getApplication()).getAll().also { list ->
                    list.forEach { a ->
                        if (cache.has(a.packageName)) {
                            a.patchStatus      = cache.getStatus(a.packageName)
                            a.opportunityCount = cache.getCount(a.packageName)
                        }
                    }
                }
            }
            _state.update { s ->
                s.copy(
                    apps      = apps,
                    isLoading = false
                ).applyFilter()
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
        scanJob = viewModelScope.launch(Dispatchers.IO + CoroutineName("BgScan")) {
            _state.update { it.copy(isScanning = true) }
            for (a in apps) {
                if (!isActive) break
                if (cache.has(a.packageName)) continue
                try {
                    val st  = engine.quickStatus(a.packageName)
                    val cnt = engine.quickCount(a.packageName)
                    a.patchStatus      = st
                    a.opportunityCount = cnt
                    cache.save(a.packageName, st, cnt)
                    _state.update { s -> s.copy(apps = s.apps).applyFilter() }
                } catch (_: Exception) {}
            }
            _state.update { it.copy(isScanning = false) }
        }
    }

    private fun MainUiState.applyFilter(): MainUiState {
        val qL = query.lowercase().trim()
        val filtered = apps.filter { a ->
            when (filter) {
                0 -> !a.isSystemApp
                1 ->  a.isSystemApp
                else -> true
            } && (qL.isEmpty() ||
                a.appName.lowercase().contains(qL) ||
                a.packageName.lowercase().contains(qL))
        }
        return copy(filteredApps = filtered)
    }
}
