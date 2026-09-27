package com.azluk.patcher.core

import android.content.Context
import org.json.JSONArray

object PatchPackCatalog {
    fun load(context: Context): List<PatchPack> {
        val json = context.assets.open("azluk_patchpacks.json")
            .bufferedReader().use { it.readText() }
        val arr = JSONArray(org.json.JSONObject(json).getJSONArray("packs").toString())
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                add(
                    PatchPack(
                        id = o.getString("id"),
                        name = o.getString("name"),
                        icon = o.getString("icon"),
                        category = o.getString("category"),
                        description = o.getString("description")
                    )
                )
            }
        }
    }
}
