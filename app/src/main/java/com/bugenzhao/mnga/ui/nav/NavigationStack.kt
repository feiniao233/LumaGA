package com.bugenzhao.mnga.ui.nav

/**
 * Pop to the exact entry at an index in the exposed route stack, excluding
 * undecodable entries. Repeated destinations/arguments still have distinct IDs.
 * Public single-entry pops avoid the typed-route overload, which cannot accept
 * a NavBackStackEntry. The live snapshot also protects against reentrant changes.
 */
internal fun <T> popToRouteEntry(
    index: Int,
    entries: () -> List<T>,
    isRoute: (T) -> Boolean,
    entryId: (T) -> String,
    pop: () -> Boolean,
) {
    val snapshot = entries()
    val target = snapshot.filter(isRoute).getOrNull(index) ?: return
    val targetId = entryId(target)
    // Bound work by the original stack, even if a callback unexpectedly navigates.
    repeat(snapshot.size) {
        val live = entries()
        val targetIndex = live.indexOfFirst { entryId(it) == targetId }
        if (targetIndex < 0 || targetIndex == live.lastIndex) return
        val expectedIds = live.dropLast(1).map(entryId)
        if (!pop()) return
        // Do not consume a new navigation started by a destination callback.
        if (entries().map(entryId) != expectedIds) return
    }
}
