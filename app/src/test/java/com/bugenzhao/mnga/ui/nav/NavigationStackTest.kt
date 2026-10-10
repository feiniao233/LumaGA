package com.bugenzhao.mnga.ui.nav

import org.junit.Assert.assertEquals
import org.junit.Test

/** Exercises exact-entry popping without Android or a navigation runtime. */
class NavigationStackTest {
    @Test
    fun `index zero retains the root and removes every later entry`() {
        val stack = FakeStack(root, entry("about"), entry("settings"))

        stack.popTo(0)

        assertEquals(listOf(root), stack.entries)
        assertEquals(2, stack.popCalls)
    }

    @Test
    fun `earlier identical destination is retained by entry ID`() {
        val first = entry("first", "topic-details", "topicId=42")
        val duplicate = entry("duplicate", "topic-details", "topicId=42")
        val stack = FakeStack(root, first, entry("about"), duplicate, entry("settings"))

        stack.popTo(1)

        assertEquals(listOf(root, first), stack.entries)
        assertEquals(3, stack.popCalls)
    }

    @Test
    fun `later identical destination does not pop its earlier occurrence`() {
        val first = entry("first", "topic-details", "topicId=42")
        val duplicate = entry("duplicate", "topic-details", "topicId=42")
        val about = entry("about")
        val stack = FakeStack(root, first, about, duplicate, entry("settings"))

        stack.popTo(3)

        assertEquals(listOf(root, first, about, duplicate), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `same destination with different arguments has independent route indexes`() {
        val first = entry("first", "topic-details", "topicId=41")
        val second = entry("second", "topic-details", "topicId=42")
        val third = entry("third", "topic-details", "topicId=41")
        val stack = FakeStack(root, first, second, third)

        stack.popTo(2)

        assertEquals(listOf(root, first, second), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `negative index leaves the entire stack unchanged`() {
        val about = entry("about")
        val stack = FakeStack(root, about)

        stack.popTo(-1)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `out of range index leaves the entire stack unchanged`() {
        val about = entry("about")
        val stack = FakeStack(root, about)

        stack.popTo(2)
        stack.popTo(Int.MAX_VALUE)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `already current target does not pop`() {
        val about = entry("about")
        val stack = FakeStack(root, about)

        stack.popTo(1)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `sole root entry does not pop`() {
        val stack = FakeStack(root)

        stack.popTo(0)

        assertEquals(listOf(root), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `empty stack does not pop`() {
        val stack = FakeStack()

        stack.popTo(0)

        assertEquals(emptyList<Entry>(), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `undecodable entry before root does not shift exposed indexes`() {
        val unknown = entry("unknown", route = null)
        val stack = FakeStack(unknown, root, entry("about"))

        stack.popTo(0)

        assertEquals(listOf(unknown, root), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `undecodable entry between routes does not shift target index`() {
        val unknown = entry("unknown", route = null)
        val about = entry("about")
        val stack = FakeStack(root, unknown, about, entry("settings"))

        stack.popTo(1)

        assertEquals(listOf(root, unknown, about), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `undecodable entries after target are also removed`() {
        val about = entry("about")
        val stack = FakeStack(
            root,
            about,
            entry("unknown-one", route = null),
            entry("settings"),
            entry("unknown-two", route = null),
        )

        stack.popTo(1)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(3, stack.popCalls)
    }

    @Test
    fun `index valid only in unfiltered stack does not pop`() {
        val unknown = entry("unknown", route = null)
        val stack = FakeStack(root, unknown)

        stack.popTo(1)

        assertEquals(listOf(root, unknown), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `stack containing only undecodable entries does not pop`() {
        val unknown = entry("unknown", route = null)
        val stack = FakeStack(unknown)

        stack.popTo(0)

        assertEquals(listOf(unknown), stack.entries)
        assertEquals(0, stack.popCalls)
    }

    @Test
    fun `failed pop stops without retrying`() {
        val about = entry("about")
        val stack = FakeStack(root, about)
        stack.onPop = { false }

        stack.popTo(0)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `false result stops even if callback changed the stack`() {
        val about = entry("about")
        val stack = FakeStack(root, about, entry("settings"))
        stack.onPop = {
            stack.entries.removeAt(stack.entries.lastIndex)
            false
        }

        stack.popTo(0)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `successful pop reporting no progress stops without retrying`() {
        val about = entry("about")
        val stack = FakeStack(root, about)
        stack.onPop = { true }

        stack.popTo(0)

        assertEquals(listOf(root, about), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `target removed by reentrant callback stops before another pop`() {
        val replacement = entry("replacement")
        val replacementTop = entry("replacement-top")
        val stack = FakeStack(root, entry("about"), entry("settings"))
        stack.onPop = {
            stack.entries.clear()
            stack.entries.addAll(listOf(replacement, replacementTop))
            true
        }

        stack.popTo(0)

        assertEquals(listOf(replacement, replacementTop), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `replacement with equal route and arguments is not mistaken for target`() {
        val target = entry("original", "topic-details", "topicId=42")
        val replacement = entry("replacement", "topic-details", "topicId=42")
        val replacementTop = entry("replacement-top")
        val stack = FakeStack(root, target, entry("settings"))
        stack.onPop = {
            stack.entries.clear()
            stack.entries.addAll(listOf(root, replacement, replacementTop))
            true
        }

        stack.popTo(1)

        assertEquals(listOf(root, replacement, replacementTop), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test
    fun `stack cleared during pop stops safely`() {
        val stack = FakeStack(root, entry("about"))
        stack.onPop = {
            stack.entries.clear()
            true
        }

        stack.popTo(0)

        assertEquals(emptyList<Entry>(), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    @Test(timeout = 1000)
    fun `reentrant navigation stops before popping a newly pushed screen`() {
        val stack = FakeStack(root, entry("about"), entry("settings"))
        stack.onPop = {
            stack.entries.removeAt(stack.entries.lastIndex)
            stack.entries.add(entry("reentrant-${stack.popCalls}"))
            true
        }

        stack.popTo(0)

        assertEquals(1, stack.popCalls)
        assertEquals(root, stack.entries.first())
        assertEquals("reentrant-1", stack.entries.last().id)
    }

    @Test
    fun `reentrant replacement below expected top stops before another pop`() {
        val about = entry("about")
        val replacement = entry("replacement")
        val stack = FakeStack(root, entry("first"), about, entry("settings"))
        stack.onPop = {
            stack.entries.removeAt(stack.entries.lastIndex)
            stack.entries[1] = replacement
            true
        }

        stack.popTo(0)

        assertEquals(listOf(root, replacement, about), stack.entries)
        assertEquals(1, stack.popCalls)
    }

    private data class Entry(val id: String, val route: String?, val arguments: String?)

    private class FakeStack(vararg initial: Entry) {
        val entries = initial.toMutableList()
        var popCalls = 0
        var onPop: () -> Boolean = {
            entries.removeAt(entries.lastIndex)
            entries.isNotEmpty()
        }

        fun popTo(index: Int) {
            popToRouteEntry(
                index = index,
                entries = { entries.toList() },
                isRoute = { it.route != null },
                entryId = { it.id },
                pop = {
                    popCalls++
                    onPop()
                },
            )
        }
    }

    private fun entry(id: String, route: String? = id, arguments: String? = null) =
        Entry(id, route, arguments)

    private val root = entry("root", "forum-list")
}
