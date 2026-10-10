package com.bugenzhao.mnga.auth;

/** One-use gate: a canceled, failed or superseded network result must never install a session. */
public final class CookieImportAttempt {
    private long generation;
    private boolean pending;

    public synchronized long begin() {
        pending = true;
        return ++generation;
    }

    public synchronized void cancel() {
        pending = false;
        generation++;
    }

    public synchronized boolean finish(long attempt, boolean verified) {
        if (!pending || attempt != generation) return false;
        pending = false;
        return verified;
    }
}
