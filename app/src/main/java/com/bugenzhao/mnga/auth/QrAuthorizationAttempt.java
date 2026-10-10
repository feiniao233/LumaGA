package com.bugenzhao.mnga.auth;

/** Invalidate late camera/cookie/WebView callbacks on close, restart or account changes. */
public final class QrAuthorizationAttempt {
    private long generation;
    private String uid;
    private String token;

    public synchronized long begin(String uid, String token) {
        if (uid == null || uid.isEmpty() || token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Sign in before scanning");
        }
        this.uid = uid;
        this.token = token;
        return ++generation;
    }

    public synchronized boolean isActive(long generation, String uid, String token) {
        if (this.uid == null || generation != this.generation) return false;
        if (!this.uid.equals(uid) || !this.token.equals(token)) {
            cancel();
            return false;
        }
        return true;
    }

    public synchronized void cancel() {
        generation++;
        uid = null;
        token = null;
    }

    @Override public String toString() { return "QrAuthorizationAttempt([redacted])"; }
}
