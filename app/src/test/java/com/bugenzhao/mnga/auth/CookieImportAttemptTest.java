package com.bugenzhao.mnga.auth;

import org.junit.Test;
import static org.junit.Assert.*;

public class CookieImportAttemptTest {
    @Test public void commitsVerifiedResultOnlyOnce() {
        CookieImportAttempt gate = new CookieImportAttempt();
        long id = gate.begin();
        assertTrue(gate.finish(id, true));
        assertFalse(gate.finish(id, true));
    }
    @Test public void failureDoesNotCommitAndCanRetry() {
        CookieImportAttempt gate = new CookieImportAttempt();
        assertFalse(gate.finish(gate.begin(), false));
        assertTrue(gate.finish(gate.begin(), true));
    }
    @Test public void cancellationRejectsLateSuccess() {
        CookieImportAttempt gate = new CookieImportAttempt();
        long id = gate.begin();
        gate.cancel();
        assertFalse(gate.finish(id, true));
    }
    @Test public void newAttemptRejectsOldResult() {
        CookieImportAttempt gate = new CookieImportAttempt();
        long old = gate.begin();
        long current = gate.begin();
        assertFalse(gate.finish(old, true));
        assertTrue(gate.finish(current, true));
    }
}
