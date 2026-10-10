package com.bugenzhao.mnga.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class QrAuthorizationAttemptTest {
    private static final String UID = "12345";
    private static final String TOKEN = "SyntheticAccountToken";

    @Test public void startsInactiveAndAllowsRepeatedCallbacksForTheSameSnapshot() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        assertFalse(gate.isActive(0, UID, TOKEN));
        long generation = gate.begin(UID, TOKEN);
        assertTrue(gate.isActive(generation, UID, TOKEN));
        assertTrue(gate.isActive(generation, new String(UID), new String(TOKEN)));
        assertTrue(gate.isActive(generation, UID, TOKEN));
    }

    @Test public void rejectsMissingAccountSnapshots() {
        for (String[] account : new String[][]{
                {null, TOKEN}, {UID, null}, {"", TOKEN}, {UID, ""}, {null, null}, {"", ""}
        }) {
            QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
            assertThrows(IllegalArgumentException.class, () -> gate.begin(account[0], account[1]));
            assertFalse(gate.isActive(0, UID, TOKEN));
        }
    }

    @Test public void cancellationRejectsLateCameraCookieAndWebViewCallbacks() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long generation = gate.begin(UID, TOKEN);
        gate.cancel();
        assertFalse(gate.isActive(generation, UID, TOKEN));
        assertFalse(gate.isActive(generation, UID, TOKEN));
        assertFalse(gate.isActive(generation, UID, TOKEN));
    }

    @Test public void cancellationBeforeBeginAndRepeatedCancellationAreSafe() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        gate.cancel();
        gate.cancel();
        assertFalse(gate.isActive(0, UID, TOKEN));
        long generation = gate.begin(UID, TOKEN);
        assertTrue(gate.isActive(generation, UID, TOKEN));
        gate.cancel();
        gate.cancel();
        assertFalse(gate.isActive(generation, UID, TOKEN));
    }

    @Test public void restartingTheSameAccountInvalidatesThePreviousGeneration() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long old = gate.begin(UID, TOKEN);
        long current = gate.begin(UID, TOKEN);
        assertNotEquals(old, current);
        assertFalse(gate.isActive(old, UID, TOKEN));
        assertTrue(gate.isActive(current, UID, TOKEN));
    }

    @Test public void cancelThenReopenDoesNotReviveTheClosedGeneration() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long closed = gate.begin(UID, TOKEN);
        gate.cancel();
        long reopened = gate.begin(UID, TOKEN);
        assertNotEquals(closed, reopened);
        assertFalse(gate.isActive(closed, UID, TOKEN));
        assertTrue(gate.isActive(reopened, UID, TOKEN));
    }

    @Test public void switchingAccountsPermanentlyInvalidatesTheAttempt() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long generation = gate.begin(UID, TOKEN);
        assertFalse(gate.isActive(generation, "67890", TOKEN));
        assertFalse(gate.isActive(generation, UID, TOKEN));
    }

    @Test public void refreshingTheSameAccountsTokenPermanentlyInvalidatesTheAttempt() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long generation = gate.begin(UID, TOKEN);
        assertFalse(gate.isActive(generation, UID, "ReplacementSyntheticToken"));
        assertFalse(gate.isActive(generation, UID, TOKEN));
    }

    @Test public void logoutAndPartialCredentialsPermanentlyInvalidateTheAttempt() {
        for (String[] account : new String[][]{
                {null, TOKEN}, {UID, null}, {"", TOKEN}, {UID, ""}, {null, null}, {"", ""}
        }) {
            QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
            long generation = gate.begin(UID, TOKEN);
            assertFalse(gate.isActive(generation, account[0], account[1]));
            assertFalse(gate.isActive(generation, UID, TOKEN));
        }
    }

    @Test public void staleCallbacksCannotCancelANewerAccountAttempt() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long old = gate.begin(UID, TOKEN);
        long current = gate.begin("67890", "OtherSyntheticToken");
        assertFalse(gate.isActive(old, UID, TOKEN));
        assertFalse(gate.isActive(old, null, null));
        assertTrue(gate.isActive(current, "67890", "OtherSyntheticToken"));
    }

    @Test public void unrelatedGenerationCannotCancelTheCurrentAttempt() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long current = gate.begin(UID, TOKEN);
        for (long unrelated : new long[]{Long.MIN_VALUE, -1, 0, current + 1, Long.MAX_VALUE}) {
            assertFalse(gate.isActive(unrelated, "OtherUid", "OtherSyntheticToken"));
            assertTrue(gate.isActive(current, UID, TOKEN));
        }
    }

    @Test public void explicitRestartAfterAccountMismatchWorksWithNewSnapshot() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        long old = gate.begin(UID, TOKEN);
        assertFalse(gate.isActive(old, "67890", "OtherSyntheticToken"));
        long current = gate.begin("67890", "OtherSyntheticToken");
        assertFalse(gate.isActive(old, UID, TOKEN));
        assertTrue(gate.isActive(current, "67890", "OtherSyntheticToken"));
    }

    @Test public void diagnosticOutputDoesNotExposeAccountCredentials() {
        QrAuthorizationAttempt gate = new QrAuthorizationAttempt();
        gate.begin(UID, TOKEN);
        assertFalse(gate.toString().contains(UID));
        assertFalse(gate.toString().contains(TOKEN));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> gate.begin(null, TOKEN));
        assertFalse(error.toString().contains(TOKEN));
    }
}
